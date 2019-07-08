/* Low level interface to ptrace, for the remote server for GDB.
   Copyright (C) 1995-2019 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>

#include "server.h"
#include "netbsd-low.h"
#include "nat/netbsd-osdata.h"
#include "common/agent.h"
#include "tdesc.h"
#include "common/rsp-low.h"
#include "common/signals-state-save-restore.h"
#include "nat/netbsd-nat.h"
#include "nat/netbsd-waitpid.h"
#include "common/gdb_wait.h"
#include "nat/gdb_ptrace.h"
#include "nat/netbsd-ptrace.h"
#include <signal.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sched.h>
#include <ctype.h>
#include <pwd.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include "common/filestuff.h"
#include "tracepoint.h"
#include "hostio.h"
#include <inttypes.h>
#include "common/common-inferior.h"
#include "nat/fork-inferior.h"
#include "common/environ.h"
#include "common/scoped_restore.h"
#include <elf.h>


int using_threads = 1;

/* Add a process to the common process list, and set its private
   data.  */

static struct process_info *
netbsd_add_process (int pid, int attached)
{
  struct process_info *proc;
    
  proc = add_process (pid, attached);
  proc->priv = XCNEW (struct process_info_private);

  if (the_low_target.new_process != NULL)  
    proc->priv->arch_private = the_low_target.new_process ();

  return proc;
}

/* Callback to be used when calling fork_inferior, responsible for
   actually initiating the tracing of the inferior.  */

static void
netbsd_ptrace_fun ()
{
  if (ptrace (PT_TRACE_ME, 0, NULL, 0) < 0)
    trace_start_error_with_name ("ptrace");

  if (setpgid (0, 0) < 0)
    trace_start_error_with_name ("setpgid");

  /* If GDBserver is connected to gdb via stdio, redirect the inferior's
     stdout to stderr so that inferior i/o doesn't corrupt the connection.
     Also, redirect stdin to /dev/null.  */
  if (remote_connection_is_stdio ())
    {
      if (close (0) < 0)
        trace_start_error_with_name ("close");
      if (open ("/dev/null", O_RDONLY) < 0)
        trace_start_error_with_name ("open");
      if (dup2 (2, 1) < 0)
        trace_start_error_with_name ("dup2");
      if (write (2, "stdin/stdout redirected\n",
                 sizeof ("stdin/stdout redirected\n") - 1) < 0)
        {
          /* Errors ignored.  */;
        }
    }
}

static struct lwp_info *
add_lwp (ptid_t ptid)
{         
  struct lwp_info *lwp;
   
  lwp = XCNEW (struct lwp_info);
        
  lwp->waitstatus.kind = TARGET_WAITKIND_IGNORE;
        
  lwp->thread = add_thread (ptid, lwp);
        
  if (the_low_target.new_thread != NULL)
    the_low_target.new_thread (lwp);
  
  return lwp;
}

/* Start an inferior process and returns its pid.
   PROGRAM is the name of the program to be started, and PROGRAM_ARGS
   are its arguments.  */

static int
netbsd_create_inferior (const char *program,
                       const std::vector<char *> &program_args)
{
  std::string str_program_args = stringify_argv (program_args);

  pid_t pid = fork_inferior (program,
                       str_program_args.c_str (),
                       get_environ ()->envp (), netbsd_ptrace_fun,
                       NULL, NULL, NULL, NULL);

  netbsd_add_process (pid, 0);

  ptid_t ptid = ptid_t (pid, 0, 0);
  lwp_info *new_lwp = add_lwp (ptid);
  new_lwp->must_set_ptrace_flags = 1;

  post_fork_inferior (pid, program);

  return pid;
}

/* Return the name of a file that can be opened to get the symbols for
   the child process identified by PID.  */

static char *
pid_to_exec_file (pid_t pid)
{
  static const int name[] = {
    CTL_KERN, KERN_PROC_ARGS, pid, KERN_PROC_PATHNAME,
  };
  static char path[MAXPATHLEN];
  size_t len;

  len = sizeof(path);
  if (sysctl(name, __arraycount(name), path, &len, NULL, 0) == -1)
    return NULL;

  return path;
}

static ptid_t
netbsd_wait (ptid_t ptid,
           struct target_waitstatus *ourstatus, int target_options)
{
  ptid_t wptid;

  /*
   * Always perform polling on exact PID, overwrite the default polling on
   * WAIT_ANY.
   *
   * This avoids events reported in random order reported for FORK / VFORK.
   *
   * Polling on traced parent always, simplifies the code.
   */
  ptid = current_ptid;

  int status;

  int options = 0;
  if (target_options & TARGET_WNOHANG)
    options |= WNOHANG;

  pid_t wpid = my_waitpid (ptid.pid(), &status, options);

  if (wpid == 0)
    {
      gdb_assert (target_options & TARGET_WNOHANG);
      ourstatus->kind = TARGET_WAITKIND_IGNORE;
      return null_ptid;
    }

  gdb_assert (wpid != -1);

  if (WIFEXITED (status))
    {
      ourstatus->kind = TARGET_WAITKIND_EXITED;
      ourstatus->value.integer = WEXITSTATUS (status);
      return ptid;
    }

  if (WIFSIGNALED (status))
    {
      ourstatus->kind = TARGET_WAITKIND_SIGNALLED;
      ourstatus->value.sig = gdb_signal_from_host (WTERMSIG (status));
      return ptid;
    }

  if (WIFCONTINUED(status))
    {
      ourstatus->kind = TARGET_WAITKIND_IGNORE;
      return null_ptid;
    }

  if (WIFSTOPPED (status))
    {
      ptrace_state_t pst;
      ptrace_siginfo_t psi, child_psi;
      pid_t pid, child, wchild;
      ptid_t child_ptid;
      lwpid_t lwp;

      pid = wptid.pid ();
      // Find the lwp that caused the wait status change
      if (ptrace(PT_GET_SIGINFO, pid, &psi, sizeof(psi)) == -1)
        perror_with_name (("ptrace"));
      /* For whole-process signals pick random thread */
      if (psi.psi_lwpid == 0)
        {
          // XXX: Is this always valid?
          lwp = lwpid_of (current_thread);
        }
      else
        {
          lwp = psi.psi_lwpid;
        }

      wptid = ptid_t (pid, lwp, 0);

      if (!find_thread_ptid (wptid))
        {
          add_thread (wptid, NULL);
        }

      switch (psi.psi_siginfo.si_signo)
        {
        case SIGTRAP:
          switch (psi.psi_siginfo.si_code)
            {
            case TRAP_BRKPT:
//            lp->stop_reason = TARGET_STOPPED_BY_SW_BREAKPOINT;
              break;
            case TRAP_DBREG:
//            if (hardware_breakpoint_inserted_here_p (get_regcache_aspace (regcache), pc))
//              lp->stop_reason = TARGET_STOPPED_BY_HW_BREAKPOINT;
//            else
//              lp->stop_reason = TARGET_STOPPED_BY_WATCHPOINT;
              break;
            case TRAP_TRACE:
//            lp->stop_reason = TARGET_STOPPED_BY_SINGLE_STEP;
              break;
            case TRAP_SCE:
              ourstatus->kind = TARGET_WAITKIND_SYSCALL_ENTRY;
              ourstatus->value.syscall_number = psi.psi_siginfo.si_sysnum;
              break;
            case TRAP_SCX:
              ourstatus->kind = TARGET_WAITKIND_SYSCALL_RETURN;
              ourstatus->value.syscall_number = psi.psi_siginfo.si_sysnum;
              break;
            case TRAP_EXEC:
              ourstatus->kind = TARGET_WAITKIND_EXECD;
              ourstatus->value.execd_pathname = xstrdup(pid_to_exec_file (pid));
              break;
            case TRAP_LWP:
            case TRAP_CHLD:
              if (ptrace(PT_GET_PROCESS_STATE, pid, &pst, sizeof(pst)) == -1)
                perror_with_name (("ptrace"));
              switch (pst.pe_report_event)
                {
                case PTRACE_FORK:
                case PTRACE_VFORK:
                  if (pst.pe_report_event == PTRACE_FORK)
                    ourstatus->kind = TARGET_WAITKIND_FORKED;
                  else
                    ourstatus->kind = TARGET_WAITKIND_VFORKED;
                  child = pst.pe_other_pid;

                  wchild = waitpid (child, &status, 0);

                  if (wchild == -1)
                    perror_with_name (("waitpid"));

                  gdb_assert (wchild == child);

                  if (!WIFSTOPPED(status))
                    {
                      /* Abnormal situation (SIGKILLed?).. bail out */
                      ourstatus->kind = TARGET_WAITKIND_SPURIOUS;
                      return wptid;
                    }

                  if (ptrace(PT_GET_SIGINFO, child, &child_psi, sizeof(child_psi)) == -1)
                    perror_with_name (("ptrace"));

                  if (child_psi.psi_siginfo.si_signo != SIGTRAP)
                    {
                      /* Abnormal situation.. bail out */
                      ourstatus->kind = TARGET_WAITKIND_SPURIOUS;
                      return wptid;
                    }

                  if (child_psi.psi_siginfo.si_code != TRAP_CHLD)
                    {
                      /* Abnormal situation.. bail out */
                      ourstatus->kind = TARGET_WAITKIND_SPURIOUS;
                      return wptid;
                    }

                  child_ptid = ptid_t (child, child_psi.psi_lwpid, 0);
                  netbsd_enable_event_reporting (child_ptid.pid ());
                  ourstatus->value.related_pid = child_ptid;
                  break;
                case PTRACE_VFORK_DONE:
                  ourstatus->kind = TARGET_WAITKIND_VFORK_DONE;
                  break;
                case PTRACE_LWP_CREATE:
                  wptid = ptid_t (pid, pst.pe_lwp, 0);
                  if (!find_thread_ptid (wptid))
                    {
                      /* Newborn reported after attach? */
                      ourstatus->kind = TARGET_WAITKIND_SPURIOUS;
                      return wptid;
                    }
                  add_thread (wptid, NULL);
                  ourstatus->kind = TARGET_WAITKIND_THREAD_CREATED;
                  break;
                case PTRACE_LWP_EXIT:
                  wptid = ptid_t (pid, pst.pe_lwp, 0);
                  thread_info *thread = find_thread_ptid (wptid);
                  if (!thread)
                    {
                      /* Dead child reported after attach? */
                      ourstatus->kind = TARGET_WAITKIND_SPURIOUS;
                      return wptid;
                    }
                  remove_thread (thread);
                  ourstatus->kind = TARGET_WAITKIND_THREAD_EXITED;

#if 0
                  if (ptrace (PT_CONTINUE, pid, (void *)1, 0) == -1)
                    perror_with_name (("ptrace"));
#endif
                  break;
                }
              break;
            }
          break;
        }
    }
  return wptid;
}

static struct target_ops netbsd_target_ops = {
  netbsd_create_inferior,
  NULL, // netbsd_post_create_inferior,
  NULL, //   netbsd_attach,
  NULL, //   netbsd_kill,
  NULL, //   netbsd_detach,
  NULL, //   netbsd_mourn,
  NULL, //   netbsd_join,
  NULL, //   netbsd_thread_alive,
  NULL, //   netbsd_resume,
  netbsd_wait,
#if 0
  netbsd_post_create_inferior,
  netbsd_attach,
  netbsd_kill,
  netbsd_detach,
  netbsd_mourn,
  netbsd_join,
  netbsd_thread_alive,
  netbsd_resume,
  netbsd_wait,
  netbsd_fetch_registers,
  netbsd_store_registers,
  netbsd_prepare_to_access_memory,
  netbsd_done_accessing_memory,
  netbsd_read_memory,
  netbsd_write_memory,
  netbsd_look_up_symbols,
  netbsd_request_interrupt,
  netbsd_read_auxv,
  netbsd_supports_z_point_type,
  netbsd_insert_point,
  netbsd_remove_point,
  netbsd_stopped_by_sw_breakpoint,
  netbsd_supports_stopped_by_sw_breakpoint,
  netbsd_stopped_by_hw_breakpoint,
  netbsd_supports_stopped_by_hw_breakpoint,
  netbsd_supports_hardware_single_step,
  netbsd_stopped_by_watchpoint,
  netbsd_stopped_data_address,
  NULL,
  NULL,
  netbsd_qxfer_spu,
  hostio_last_error_from_errno,
  netbsd_qxfer_osdata,
  netbsd_xfer_siginfo,
  netbsd_supports_non_stop,
  netbsd_async,
  netbsd_start_non_stop,
  netbsd_supports_multi_process,
  netbsd_supports_fork_events,
  netbsd_supports_vfork_events,
  netbsd_supports_exec_events,
  netbsd_handle_new_gdb_connection,
  NULL,
  netbsd_common_core_of_thread,
  netbsd_read_loadmap,
  netbsd_process_qsupported,
  netbsd_supports_tracepoints,
  netbsd_read_pc,
  netbsd_write_pc,
  netbsd_thread_stopped,
  NULL,
  netbsd_pause_all,
  netbsd_unpause_all,
  netbsd_stabilize_threads,
  netbsd_install_fast_tracepoint_jump_pad,
  netbsd_emit_ops,
  netbsd_supports_disable_randomization,
  netbsd_get_min_fast_tracepoint_insn_len,
  netbsd_qxfer_libraries_svr4,
  netbsd_supports_agent,
  NULL,
  NULL,
  NULL,
  NULL,
  netbsd_supports_range_stepping,
  netbsd_proc_pid_to_exec_file,
  netbsd_mntns_open_cloexec,
  netbsd_mntns_unlink,
  netbsd_mntns_readlink,
  netbsd_breakpoint_kind_from_pc,
  netbsd_sw_breakpoint_from_kind,
  netbsd_proc_tid_get_name,
  netbsd_breakpoint_kind_from_current_state,
  netbsd_supports_software_single_step,
  netbsd_supports_catch_syscall,
  NULL,
  NULL,
#endif
};

void
initialize_low (void)
{
  set_target_ops (&netbsd_target_ops);

  initialize_low_arch ();
}
