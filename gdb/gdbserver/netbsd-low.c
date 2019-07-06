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


static struct target_ops netbsd_target_ops = {
  netbsd_create_inferior,
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
