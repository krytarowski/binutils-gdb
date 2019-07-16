/* Copyright (C) 2009-2019 Free Software Foundation, Inc.

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

#include "server.h"
#include "target.h"
#include "netbsd-low.h"

#include <sys/types.h>

#include <sys/ptrace.h>
#include <sys/ioctl.h>

#include <limits.h>
#include <unistd.h>
#include <signal.h>

#include "gdbsupport/gdb_wait.h"
#include "gdbsupport/filestuff.h"
#include "gdbsupport/common-inferior.h"
#include "nat/fork-inferior.h"

int using_threads = 1;

const struct target_desc *netbsd_tdesc;

/* Per-process private data.  */

struct process_info_private
{
  /* The PTID obtained from the last wait performed on this process.
     Initialized to null_ptid until the first wait is performed.  */
  ptid_t last_wait_event_ptid;
};

/* Print a debug trace on standard output if debug_threads is set.  */

static void
netbsd_debug (const char *string, ...)
{
  va_list args;

  if (!debug_threads)
    return;

  va_start (args, string);
  fprintf (stderr, "DEBUG(netbsd): ");
  vfprintf (stderr, string, args);
  fprintf (stderr, "\n");
  va_end (args);
}

/* Build a ptid_t given a PID and a NetBSD TID.  */

static ptid_t
netbsd_ptid_t (pid_t pid, lwpid_t tid)
{
  /* brobecker/2010-06-21: It looks like the LWP field in ptids
     should be distinct for each thread (see write_ptid where it
     writes the thread ID from the LWP).  So instead of storing
     the NetBSD tid in the tid field of the ptid, we store it in
     the lwp field.  */
  return ptid_t (pid, tid, 0);
}

/* Return the process ID of the given PTID.

   This function has little reason to exist, it's just a wrapper around
   ptid_get_pid.  But since we have a getter function for the lynxos
   ptid, it feels cleaner to have a getter for the pid as well.  */

static int
netbsd_ptid_get_pid (ptid_t ptid)
{
  return ptid.pid ();
}

/* Return the NetBSD tid of the given PTID.  */

static long
netbsd_ptid_get_tid (ptid_t ptid)
{
  /* See lynx_ptid_t: The NetBSD tid is stored inside the lwp field
     of the ptid.  */
  return ptid.lwp ();
}

/* For a given PTID, return the associated PID as known by the NetBSD
   ptrace layer.  */

static pid_t
netbsd_ptrace_pid_from_ptid (ptid_t ptid)
{
  return netbsd_ptid_get_pid (ptid);
}

/* Return a string image of the ptrace REQUEST number.  */

static const char *
ptrace_request_to_str (int request)
{
#define CASE(X) case X: return #X
  switch (request)
    {
      CASE(PT_TRACE_ME);
      CASE(PT_READ_I);
      CASE(PT_READ_D);
      CASE(PT_WRITE_I);
      CASE(PT_WRITE_D);
      CASE(PT_CONTINUE);
      CASE(PT_KILL);
      CASE(PT_ATTACH);
      CASE(PT_DETACH);
      CASE(PT_IO);
      CASE(PT_DUMPCORE);
      CASE(PT_LWPINFO);
      CASE(PT_SYSCALL);
      CASE(PT_SYSCALLEMU);
      CASE(PT_SET_EVENT_MASK);
      CASE(PT_GET_EVENT_MASK);
      CASE(PT_GET_PROCESS_STATE);
      CASE(PT_SET_SIGINFO);
      CASE(PT_GET_SIGINFO);
      CASE(PT_RESUME);
      CASE(PT_SUSPEND);

#ifdef PT_STEP
      CASE(PT_STEP);
#endif
#ifdef PT_GETREGS
      CASE(PT_GETREGS);
#endif
#ifdef PT_SETREGS
      CASE(PT_SETREGS);
#endif
#ifdef PT_GETFPREGS
      CASE(PT_GETFPREGS);
#endif
#ifdef PT_SETFPREGS
      CASE(PT_SETFPREGS);
#endif
#ifdef PT_GETDBREGS
      CASE(PT_GETDBREGS);
#endif
#ifdef PT_SETDBREGS
      CASE(PT_SETDBREGS);
#endif
#ifdef PT_SETSTEP
      CASE(PT_SETSTEP);
#endif
#ifdef PT_CLEARSTEP
      CASE(PT_CLEARSTEP);
#endif
#ifdef PT_GETXSTATE
      CASE(PT_GETXSTATE);
#endif
#ifdef PT_SETXSTATE
      CASE(PT_SETXSTATE);
#endif
#ifdef PT_GETXMMREGS
      CASE(PT_GETXMMREGS);
#endif
#ifdef PT_SETXMMREGS
      CASE(PT_SETXMMREGS);
#endif
#ifdef PT_GETVECREGS
      CASE(PT_GETVECREGS);
#endif
#ifdef PT_SETVECREGS
      CASE(PT_SETVECREGS);
#endif
    }
#undef CASE

  return "<unknown-request>";
}

/* A wrapper around ptrace that allows us to print debug traces of
   ptrace calls if debug traces are activated.  */

static int
netbsd_ptrace (int request, pid_t pid, void *addr, int data)
{
  int result;
  int saved_errno;

  if (debug_threads)
    fprintf (stderr, "PTRACE (%s, pid=%d, addr=%p, "
             "data=%#x)",
             ptrace_request_to_str (request), pid,
             addr, data);
  result = ptrace (request, pid, addr, data);
  saved_errno = errno;
  if (debug_threads)
    fprintf (stderr, " -> %d (=0x%x)\n", result, result);

  errno = saved_errno;
  return result;
}

/* Call add_process with the given parameters, and initializes
   the process' private data.  */

static struct process_info *
netbsd_add_process (int pid, int attached)
{
  struct process_info *proc;

  proc = add_process (pid, attached);
  proc->tdesc = netbsd_tdesc;
  proc->priv = XCNEW (struct process_info_private);
  proc->priv->last_wait_event_ptid = null_ptid;

  return proc;
}

/* Callback used by fork_inferior to start tracing the inferior.  */

static void
netbsd_ptrace_fun ()
{
  /* Switch child to its own process group so that signals won't
     directly affect GDBserver. */
  if (setpgid (0, 0) < 0)
    trace_start_error_with_name ("setpgid");

  if (netbsd_ptrace (PT_TRACE_ME, 0, NULL, 0) < 0)
    trace_start_error_with_name ("netbsd_ptrace");

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

/* Implement the create_inferior method of the target_ops vector.  */

static int
netbsd_create_inferior (const char *program,
		      const std::vector<char *> &program_args)
{
  int pid;
  std::string str_program_args = stringify_argv (program_args);

  netbsd_debug ("netbsd_create_inferior ()");

  pid = fork_inferior (program,
		       str_program_args.c_str (),
		       get_environ ()->envp (), netbsd_ptrace_fun,
		       NULL, NULL, NULL, NULL);

  post_fork_inferior (pid, program);

  netbsd_add_process (pid, 0);
  /* Do not add the process thread just yet, as we do not know its tid.
     We will add it later, during the wait for the STOP event corresponding
     to the netbsd_ptrace (PTRACE_TRACEME) call above.  */
  return pid;
}

/* Assuming we've just attached to a running inferior whose pid is PID,
   add all threads running in that process.  */

static void
netbsd_add_threads_after_attach (pid_t pid)
{
  struct ptrace_lwpinfo pl;
  int val;
  pl.pl_lwpid = 0;
  while ((val = netbsd_ptrace(PT_LWPINFO, pid, (void *)&pl, sizeof(pl))) != -1 &&
    pl.pl_lwpid != 0)
    {
      ptid_t thread_ptid = netbsd_ptid_t (pid, pl.pl_lwpid);

      if (!find_thread_ptid (thread_ptid))
	{
	  netbsd_debug ("New thread: (pid = %d, tid = %d)",
		      pid, pl.pl_lwpid);
	  add_thread (thread_ptid, NULL);
	}
    }
}

/* Implement the attach target_ops method.  */

static int
netbsd_attach (unsigned long pid)
{

  if (netbsd_ptrace (PT_ATTACH, pid, NULL, 0) != 0)
    error ("Cannot attach to process %lu: %s (%d)\n", pid,
	   strerror (errno), errno);

  netbsd_add_process (pid, 1);
  netbsd_add_threads_after_attach (pid);

  return 0;
}

/* Implement the resume target_ops method.  */

static void
netbsd_resume (struct thread_resume *resume_info, size_t n)
{
  ptid_t ptid = resume_info[0].thread;
  const int signal = resume_info[0].sig;

  if (ptid == minus_one_ptid)
    ptid = ptid_of (current_thread);

  regcache_invalidate_pid (ptid.pid ());

  if (resume_info[0].kind == resume_step)
    {
      if (n == 1)
        {
          struct ptrace_lwpinfo pl;
          int val;
          pl.pl_lwpid = 0;
          while ((val = netbsd_ptrace(PT_LWPINFO, ptid.pid(), (void *)&pl,
            sizeof(pl))) != -1 && pl.pl_lwpid != 0)
           {
              if (pl.pl_lwpid == ptid.lwp())
                {
                  netbsd_ptrace (PT_SETSTEP, ptid.pid(), NULL, pl.pl_lwpid);
                  netbsd_ptrace (PT_RESUME, ptid.pid(), NULL, pl.pl_lwpid);
                }
              else
                {
                  netbsd_ptrace (PT_CLEARSTEP, ptid.pid(), NULL, pl.pl_lwpid);
                  netbsd_ptrace (PT_SUSPEND, ptid.pid(), NULL, pl.pl_lwpid);
                }
           }
        }
      else
        {
          struct ptrace_lwpinfo pl;
          int val;
          pl.pl_lwpid = 0;
          while ((val = netbsd_ptrace(PT_LWPINFO, ptid.pid(), (void *)&pl,
            sizeof(pl))) != -1 && pl.pl_lwpid != 0)
           {
              netbsd_ptrace (PT_SETSTEP, ptid.pid(), NULL, pl.pl_lwpid);
              netbsd_ptrace (PT_RESUME, ptid.pid(), NULL, pl.pl_lwpid);
           }
        }
    }
  else
    {
      struct ptrace_lwpinfo pl;
      int val;
      pl.pl_lwpid = 0;
      while ((val = netbsd_ptrace(PT_LWPINFO, ptid.pid(), (void *)&pl, sizeof(pl))) != -1 &&
        pl.pl_lwpid != 0)
        {
          netbsd_ptrace (PT_CLEARSTEP, ptid.pid(), NULL, pl.pl_lwpid);
          netbsd_ptrace (PT_RESUME, ptid.pid(), NULL, pl.pl_lwpid);
        }
    }

  errno = 0;
  netbsd_ptrace (PT_CONTINUE, ptid.pid(), (void *)1, signal);
  if (errno)
    perror_with_name ("ptrace");
}

/* Resume the execution of the given PTID.  */

static void
netbsd_continue (ptid_t ptid)
{
  struct thread_resume resume_info;

  resume_info.thread = ptid;
  resume_info.kind = resume_continue;
  resume_info.sig = 0;

  netbsd_resume (&resume_info, 1);
}

/* A wrapper around waitpid that handles the various idiosyncrasies
   of NetBSD waitpid.  */

static int
netbsd_waitpid (int pid, int *stat_loc, int options)
{
  int ret;

  do
    {
      ret = waitpid (pid, stat_loc, options);
    }
  while (ret == -1 && errno == EINTR);

  return ret;
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

/* Implement the wait target_ops method.  */

static ptid_t
netbsd_wait_1 (ptid_t ptid, struct target_waitstatus *ourstatus, int target_options)
{
  pid_t pid;
  int status;

  if (ptid == minus_one_ptid)
    pid = netbsd_ptid_get_pid (ptid_of (current_thread));
  else
    pid = netbsd_ptid_get_pid (ptid);

  int options = 0;
  if (target_options & TARGET_WNOHANG)
    options |= WNOHANG;

  pid_t wpid = netbsd_waitpid (pid, &status, options);

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
      pid_t child, wchild;
      ptid_t child_ptid;
      lwpid_t lwp;

      {
        struct process_info *proc;

      /* Architecture-specific setup after inferior is running.  */
      proc = find_process_pid (wpid);
      if (proc->tdesc == NULL)
        {
              /* This needs to happen after we have attached to the
                 inferior and it is stopped for the first time, but
                 before we access any inferior registers.  */
              the_low_target.arch_setup ();
        }
      }

      ourstatus->kind = TARGET_WAITKIND_STOPPED;
      ourstatus->value.sig = gdb_signal_from_host (WSTOPSIG (status));

      // Find the lwp that caused the wait status change
      if (ptrace(PT_GET_SIGINFO, wpid, &psi, sizeof(psi)) == -1)
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

      ptid_t wptid = netbsd_ptid_t (wpid, lwp);

      if (!find_thread_ptid (wptid))
        {
          add_thread (wptid, NULL);
        }

      switch (psi.psi_siginfo.si_signo)
        {
        case SIGTRAP:
          switch (psi.psi_siginfo.si_code)
            {
#if 0
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
#endif
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
              ourstatus->value.execd_pathname = xstrdup(pid_to_exec_file (wpid));
              break;
            case TRAP_LWP:
            case TRAP_CHLD:
              if (ptrace(PT_GET_PROCESS_STATE, wpid, &pst, sizeof(pst)) == -1)
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

                  child_ptid = netbsd_ptid_t (child, child_psi.psi_lwpid);
                  netbsd_enable_event_reporting (child_ptid.pid ());
                  ourstatus->value.related_pid = child_ptid;
                  break;
                case PTRACE_VFORK_DONE:
                  ourstatus->kind = TARGET_WAITKIND_VFORK_DONE;
                  break;
                case PTRACE_LWP_CREATE:
                  wptid = netbsd_ptid_t (wpid, pst.pe_lwp);
                  if (!find_thread_ptid (wptid))
                    {
                      add_thread (wptid, NULL);
                    }
                  ourstatus->kind = TARGET_WAITKIND_THREAD_CREATED;
                  break;
                case PTRACE_LWP_EXIT:
                  wptid = netbsd_ptid_t (wpid, pst.pe_lwp);
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

/* A wrapper around netbsd_wait_1 that also prints debug traces when
   such debug traces have been activated.  */

static ptid_t
netbsd_wait (ptid_t ptid, struct target_waitstatus *status, int options)
{
  ptid_t new_ptid;

  netbsd_debug ("netbsd_wait (pid = %d, %s)",
              netbsd_ptid_get_pid (ptid),
              options & TARGET_WNOHANG ? "WNOHANG" : "" );
  new_ptid = netbsd_wait_1 (ptid, status, options);
  netbsd_debug ("          -> (pid=%d, status->kind = %d)",
	      netbsd_ptid_get_pid (new_ptid),
	      status->kind);
  return new_ptid;
}

/* Implement the kill target_ops method.  */

static int
netbsd_kill (process_info *process)
{
  ptid_t ptid = netbsd_ptid_t (process->pid, 0);
  struct target_waitstatus status;

  netbsd_ptrace (PTRACE_KILL, ptid, 0, 0, 0);
  netbsd_wait (ptid, &status, 0);
  the_target->mourn (process);
  return 0;
}

/* Implement the detach target_ops method.  */

static int
netbsd_detach (process_info *process)
{
  ptid_t ptid = netbsd_ptid_t (process->pid, 0);

  netbsd_ptrace (PTRACE_DETACH, ptid, 0, 0, 0);
  the_target->mourn (process);
  return 0;
}

/* Implement the mourn target_ops method.  */

static void
netbsd_mourn (struct process_info *proc)
{
  for_each_thread (proc->pid, remove_thread);

  /* Free our private data.  */
  free (proc->priv);
  proc->priv = NULL;

  remove_process (proc);
}

/* Implement the join target_ops method.  */

static void
netbsd_join (int pid)
{
  /* The PTRACE_DETACH is sufficient to detach from the process.
     So no need to do anything extra.  */
}

/* Implement the thread_alive target_ops method.  */

static int
netbsd_thread_alive (ptid_t ptid)
{
  /* The list of threads is updated at the end of each wait, so it
     should be up to date.  No need to re-fetch it.  */
  return (find_thread_ptid (ptid) != NULL);
}

/* Implement the fetch_registers target_ops method.  */

static void
netbsd_fetch_registers (struct regcache *regcache, int regno)
{
  struct netbsd_regset_info *regset = netbsd_target_regsets;
  ptid_t inferior_ptid = ptid_of (current_thread);

  netbsd_debug ("netbsd_fetch_registers (regno = %d)", regno);

  while (regset->size >= 0)
    {
      char *buf;
      int res;

      buf = xmalloc (regset->size);
      res = netbsd_ptrace (regset->get_request, inferior_ptid, (int) buf, 0, 0);
      if (res < 0)
        perror ("ptrace");
      regset->store_function (regcache, buf);
      free (buf);
      regset++;
    }
}

/* Implement the store_registers target_ops method.  */

static void
netbsd_store_registers (struct regcache *regcache, int regno)
{
  struct netbsd_regset_info *regset = netbsd_target_regsets;
  ptid_t inferior_ptid = ptid_of (current_thread);

  netbsd_debug ("netbsd_store_registers (regno = %d)", regno);

  while (regset->size >= 0)
    {
      char *buf;
      int res;

      buf = xmalloc (regset->size);
      res = netbsd_ptrace (regset->get_request, inferior_ptid, (int) buf, 0, 0);
      if (res == 0)
        {
	  /* Then overlay our cached registers on that.  */
	  regset->fill_function (regcache, buf);
	  /* Only now do we write the register set.  */
	  res = netbsd_ptrace (regset->set_request, inferior_ptid, (int) buf,
			     0, 0);
        }
      if (res < 0)
        perror ("ptrace");
      free (buf);
      regset++;
    }
}

/* Implement the read_memory target_ops method.  */

static int
netbsd_read_memory (CORE_ADDR memaddr, unsigned char *myaddr, int len)
{
  /* On netbsdOS, memory reads needs to be performed in chunks the size
     of int types, and they should also be aligned accordingly.  */
  int buf;
  const int xfer_size = sizeof (buf);
  CORE_ADDR addr = memaddr & -(CORE_ADDR) xfer_size;
  ptid_t inferior_ptid = ptid_of (current_thread);

  while (addr < memaddr + len)
    {
      int skip = 0;
      int truncate = 0;

      errno = 0;
      if (addr < memaddr)
        skip = memaddr - addr;
      if (addr + xfer_size > memaddr + len)
        truncate = addr + xfer_size - memaddr - len;
      buf = netbsd_ptrace (PTRACE_PEEKTEXT, inferior_ptid, addr, 0, 0);
      if (errno)
        return errno;
      memcpy (myaddr + (addr - memaddr) + skip, (gdb_byte *) &buf + skip,
              xfer_size - skip - truncate);
      addr += xfer_size;
    }

  return 0;
}

/* Implement the write_memory target_ops method.  */

static int
netbsd_write_memory (CORE_ADDR memaddr, const unsigned char *myaddr, int len)
{
  /* On netbsdOS, memory writes needs to be performed in chunks the size
     of int types, and they should also be aligned accordingly.  */
  int buf;
  const int xfer_size = sizeof (buf);
  CORE_ADDR addr = memaddr & -(CORE_ADDR) xfer_size;
  ptid_t inferior_ptid = ptid_of (current_thread);

  while (addr < memaddr + len)
    {
      int skip = 0;
      int truncate = 0;

      if (addr < memaddr)
        skip = memaddr - addr;
      if (addr + xfer_size > memaddr + len)
        truncate = addr + xfer_size - memaddr - len;
      if (skip > 0 || truncate > 0)
	{
	  /* We need to read the memory at this address in order to preserve
	     the data that we are not overwriting.  */
	  netbsd_read_memory (addr, (unsigned char *) &buf, xfer_size);
	  if (errno)
	    return errno;
	}
      memcpy ((gdb_byte *) &buf + skip, myaddr + (addr - memaddr) + skip,
              xfer_size - skip - truncate);
      errno = 0;
      netbsd_ptrace (PTRACE_POKETEXT, inferior_ptid, addr, buf, 0);
      if (errno)
        return errno;
      addr += xfer_size;
    }

  return 0;
}

/* Implement the kill_request target_ops method.  */

static void
netbsd_request_interrupt (void)
{
  ptid_t inferior_ptid = ptid_of (get_first_thread ());

  kill (netbsd_ptid_get_pid (inferior_ptid), SIGINT);
}

/* The netbsdOS target_ops vector.  */

static struct target_ops netbsd_target_ops = {
  netbsd_create_inferior,
  NULL,  /* post_create_inferior */
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
  NULL,  /* prepare_to_access_memory */
  NULL,  /* done_accessing_memory */
  netbsd_read_memory,
  netbsd_write_memory,
  NULL,  /* look_up_symbols */
  netbsd_request_interrupt,
  NULL,  /* read_auxv */
  NULL,  /* supports_z_point_type */
  NULL,  /* insert_point */
  NULL,  /* remove_point */
  NULL,  /* stopped_by_sw_breakpoint */
  NULL,  /* supports_stopped_by_sw_breakpoint */
  NULL,  /* stopped_by_hw_breakpoint */
  NULL,  /* supports_stopped_by_hw_breakpoint */
  target_can_do_hardware_single_step,
  NULL,  /* stopped_by_watchpoint */
  NULL,  /* stopped_data_address */
  NULL,  /* read_offsets */
  NULL,  /* get_tls_address */
  NULL,  /* qxfer_spu */
  NULL,  /* hostio_last_error */
  NULL,  /* qxfer_osdata */
  NULL,  /* qxfer_siginfo */
  NULL,  /* supports_non_stop */
  NULL,  /* async */
  NULL,  /* start_non_stop */
  NULL,  /* supports_multi_process */
  NULL,  /* supports_fork_events */
  NULL,  /* supports_vfork_events */
  NULL,  /* supports_exec_events */
  NULL,  /* handle_new_gdb_connection */
  NULL,  /* handle_monitor_command */
};

void
initialize_low (void)
{
  set_target_ops (&netbsd_target_ops);
  the_low_target.arch_setup ();
}
