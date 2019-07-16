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
netbsd_ptid_t (int pid, long tid)
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
  const int request
    = (resume_info[0].kind == resume_step
       ? (n == 1 ? PTRACE_SINGLESTEP_ONE : PTRACE_SINGLESTEP)
       : PTRACE_CONT);
  const int signal = resume_info[0].sig;

  /* If given a minus_one_ptid, then try using the current_process'
     private->last_wait_event_ptid.  On most NetBSD versions,
     using any of the process' thread works well enough, but
     NetBSD 178 is a little more sensitive, and triggers some
     unexpected signals (Eg SIG61) when we resume the inferior
     using a different thread.  */
  if (ptid == minus_one_ptid)
    ptid = current_process()->priv->last_wait_event_ptid;

  /* The ptid might still be minus_one_ptid; this can happen between
     the moment we create the inferior or attach to a process, and
     the moment we resume its execution for the first time.  It is
     fine to use the current_thread's ptid in those cases.  */
  if (ptid == minus_one_ptid)
    ptid = ptid_of (current_thread);

  regcache_invalidate_pid (ptid.pid ());

  errno = 0;
  netbsd_ptrace (request, ptid, 1, signal, 0);
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
netbsd_waitpid (int pid, int *stat_loc)
{
  int ret = 0;

  while (1)
    {
      ret = waitpid (pid, stat_loc, WNOHANG);
      if (ret < 0)
        {
	  /* An ECHILD error is not indicative of a real problem.
	     It happens for instance while waiting for the inferior
	     to stop after attaching to it.  */
	  if (errno != ECHILD)
	    perror_with_name ("waitpid (WNOHANG)");
	}
      if (ret > 0)
        break;
      /* No event with WNOHANG.  See if there is one with WUNTRACED.  */
      ret = waitpid (pid, stat_loc, WNOHANG | WUNTRACED);
      if (ret < 0)
        {
	  /* An ECHILD error is not indicative of a real problem.
	     It happens for instance while waiting for the inferior
	     to stop after attaching to it.  */
	  if (errno != ECHILD)
	    perror_with_name ("waitpid (WNOHANG|WUNTRACED)");
	}
      if (ret > 0)
        break;
      usleep (1000);
    }
  return ret;
}

/* Implement the wait target_ops method.  */

static ptid_t
netbsd_wait_1 (ptid_t ptid, struct target_waitstatus *status, int options)
{
  int pid;
  int ret;
  int wstat;
  ptid_t new_ptid;

  if (ptid == minus_one_ptid)
    pid = netbsd_ptid_get_pid (ptid_of (current_thread));
  else
    pid = BUILDPID (netbsd_ptid_get_pid (ptid), netbsd_ptid_get_tid (ptid));

retry:

  ret = netbsd_waitpid (pid, &wstat);
  new_ptid = netbsd_ptid_t (ret, ((union wait *) &wstat)->w_tid);
  find_process_pid (ret)->priv->last_wait_event_ptid = new_ptid;

  /* If this is a new thread, then add it now.  The reason why we do
     this here instead of when handling new-thread events is because
     we need to add the thread associated to the "main" thread - even
     for non-threaded applications where the new-thread events are not
     generated.  */
  if (!find_thread_ptid (new_ptid))
    {
      netbsd_debug ("New thread: (pid = %d, tid = %d)",
		  netbsd_ptid_get_pid (new_ptid), netbsd_ptid_get_tid (new_ptid));
      add_thread (new_ptid, NULL);
    }

  if (WIFSTOPPED (wstat))
    {
      status->kind = TARGET_WAITKIND_STOPPED;
      status->value.integer = gdb_signal_from_host (WSTOPSIG (wstat));
      netbsd_debug ("process stopped with signal: %d",
                  status->value.integer);
    }
  else if (WIFEXITED (wstat))
    {
      status->kind = TARGET_WAITKIND_EXITED;
      status->value.integer = WEXITSTATUS (wstat);
      netbsd_debug ("process exited with code: %d", status->value.integer);
    }
  else if (WIFSIGNALED (wstat))
    {
      status->kind = TARGET_WAITKIND_SIGNALLED;
      status->value.integer = gdb_signal_from_host (WTERMSIG (wstat));
      netbsd_debug ("process terminated with code: %d",
                  status->value.integer);
    }
  else
    {
      /* Not sure what happened if we get here, or whether we can
	 in fact get here.  But if we do, handle the event the best
	 we can.  */
      status->kind = TARGET_WAITKIND_STOPPED;
      status->value.integer = gdb_signal_from_host (0);
      netbsd_debug ("unknown event ????");
    }

  /* SIGTRAP events are generated for situations other than single-step/
     breakpoint events (Eg. new-thread events).  Handle those other types
     of events, and resume the execution if necessary.  */
  if (status->kind == TARGET_WAITKIND_STOPPED
      && status->value.integer == GDB_SIGNAL_TRAP)
    {
      const int realsig = netbsd_ptrace (PTRACE_GETTRACESIG, new_ptid, 0, 0, 0);

      netbsd_debug ("(realsig = %d)", realsig);
      switch (realsig)
	{
	  case SIGNEWTHREAD:
	    /* We just added the new thread above.  No need to do anything
	       further.  Just resume the execution again.  */
	    netbsd_continue (new_ptid);
	    goto retry;

	  case SIGTHREADEXIT:
	    remove_thread (find_thread_ptid (new_ptid));
	    netbsd_continue (new_ptid);
	    goto retry;
	}
    }

  return new_ptid;
}

/* A wrapper around netbsd_wait_1 that also prints debug traces when
   such debug traces have been activated.  */

static ptid_t
netbsd_wait (ptid_t ptid, struct target_waitstatus *status, int options)
{
  ptid_t new_ptid;

  netbsd_debug ("netbsd_wait (pid = %d, tid = %ld)",
              netbsd_ptid_get_pid (ptid), netbsd_ptid_get_tid (ptid));
  new_ptid = netbsd_wait_1 (ptid, status, options);
  netbsd_debug ("          -> (pid=%d, tid=%ld, status->kind = %d)",
	      netbsd_ptid_get_pid (new_ptid), netbsd_ptid_get_tid (new_ptid),
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
