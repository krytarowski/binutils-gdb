/* Copyright (C) 2020 Free Software Foundation, Inc.

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
#include <sys/sysctl.h>
#include <limits.h>
#include <unistd.h>
#include <signal.h>

#include <elf.h>

#include "gdbsupport/gdb_wait.h"
#include "gdbsupport/filestuff.h"
#include "gdbsupport/common-inferior.h"
#include "nat/fork-inferior.h"
#include "hostio.h"

int using_threads = 1;

const struct target_desc *netbsd_tdesc;

/* Per-process private data.  */

struct process_info_private
{
  /* The PTID obtained from the last wait performed on this process.
     Initialized to null_ptid until the first wait is performed.  */
  ptid_t last_wait_event_ptid;

  /* &_r_debug.  0 if not yet determined.  -1 if no PT_DYNAMIC in Phdrs.  */
  CORE_ADDR r_debug;
};

/* Print a debug trace on standard output if debug_threads is set.  */

static void
netbsd_debug (char *string, ...)
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

/* Return a string image of the ptrace REQUEST number.  */

static char *
ptrace_request_to_str (int request)
{
#define CASE(X) case X: return #X
  switch (request)
    {
      /* Machine Independent operations. */
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
      CASE(PT_SYSCALL);
      CASE(PT_SYSCALLEMU);
      CASE(PT_SET_EVENT_MASK);
      CASE(PT_GET_EVENT_MASK);
      CASE(PT_GET_PROCESS_STATE);
      CASE(PT_SET_SIGINFO);
      CASE(PT_GET_SIGINFO);
      CASE(PT_RESUME);
      CASE(PT_SUSPEND);
      CASE(PT_STOP);
      CASE(PT_LWPSTATUS);
      CASE(PT_LWPNEXT);

      /* Machine Dependent operations. */
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
#fidef PT_GETXSTATE
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
    }
#undef CASE

  return "<unknown-request>";
}

/* Return a string image of the ptrace PT_IO REQUEST number.  */

static const char *
ptrace_ptio_request_to_str (int request)
{
#define CASE(X) case X: return #X
  switch (request)
    {
      CASE(PIOD_READ_D);
      CASE(PIOD_WRITE_D);
      CASE(PIOD_READ_I);
      CASE(PIOD_WRITE_I);
      CASE(PIOD_READ_AUXV);
    }
#undef CASE

  return "<unknown-request>";
}

/* Return a string image of the siginfo_t::code.  */

static const char *
sigcode_to_str (int signo, int sigcode)
{
#define CASE(X) case X: return #X
  switch (signo)
    {
      case SIGILL:
      switch (sigcode)
        {
          CASE(ILL_ILLOPC);
          CASE(ILL_ILLOPN);
          CASE(ILL_ILLADR);
          CASE(ILL_ILLTRP);
          CASE(ILL_PRVOPC);
          CASE(ILL_PRVREG);
          CASE(ILL_COPROC);
          CASE(ILL_BADSTK);
        }
        break;

      case SIGFPE:
      switch (sigcode)
        {
          CASE(FPE_INTDIV);
          CASE(FPE_INTOVF);
          CASE(FPE_FLTDIV);
          CASE(FPE_FLTOVF);
          CASE(FPE_FLTUND);
          CASE(FPE_FLTRES);
          CASE(FPE_FLTINV);
          CASE(FPE_FLTSUB);
        }
        break;

      case SIGSEGV:
      switch (sigcode)
        {
          CASE(SEGV_MAPERR);
          CASE(SEGV_ACCERR);
        }
        break;

      case SIGBUS:
      switch (sigcode)
        {
          CASE(BUS_ADRALN);
          CASE(BUS_ADRERR);
          CASE(BUS_OBJERR);
        }
        break;

      case SIGTRAP:
      switch (sigcode)
        {
          CASE(TRAP_BRKPT);
          CASE(TRAP_TRACE);
          CASE(TRAP_EXEC);
          CASE(TRAP_CHLD);
          CASE(TRAP_LWP);
          CASE(TRAP_DBREG);
          CASE(TRAP_SCE);
          CASE(TRAP_SCX);
        }
        break;

      case SIGCHLD:
      switch (sigcode)
        {
          CASE(CLD_EXITED);
          CASE(CLD_KILLED);
          CASE(CLD_DUMPED);
          CASE(CLD_TRAPPED);
          CASE(CLD_STOPPED);
          CASE(CLD_CONTINUED);
        }
        break;

      case SIGIO:
      switch (sigcode)
        {
          CASE(POLL_IN);
          CASE(POLL_OUT);
          CASE(POLL_MSG);
          CASE(POLL_ERR);
          CASE(POLL_PRI);
          CASE(POLL_HUP);
        }
        break;
    }

  switch (sigcode)
    {
      CASE(SI_USER);
      CASE(SI_QUEUE);
      CASE(SI_TIMER);
      CASE(SI_ASYNCIO);
      CASE(SI_MESGQ);
      CASE(SI_LWP);
      CASE(SI_NOINFO);
    }
#undef CASE

  return "<unknown-sigcode>";
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

/* Return a string image of the waitkind operation.  */

static const char *
netbsd_wait_kind_to_str (int kind)
{
#define CASE(X) case X: return #X
  switch (kind)
    {
      CASE(TARGET_WAITKIND_EXITED);
      CASE(TARGET_WAITKIND_STOPPED);
      CASE(TARGET_WAITKIND_SIGNALLED);
      CASE(TARGET_WAITKIND_LOADED);
      CASE(TARGET_WAITKIND_FORKED);
      CASE(TARGET_WAITKIND_VFORKED);
      CASE(TARGET_WAITKIND_EXECD);
      CASE(TARGET_WAITKIND_VFORK_DONE);
      CASE(TARGET_WAITKIND_SYSCALL_ENTRY);
      CASE(TARGET_WAITKIND_SYSCALL_RETURN);
      CASE(TARGET_WAITKIND_IGNORE);
      CASE(TARGET_WAITKIND_NO_HISTORY);
      CASE(TARGET_WAITKIND_NO_RESUMED);
      CASE(TARGET_WAITKIND_THREAD_CREATED);
      CASE(TARGET_WAITKIND_THREAD_EXITED);
    }
#undef CASE

  return "<unknown-request>";
}

/* A wrapper around ptrace that allows us to print debug traces of
   ptrace calls if debug traces are activated.  */

static int
netbsd_ptrace (int request, pid_t ptid, void *addr, int data)
{
  int result;
  int saved_errno;

  netbsd_debug ("PTRACE (%s, pid=%d, addr=%p, data=%#x)\n",
              ptrace_request_to_str (request), pid, addr, data);

  if (request == PT_IO)
    {
      struct ptrace_io_desc *pio = (struct ptrace_io_desc *)addr;
      netbsd_debug (":: { .piod_op=%s, .piod_offs=%p, .piod_addr=%p, "
                    ".piod_len=%zu }\n",
                    ptrace_ptio_request_to_str (pio->piod_op),
                    pio->piod_offs, pio->piod_addr, pio->piod_len);
      if (pio->piod_op == PT_WRITE_I || pio->piod_op == PT_WRITE_D)
        {
          for (size_t i = 0; i < pio->piod_len; i++)
            netbsd_debug (" :: [%02zu] = %#02x\n", i,
			  (unsigned char)((char *)pio->piod_addr)[i]);
        }
    }

  saved_errno = errno;
  errno = 0;
  result = ptrace (request, pid, addr, data);

  netbsd_debug (" -> %d (=%#x errno=%d)\n", result, result, errno);
  if (request == PT_IO)
    {
      struct ptrace_io_desc *pio = (struct ptrace_io_desc *)addr;
      netbsd_debug (" -> :: { .piod_op=%s, .piod_offs=%p, .piod_addr=%p, "
                    ".piod_len=%zu }\n",
                    ptrace_ptio_request_to_str (pio->piod_op),
                    pio->piod_offs, pio->piod_addr, pio->piod_len);
      if (pio->piod_op == PT_READ_I || pio->piod_op == PT_READ_D)
        {
          for (size_t i = 0; i < pio->piod_len; i++)
            netbsd_debug (" :: [%02zu] = %#02x\n", i,
			  (unsigned char)((char *)pio->piod_addr)[i]);
        }
    }

  errno = saved_errno;
  return result;
}

/* A wrapper around ptrace that allows us to print debug traces of
   ptrace calls if debug traces are activated.  */

static int
netbsd_sysctl (const int *name, u_int namelen, void *oldp, size_t *oldlenp,
  const void *newp, size_t newlen)
{
  int result;

  gdb_assert(name);
  gdb_assert(namelen > 0);

  std::string str = "[" + std::to_string(name[0]);
  for (u_int i = 1; i < namelen; i++)
    str += ", " + std::to_string(name[i]);
  str += "]";

  netbsd_debug ("SYSCTL (name=%s, namelen=%u, oldp=%p, oldlenp=%p, newp=%p, "
                "newlen=%zu)\n",
                str.c_str(), namelen, oldp, oldlenp, newp, newlen);
  result = sysctl(name, namelen, oldp, oldlenp, newp, newlen);

  netbsd_debug (" -> %d (=%#x errno=%d)\n", result, result, errno);

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

static void
netbsd_add_threads_sysctl (pid_t pid)
{
 struct kinfo_lwp *kl;
  int mib[5];
  size_t i, nlwps;
  size_t size;

  mib[0] = CTL_KERN;
  mib[1] = KERN_LWP;
  mib[2] = pid;
  mib[3] = sizeof(struct kinfo_lwp);
  mib[4] = 0;

  if (netbsd_sysctl (mib, 5, NULL, &size, NULL, 0) == -1 || size == 0)
    trace_start_error_with_name ("sysctl");

  mib[4] = size / sizeof(size_t);

  kl = (struct kinfo_lwp *) xmalloc (size);
  if (kl == NULL)
    trace_start_error_with_name ("malloc");

  if (netbsd_sysctl (mib, 5, kl, &size, NULL, 0) == -1 || size == 0)
    trace_start_error_with_name ("sysctl");

  nlwps = size / sizeof(struct kinfo_lwp);

  for (i = 0; i < nlwps; i++) {
    ptid_t ptid = netbsd_ptid_t (pid, kl[i].l_lid);
    netbsd_debug ("Registering thread (pid=%d, lwpid=%d)\n", pid, kl[i].l_lid);
    add_thread (ptid, NULL);
  }

  xfree(kl);
}

const char *
netbsd_thread_name (ptid_t ptid)
{
  netbsd_debug ("%s(ptid=(%d, %d, %d))\n",
                __func__, ptid.pid(), ptid.lwp(), ptid.tid());

  struct kinfo_lwp *kl;
  pid_t pid = ptid.pid ();
  lwpid_t lwp = ptid.lwp ();
  static char buf[KI_LNAMELEN];
  int mib[5];
  size_t i, nlwps;
  size_t size;

  mib[0] = CTL_KERN;
  mib[1] = KERN_LWP;
  mib[2] = pid;
  mib[3] = sizeof(struct kinfo_lwp);
  mib[4] = 0;

  if (netbsd_sysctl (mib, 5, NULL, &size, NULL, 0) == -1 || size == 0)
    perror_with_name (("sysctl"));

  mib[4] = size / sizeof(size_t);

  kl = (struct kinfo_lwp *) xmalloc (size);
  if (kl == NULL)
    perror_with_name (("malloc"));

  if (netbsd_sysctl (mib, 5, kl, &size, NULL, 0) == -1 || size == 0)
    perror_with_name (("sysctl"));

  nlwps = size / sizeof(struct kinfo_lwp);
  buf[0] = '\0';
  for (i = 0; i < nlwps; i++) {
    if (kl[i].l_lid == lwp) {
      xsnprintf (buf, sizeof buf, "%s", kl[i].l_name);
      break;
    }
  }
  xfree(kl);

  return buf;
}

static int
netbsd_supports_catch_syscall (void)
{
  netbsd_debug ("%s()\n", __func__);

  return 1;
}

/* Implementation of the target_ops method "sw_breakpoint_from_kind".  */

static const gdb_byte *
netbsd_sw_breakpoint_from_kind (int kind, int *size)
{
  netbsd_debug ("%s(kind=%d)\n", __func__, kind);

  static gdb_byte brkpt[PTRACE_BREAKPOINT_SIZE];

  *size = PTRACE_BREAKPOINT_SIZE;

  memcpy(brkpt, PTRACE_BREAKPOINT, PTRACE_BREAKPOINT_SIZE);

  return brkpt;
}

/* Implement the to_stopped_by_sw_breakpoint target_ops
   method.  */

static int
netbsd_stopped_by_sw_breakpoint (void)
{
  netbsd_debug ("%s()\n", __func__);

  ptrace_siginfo_t psi;
  pid_t pid = pid_of (current_thread);

  if (netbsd_ptrace (PT_GET_SIGINFO, pid, &psi, sizeof(psi)) == -1)
    return -1; // XXX

  netbsd_debug (" -> psi_lwpid = %d, psi_siginfo.si_signo=SIG%s, "
                "psi_siginfo.si_code=%s\n", psi.psi_lwpid,
                signalname(psi.psi_siginfo.si_signo),
                sigcode_to_str(psi.psi_siginfo.si_signo, psi.psi_siginfo.si_code));

  return psi.psi_siginfo.si_signo == SIGTRAP &&
         psi.psi_siginfo.si_code == TRAP_BRKPT;
}

/* Implement the to_supports_stopped_by_sw_breakpoint target_ops
   method.  */

static int
netbsd_supports_stopped_by_sw_breakpoint (void)
{
  netbsd_debug ("%s()\n", __func__);

  return 1;
}

/* Check if exec events are supported.  */

static int
netbsd_supports_exec_events (void)
{
  netbsd_debug ("%s()\n", __func__);

  return 1;
}

static int
netbsd_supports_disable_randomization (void)
{
  netbsd_debug ("%s()\n", __func__);

  return 0;
}

static int
netbsd_supports_non_stop (void)
{
  netbsd_debug ("%s()\n", __func__);

  return 0;
}

static int
netbsd_supports_multi_process (void)
{
  netbsd_debug ("%s()\n", __func__);

  return 0; /* XXX */
}

/* Check if fork events are supported.  */

static int
netbsd_supports_fork_events (void)
{
  netbsd_debug ("%s()\n", __func__);

  return 1;
}

/* Check if vfork events are supported.  */

static int
netbsd_supports_vfork_events (void)
{
  netbsd_debug ("%s()\n", __func__);

  return 1;
}

/* Implement the create_inferior method of the target_ops vector.  */

int
netbsd_process_target::create_inferior (const char *program,
				      const std::vector<char *> &program_args)
{
  int pid;
  std::string str_program_args = stringify_argv (program_args);

  netbsd_debug ("create_inferior ()");

  pid = fork_inferior (program,
		       str_program_args.c_str (),
		       get_environ ()->envp (), netbsd_ptrace_fun,
		       NULL, NULL, NULL, NULL);

  post_fork_inferior (pid, program);

  netbsd_add_process (pid, 0);

  netbsd_add_threads_sysctl (pid);

  post_fork_inferior (pid, program);
  
  return pid;
}

/* Assuming we've just attached to a running inferior whose pid is PID,
   add all threads running in that process.  */

static void
netbsd_add_threads_after_attach (int pid)
{
  struct ptrace_lwpinfo pl;

  pl.pl_lwpid = 0;
  while (netbsd_ptrace(PT_LWPINFO, pid, (void *)&pl, sizeof(pl)) != -1 &&
    pl.pl_lwpid != 0)
    {
      ptid_t thread_ptid = netbsd_ptid_t (pid, pl.pl_lwpid);

      if (!find_thread_ptid (thread_ptid))
	{
	  netbsd_debug ("New thread: (pid = %d, tid = %d)\n",
		      pid, pl.pl_lwpid);
	  add_thread (thread_ptid, NULL);
	}
    }
}

/* Implement the attach target_ops method.  */

int
netbsd_process_target::attach (unsigned long pid)
{
  ptid_t ptid = netbsd_ptid_t (pid, 0);

  if (netbsd_ptrace (PTRACE_ATTACH, ptid, 0, 0, 0) != 0)
    error ("Cannot attach to process %lu: %s (%d)\n", pid,
	   safe_strerror (errno), errno);

  netbsd_add_process (pid, 1);
  netbsd_add_threads_after_attach (pid);

  return 0;
}

/* Implement the resume target_ops method.  */

void
netbsd_process_target::resume (thread_resume *resume_info, size_t n)
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
   of NetBSD' waitpid.  */

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

ptid_t
netbsd_process_target::wait (ptid_t ptid, target_waitstatus *status,
			   int options)
{
  ptid_t new_ptid;

  netbsd_debug ("wait (pid = %d, tid = %ld)",
              netbsd_ptid_get_pid (ptid), netbsd_ptid_get_tid (ptid));
  new_ptid = netbsd_wait_1 (ptid, status, options);
  netbsd_debug ("          -> (pid=%d, tid=%ld, status->kind = %d)",
	      netbsd_ptid_get_pid (new_ptid), netbsd_ptid_get_tid (new_ptid),
	      status->kind);
  return new_ptid;
}

/* Implement the kill target_ops method.  */

int
netbsd_process_target::kill (process_info *process)
{
  ptid_t ptid = netbsd_ptid_t (process->pid, 0);
  struct target_waitstatus status;

  netbsd_ptrace (PTRACE_KILL, ptid, 0, 0, 0);
  netbsd_wait (ptid, &status, 0);
  mourn (process);
  return 0;
}

/* Implement the detach target_ops method.  */

int
netbsd_process_target::detach (process_info *process)
{
  ptid_t ptid = netbsd_ptid_t (process->pid, 0);

  netbsd_ptrace (PTRACE_DETACH, ptid, 0, 0, 0);
  mourn (process);
  return 0;
}

/* Implement the mourn target_ops method.  */

void
netbsd_process_target::mourn (struct process_info *proc)
{
  for_each_thread (proc->pid, remove_thread);

  /* Free our private data.  */
  free (proc->priv);
  proc->priv = NULL;

  remove_process (proc);
}

/* Implement the join target_ops method.  */

void
netbsd_process_target::join (int pid)
{
  /* The PTRACE_DETACH is sufficient to detach from the process.
     So no need to do anything extra.  */
}

/* Implement the thread_alive target_ops method.  */

bool
netbsd_process_target::thread_alive (ptid_t ptid)
{
  /* The list of threads is updated at the end of each wait, so it
     should be up to date.  No need to re-fetch it.  */
  return (find_thread_ptid (ptid) != NULL);
}

/* Implement the fetch_registers target_ops method.  */

void
netbsd_process_target::fetch_registers (regcache *regcache, int regno)
{
  struct netbsd_regset_info *regset = netbsd_target_regsets;
  ptid_t inferior_ptid = ptid_of (current_thread);

  netbsd_debug ("fetch_registers (regno = %d)", regno);

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

void
netbsd_process_target::store_registers (regcache *regcache, int regno)
{
  struct netbsd_regset_info *regset = netbsd_target_regsets;
  ptid_t inferior_ptid = ptid_of (current_thread);

  netbsd_debug ("store_registers (regno = %d)", regno);

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

int
netbsd_process_target::read_memory (CORE_ADDR memaddr, unsigned char *myaddr,
				  int len)
{
  /* On NetBSD, memory reads needs to be performed in chunks the size
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

int
netbsd_process_target::write_memory (CORE_ADDR memaddr,
				   const unsigned char *myaddr, int len)
{
  /* On NetBSD, memory writes needs to be performed in chunks the size
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
	  read_memory (addr, (unsigned char *) &buf, xfer_size);
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

void
netbsd_process_target::request_interrupt ()
{
  ptid_t inferior_ptid = ptid_of (get_first_thread ());

  kill (netbsd_ptid_get_pid (inferior_ptid), SIGINT);
}

bool
netbsd_process_target::supports_hardware_single_step ()
{
  return true;
}

const gdb_byte *
netbsd_process_target::sw_breakpoint_from_kind (int kind, int *size)
{
  error (_("Target does not implement the sw_breakpoint_from_kind op"));
}

/* The NetBSD target ops object.  */

static netbsd_process_target the_netbsd_target;

void
initialize_low (void)
{
  set_target_ops (&the_netbsd_target);
  the_low_target.arch_setup ();
}

