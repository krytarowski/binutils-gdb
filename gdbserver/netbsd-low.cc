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

/* Return a string image of the ptrace REQUEST number.  */

static const char *
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
netbsd_ptrace (int request, pid_t pid, void *addr, int data)
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
    ptid_t ptid = ptid_t (pid, kl[i].l_lid, 0);
    netbsd_debug ("Registering thread (pid=%d, lwpid=%d)\n", pid, kl[i].l_lid);
    add_thread (ptid, NULL);
  }

  xfree(kl);
}

const char *
netbsd_process_target::thread_name (ptid_t ptid)
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

bool
netbsd_process_target::supports_catch_syscall ()
{
  netbsd_debug ("%s()\n", __func__);

  return 1;
}

/* Implementation of the target_ops method "sw_breakpoint_from_kind".  */

const gdb_byte *
netbsd_process_target::sw_breakpoint_from_kind (int kind, int *size)
{
  netbsd_debug ("%s(kind=%d)\n", __func__, kind);

  static gdb_byte brkpt[PTRACE_BREAKPOINT_SIZE];

  *size = PTRACE_BREAKPOINT_SIZE;

  memcpy(brkpt, PTRACE_BREAKPOINT, PTRACE_BREAKPOINT_SIZE);

  return brkpt;
}

/* Implement the to_stopped_by_sw_breakpoint target_ops
   method.  */

bool
netbsd_process_target::stopped_by_sw_breakpoint ()
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

bool
netbsd_process_target::supports_stopped_by_sw_breakpoint ()
{
  netbsd_debug ("%s()\n", __func__);

  return 1;
}

/* Check if exec events are supported.  */

bool
netbsd_process_target::supports_exec_events ()
{
  netbsd_debug ("%s()\n", __func__);

  return 1;
}

bool
netbsd_process_target::supports_disable_randomization ()
{
  netbsd_debug ("%s()\n", __func__);

  return 0;
}

bool
netbsd_process_target::supports_non_stop ()
{
  netbsd_debug ("%s()\n", __func__);

  return 0;
}

bool
netbsd_process_target::supports_multi_process ()
{
  netbsd_debug ("%s()\n", __func__);

  return 0; /* XXX */
}

/* Check if fork events are supported.  */

bool
netbsd_process_target::supports_fork_events ()
{
  netbsd_debug ("%s()\n", __func__);

  return 1;
}

/* Check if vfork events are supported.  */

bool
netbsd_process_target::supports_vfork_events ()
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
  struct ptrace_lwpstatus pl;

  pl.pl_lwpid = 0;
  while (netbsd_ptrace(PT_LWPNEXT, pid, (void *)&pl, sizeof(pl)) != -1 &&
    pl.pl_lwpid != 0)
    {
      ptid_t thread_ptid = ptid_t (pid, pl.pl_lwpid, 0);

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
  if (netbsd_ptrace (PT_ATTACH, pid, NULL, 0) != 0)
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

  netbsd_debug ("%s()\n", __func__);

  ptid_t ptid = resume_info[0].thread;
  const int signal = resume_info[0].sig;

  if (ptid == minus_one_ptid)
    ptid = ptid_of (current_thread);

  regcache_invalidate_pid (ptid.pid ());

  if (resume_info[0].kind == resume_step)
    {
      if (n == 1)
        {
          struct ptrace_lwpstatus pl;
          int val;
          pl.pl_lwpid = 0;
          while ((val = netbsd_ptrace(PT_LWPNEXT, ptid.pid(), (void *)&pl,
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
          struct ptrace_lwpstatus pl;
          int val;
          pl.pl_lwpid = 0;
          while ((val = netbsd_ptrace(PT_LWPNEXT, ptid.pid(), (void *)&pl,
            sizeof(pl))) != -1 && pl.pl_lwpid != 0)
           {
              netbsd_ptrace (PT_SETSTEP, ptid.pid(), NULL, pl.pl_lwpid);
              netbsd_ptrace (PT_RESUME, ptid.pid(), NULL, pl.pl_lwpid);
           }
        }
    }
  else
    {
      struct ptrace_lwpstatus pl;
      int val;
      pl.pl_lwpid = 0;
      while ((val = netbsd_ptrace(PT_LWPNEXT, ptid.pid(), (void *)&pl, sizeof(pl))) != -1 &&
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

#if 0
static char *
pid_to_exec_file (pid_t pid)
{
  static const int name[] = {
    CTL_KERN, KERN_PROC_ARGS, pid, KERN_PROC_PATHNAME,
  };
  static char path[MAXPATHLEN];
  size_t len;

  len = sizeof(path);
  if (netbsd_sysctl (name, __arraycount(name), path, &len, NULL, 0) == -1)
    return NULL;

  return path;
}
#endif

static void
netbsd_enable_event_reporting (pid_t pid)
{
  ptrace_event_t event;

  ptrace (PT_GET_EVENT_MASK, pid, &event, sizeof(event));

  event.pe_set_event |= PTRACE_FORK;
  event.pe_set_event |= PTRACE_VFORK;
  event.pe_set_event |= PTRACE_VFORK_DONE;
  event.pe_set_event |= PTRACE_LWP_CREATE;
  event.pe_set_event |= PTRACE_LWP_EXIT;
  event.pe_set_event |= PTRACE_POSIX_SPAWN;

  netbsd_ptrace (PT_SET_EVENT_MASK, pid, &event, sizeof(event));
}

#if 0
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
#endif


/* Implement the wait target_ops method.  */

static ptid_t
netbsd_wait_1 (ptid_t ptid, struct target_waitstatus *ourstatus, int target_options)
{
  pid_t pid;
  int status;

  if (ptid == minus_one_ptid)
    ptid = ptid_of (current_thread);

  pid = ptid.pid();

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
      if (netbsd_ptrace (PT_GET_SIGINFO, wpid, &psi, sizeof(psi)) == -1)
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

      ptid_t wptid = ptid_t (wpid, lwp, 0);

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
#ifdef PTRACE_BREAKPOINT_ADJ
              {
                CORE_ADDR pc;
                struct reg r;
                netbsd_ptrace (PT_GETREGS, wpid, &r, psi.psi_lwpid);
                pc = PTRACE_REG_PC (&r);
                PTRACE_REG_SET_PC (&r, pc - PTRACE_BREAKPOINT_ADJ);
                netbsd_ptrace (PT_SETREGS, wpid, &r, psi.psi_lwpid);
              }
#endif
            case TRAP_DBREG:
            case TRAP_TRACE:
              /* These stop reasons return STOPPED and are distinguished later */
              break;
            case TRAP_SCE:
              ourstatus->kind = TARGET_WAITKIND_SYSCALL_ENTRY;
              ourstatus->value.syscall_number = psi.psi_siginfo.si_sysnum;
              break;
            case TRAP_SCX:
              ourstatus->kind = TARGET_WAITKIND_SYSCALL_RETURN;
              ourstatus->value.syscall_number = psi.psi_siginfo.si_sysnum;
              break;
#if 0
            case TRAP_EXEC:
              ourstatus->kind = TARGET_WAITKIND_EXECD;
              ourstatus->value.execd_pathname = xstrdup(pid_to_exec_file (wpid));
              break;
#endif
            case TRAP_LWP:
            case TRAP_CHLD:
              if (netbsd_ptrace (PT_GET_PROCESS_STATE, wpid, &pst, sizeof(pst)) == -1)
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

                  wchild = netbsd_waitpid (child, &status, 0);

                  if (wchild == -1)
                    perror_with_name (("waitpid"));

                  gdb_assert (wchild == child);

                  if (!WIFSTOPPED(status))
                    {
                      /* Abnormal situation (SIGKILLed?).. bail out */
                      ourstatus->kind = TARGET_WAITKIND_SPURIOUS;
                      return wptid;
                    }

                  if (netbsd_ptrace (PT_GET_SIGINFO, child, &child_psi, sizeof(child_psi)) == -1)
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
                  wptid = ptid_t (wpid, pst.pe_lwp, 0);
                  if (!find_thread_ptid (wptid))
                    {
                      add_thread (wptid, NULL);
                    }
                  ourstatus->kind = TARGET_WAITKIND_THREAD_CREATED;
                  break;
                case PTRACE_LWP_EXIT:
                  wptid = ptid_t (wpid, pst.pe_lwp, 0);
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
                  if (netbsd_ptrace (PT_CONTINUE, pid, (void *)1, 0) == -1)
                    perror_with_name (("ptrace"));
#endif
                  break;
                }
              break;
            }
          break;
        }
      return wptid;
    }

  return null_ptid;
}

/* A wrapper around netbsd_wait_1 that also prints debug traces when
   such debug traces have been activated.  */

ptid_t
netbsd_process_target::wait (ptid_t ptid, target_waitstatus *status,
			   int options)
{
  ptid_t new_ptid;

  netbsd_debug ("%s (pid = %d, options=%s)\n", __func__,
                ptid.pid(), options & TARGET_WNOHANG ? "WNOHANG" : "0" );
  new_ptid = netbsd_wait_1 (ptid, status, options);
  netbsd_debug ("          -> (pid=%d, status->kind = %s)\n",
	        new_ptid.pid(), netbsd_wait_kind_to_str(status->kind));
  if (status->kind == TARGET_WAITKIND_EXECD)
    {
        netbsd_debug ("          -> (execd_pathname='%s')\n",
                      status->value.execd_pathname);
    }

  return new_ptid;
}

/* Implement the kill target_ops method.  */

int
netbsd_process_target::kill (process_info *process)
{
  pid_t pid = process->pid;
  ptid_t ptid = ptid_t (pid, 0, 0);
  struct target_waitstatus status;

  netbsd_ptrace (PT_KILL, pid, NULL, 0);
  this->wait (ptid, &status, 0);
  mourn (process);
  return 0;
}

/* Implement the detach target_ops method.  */

int
netbsd_process_target::detach (process_info *process)
{
  pid_t pid = process->pid;

  netbsd_ptrace (PT_DETACH, pid, NULL, 0);
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
  /* The PT_DETACH is sufficient to detach from the process.
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

      buf = (char *) xmalloc (regset->size);
      res = netbsd_ptrace (regset->get_request, inferior_ptid.pid(), buf, 0);
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

      buf = (char*) xmalloc (regset->size);
      res = netbsd_ptrace (regset->get_request, inferior_ptid.pid (), buf, inferior_ptid.lwp ());
      if (res == 0)
        {
	  /* Then overlay our cached registers on that.  */
	  regset->fill_function (regcache, buf);
	  /* Only now do we write the register set.  */
	  res = netbsd_ptrace (regset->set_request, inferior_ptid.pid (), buf,
			     inferior_ptid.lwp ());
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
				  int size)
{
  netbsd_debug ("%s(memaddr=%p, myaddr=%p, size=%d)\n",
                __func__, memaddr, myaddr, size);

  struct ptrace_io_desc io;
  io.piod_op = PIOD_READ_D;
  io.piod_len = size;

  ptid_t inferior_ptid = ptid_of (current_thread);

  int bytes_read = 0;

  if (size == 0)
    {
      /* Zero length write always succeeds.  */
      return 0;
    }
  do
    {
      io.piod_offs = (void *)(memaddr + bytes_read);
      io.piod_addr = myaddr + bytes_read;

      int rv = netbsd_ptrace (PT_IO, inferior_ptid.pid(), &io, 0);
      if (rv == -1)
        return errno;
      if (io.piod_len == 0)
        return 0;

      bytes_read += io.piod_len;
      io.piod_len = size - bytes_read;
    }
  while (bytes_read < size);

  return 0;
}

/* Implement the write_memory target_ops method.  */

int
netbsd_process_target::write_memory (CORE_ADDR memaddr,
				   const unsigned char *myaddr, int size)
{
  netbsd_debug ("%s(memaddr=%p, myaddr=%p, size=%d)\n",
                __func__, memaddr, myaddr, size);

  struct ptrace_io_desc io;
  io.piod_op = PIOD_WRITE_D;
  io.piod_len = size;

  ptid_t inferior_ptid = ptid_of (current_thread);

  int bytes_written = 0;

  if (size == 0)
    {
      /* Zero length write always succeeds.  */
      return 0;
    }

  do
    {
      io.piod_addr = (void *)(myaddr + bytes_written);
      io.piod_offs = (void *)(memaddr + bytes_written);

      int rv = netbsd_ptrace (PT_IO, inferior_ptid.pid(), &io, 0);
      if (rv == -1)
        return errno;
      if (io.piod_len == 0)
        return 0;

      bytes_written += io.piod_len;
      io.piod_len = size - bytes_written;
    }
  while (bytes_written < size);

  return 0;
}

/* Implement the kill_request target_ops method.  */

void
netbsd_process_target::request_interrupt ()
{
  ptid_t inferior_ptid = ptid_of (get_first_thread ());

  ::kill (inferior_ptid.pid(), SIGINT);
}

bool
netbsd_process_target::supports_hardware_single_step ()
{
  return true;
}

/* The NetBSD target ops object.  */

static netbsd_process_target the_netbsd_target;

void
initialize_low (void)
{
  set_target_ops (&the_netbsd_target);
  the_low_target.arch_setup ();
}

