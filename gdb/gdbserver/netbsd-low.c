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

/* LWP accessors.  */

/* See nat/netbsd-nat.h.  */

ptid_t
ptid_of_lwp (struct lwp_info *lwp)
{
  return ptid_of (get_lwp_thread (lwp));
}

/* See nat/netbsd-nat.h.  */

void
lwp_set_arch_private_info (struct lwp_info *lwp,
			   struct arch_lwp_info *info)
{
  lwp->arch_private = info;
}

/* See nat/netbsd-nat.h.  */

struct arch_lwp_info *
lwp_arch_private_info (struct lwp_info *lwp)
{
  return lwp->arch_private;
}

/* See nat/netbsd-nat.h.  */

int
lwp_is_stopped (struct lwp_info *lwp)
{
  return lwp->stopped;
}

/* See nat/netbsd-nat.h.  */

enum target_stop_reason
lwp_stop_reason (struct lwp_info *lwp)
{
  return lwp->stop_reason;
}

/* See nat/netbsd-nat.h.  */

int
lwp_is_stepping (struct lwp_info *lwp)
{
  return lwp->stepping;
}

/* A list of all unknown processes which receive stop signals.  Some
   other process will presumably claim each of these as forked
   children momentarily.  */

struct simple_pid_list
{
  /* The process ID.  */
  int pid;

  /* The status as reported by waitpid.  */
  int status;

  /* Next in chain.  */
  struct simple_pid_list *next;
};
struct simple_pid_list *stopped_pids;

/* Trivial list manipulation functions to keep track of a list of new
   stopped processes.  */

static void
add_to_pid_list (struct simple_pid_list **listp, int pid, int status)
{
  struct simple_pid_list *new_pid = XNEW (struct simple_pid_list);

  new_pid->pid = pid;
  new_pid->status = status;
  new_pid->next = *listp;
  *listp = new_pid;
}

static int
pull_pid_from_list (struct simple_pid_list **listp, int pid, int *statusp)
{
  struct simple_pid_list **p;

  for (p = listp; *p != NULL; p = &(*p)->next)
    if ((*p)->pid == pid)
      {
	struct simple_pid_list *next = (*p)->next;

	*statusp = (*p)->status;
	xfree (*p);
	*p = next;
	return 1;
      }
  return 0;
}

enum stopping_threads_kind
  {
    /* Not stopping threads presently.  */
    NOT_STOPPING_THREADS,

    /* Stopping threads.  */
    STOPPING_THREADS,

    /* Stopping and suspending threads.  */
    STOPPING_AND_SUSPENDING_THREADS
  };

/* This is set while stop_all_lwps is in effect.  */
enum stopping_threads_kind stopping_threads = NOT_STOPPING_THREADS;

/* FIXME make into a target method?  */
int using_threads = 1;

/* True if we're presently stabilizing threads (moving them out of
   jump pads).  */
static int stabilizing_threads;

static void netbsd_resume_one_lwp (struct lwp_info *lwp,
				  int step, int signal, siginfo_t *info);
static void netbsd_resume (struct thread_resume *resume_info, size_t n);
static void stop_all_lwps (int suspend, struct lwp_info *except);
static void unstop_all_lwps (int unsuspend, struct lwp_info *except);
static void unsuspend_all_lwps (struct lwp_info *except);
static int netbsd_wait_for_event_filtered (ptid_t wait_ptid, ptid_t filter_ptid,
					  int *wstat, int options);
static int netbsd_wait_for_event (ptid_t ptid, int *wstat, int options);
static struct lwp_info *add_lwp (ptid_t ptid);
static void netbsd_mourn (struct process_info *process);
static int netbsd_stopped_by_watchpoint (void);
static void mark_lwp_dead (struct lwp_info *lwp, int wstat);
static int lwp_is_marked_dead (struct lwp_info *lwp);
static void proceed_all_lwps (void);
static int finish_step_over (struct lwp_info *lwp);
static int kill_lwp (unsigned long lwpid, int signo);
static void enqueue_pending_signal (struct lwp_info *lwp, int signal, siginfo_t *info);
static void complete_ongoing_step_over (void);
static int netbsd_low_ptrace_options (int attached);
static int check_ptrace_stopped_lwp_gone (struct lwp_info *lp);
static void proceed_one_lwp (thread_info *thread, lwp_info *except);

/* When the event-loop is doing a step-over, this points at the thread
   being stepped.  */
ptid_t step_over_bkpt;

/* True if the low target can hardware single-step.  */

static int
can_hardware_single_step (void)
{
  if (the_low_target.supports_hardware_single_step != NULL)
    return the_low_target.supports_hardware_single_step ();
  else
    return 0;
}

/* True if the low target can software single-step.  Such targets
   implement the GET_NEXT_PCS callback.  */

static int
can_software_single_step (void)
{
  return (the_low_target.get_next_pcs != NULL);
}

/* True if the low target supports memory breakpoints.  If so, we'll
   have a GET_PC implementation.  */

static int
supports_breakpoints (void)
{
  return (the_low_target.get_pc != NULL);
}

/* Returns true if this target can support fast tracepoints.  This
   does not mean that the in-process agent has been loaded in the
   inferior.  */

static int
supports_fast_tracepoints (void)
{
  return the_low_target.install_fast_tracepoint_jump_pad != NULL;
}

/* True if LWP is stopped in its stepping range.  */

static int
lwp_in_step_range (struct lwp_info *lwp)
{
  CORE_ADDR pc = lwp->stop_pc;

  return (pc >= lwp->step_range_start && pc < lwp->step_range_end);
}

struct pending_signals
{
  int signal;
  siginfo_t info;
  struct pending_signals *prev;
};

/* The read/write ends of the pipe registered as waitable file in the
   event loop.  */
static int netbsd_event_pipe[2] = { -1, -1 };

/* True if we're currently in async mode.  */
#define target_is_async_p() (netbsd_event_pipe[0] != -1)

static void send_sigstop (struct lwp_info *lwp);
static void wait_for_sigstop (void);

/* Return non-zero if HEADER is a 64-bit ELF file.  */

static int
elf_64_header_p (const Elf64_Ehdr *header, unsigned int *machine)
{
  if (header->e_ident[EI_MAG0] == ELFMAG0
      && header->e_ident[EI_MAG1] == ELFMAG1
      && header->e_ident[EI_MAG2] == ELFMAG2
      && header->e_ident[EI_MAG3] == ELFMAG3)
    {
      *machine = header->e_machine;
      return header->e_ident[EI_CLASS] == ELFCLASS64;

    }
  *machine = EM_NONE;
  return -1;
}

/* Return non-zero if FILE is a 64-bit ELF file,
   zero if the file is not a 64-bit ELF file,
   and -1 if the file is not accessible or doesn't exist.  */

static int
elf_64_file_p (const char *file, unsigned int *machine)
{
  Elf64_Ehdr header;
  int fd;

  fd = open (file, O_RDONLY);
  if (fd < 0)
    return -1;

  if (read (fd, &header, sizeof (header)) != sizeof (header))
    {
      close (fd);
      return 0;
    }
  close (fd);

  return elf_64_header_p (&header, machine);
}

/* Accepts an integer PID; Returns true if the executable PID is
   running is a 64-bit ELF file..  */

int
netbsd_pid_exe_is_elf_64_file (int pid, unsigned int *machine)
{
  char file[PATH_MAX];

  sprintf (file, "/proc/%d/exe", pid);
  return elf_64_file_p (file, machine);
}

static void
delete_lwp (struct lwp_info *lwp)
{
  struct thread_info *thr = get_lwp_thread (lwp);

  if (debug_threads)
    debug_printf ("deleting %ld\n", lwpid_of (thr));

  remove_thread (thr);

  if (the_low_target.delete_thread != NULL)
    the_low_target.delete_thread (lwp->arch_private);
  else
    gdb_assert (lwp->arch_private == NULL);

  free (lwp);
}

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

static CORE_ADDR get_pc (struct lwp_info *lwp);

/* Call the target arch_setup function on the current thread.  */

static void
netbsd_arch_setup (void)
{
  the_low_target.arch_setup ();
}

/* Call the target arch_setup function on THREAD.  */

static void
netbsd_arch_setup_thread (struct thread_info *thread)
{
  struct thread_info *saved_thread;

  saved_thread = current_thread;
  current_thread = thread;

  netbsd_arch_setup ();

  current_thread = saved_thread;
}

/* Return the PC as read from the regcache of LWP, without any
   adjustment.  */

static CORE_ADDR
get_pc (struct lwp_info *lwp)
{
  struct thread_info *saved_thread;
  struct regcache *regcache;
  CORE_ADDR pc;

  if (the_low_target.get_pc == NULL)
    return 0;

  saved_thread = current_thread;
  current_thread = get_lwp_thread (lwp);

  regcache = get_thread_regcache (current_thread, 1);
  pc = (*the_low_target.get_pc) (regcache);

  if (debug_threads)
    debug_printf ("pc is 0x%lx\n", (long) pc);

  current_thread = saved_thread;
  return pc;
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

/* Callback to be used when calling fork_inferior, responsible for
   actually initiating the tracing of the inferior.  */

static void
netbsd_ptrace_fun ()
{
  if (ptrace (PT_TRACE_ME, 0, (PTRACE_TYPE_ARG3) 0,
	      (PTRACE_TYPE_ARG4) 0) < 0)
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

/* Start an inferior process and returns its pid.
   PROGRAM is the name of the program to be started, and PROGRAM_ARGS
   are its arguments.  */

static int
netbsd_create_inferior (const char *program,
		       const std::vector<char *> &program_args)
{
  struct lwp_info *new_lwp;
  int pid;
  ptid_t ptid;

  {
    std::string str_program_args = stringify_argv (program_args);

    pid = fork_inferior (program,
			 str_program_args.c_str (),
			 get_environ ()->envp (), netbsd_ptrace_fun,
			 NULL, NULL, NULL, NULL);
  }

  netbsd_add_process (pid, 0);

  ptid = ptid_t (pid, pid, 0);
  new_lwp = add_lwp (ptid);
  new_lwp->must_set_ptrace_flags = 1;

  post_fork_inferior (pid, program);

  return pid;
}

/* Implement the post_create_inferior target_ops method.  */

static void
netbsd_post_create_inferior (void)
{
  pid_t pid = current_ptid.pid ();

  netbsd_enable_event_reporting (pid);
}

/* Attach to PID.  If PID is the tgid, attach to it and all
   of its threads.  */

static int
netbsd_attach (unsigned long pid)
{
  struct process_info *proc;
  struct thread_info *initial_thread;
  int err;

  proc = netbsd_add_process (pid, 1);

  err = ptrace(PT_ATTACH, pid, NULL, 0);
  if (err != 0)
    {
      remove_process (proc);
      error ("Cannot attach to process %ld: %s", pid, strerror(errno));
    }

  /* Don't ignore the initial SIGSTOP if we just attached to this
     process.  It will be collected by wait shortly.  */
  initial_thread = find_thread_ptid (ptid_t (pid, pid, 0));
  initial_thread->last_resume_kind = resume_stop;

  return 0;
}

static int
netbsd_kill (process_info *process)
{
  int pid = process->pid;

  ptrace(PT_KILL, pid, NULL, 0);

  return 0;
}

/* Get pending signal of THREAD, for detaching purposes.  This is the
   signal the thread last stopped for, which we need to deliver to the
   thread when detaching, otherwise, it'd be suppressed/lost.  */

static int
get_detach_signal (struct thread_info *thread)
{
  client_state &cs = get_client_state ();
  enum gdb_signal signo = GDB_SIGNAL_0;
  int status;
  struct lwp_info *lp = get_thread_lwp (thread);

  if (lp->status_pending_p)
    status = lp->status_pending;
  else
    {
      /* If the thread had been suspended by gdbserver, and it stopped
	 cleanly, then it'll have stopped with SIGSTOP.  But we don't
	 want to deliver that SIGSTOP.  */
      if (thread->last_status.kind != TARGET_WAITKIND_STOPPED
	  || thread->last_status.value.sig == GDB_SIGNAL_0)
	return 0;

      /* Otherwise, we may need to deliver the signal we
	 intercepted.  */
      status = lp->last_status;
    }

  if (!WIFSTOPPED (status))
    {
      if (debug_threads)
	debug_printf ("GPS: lwp %s hasn't stopped: no pending signal\n",
		      target_pid_to_str (ptid_of (thread)));
      return 0;
    }

  /* Extended wait statuses aren't real SIGTRAPs.  */
  if (WSTOPSIG (status) == SIGTRAP && netbsd_is_extended_waitstatus (status))
    {
      if (debug_threads)
	debug_printf ("GPS: lwp %s had stopped with extended "
		      "status: no pending signal\n",
		      target_pid_to_str (ptid_of (thread)));
      return 0;
    }

  signo = gdb_signal_from_host (WSTOPSIG (status));

  if (cs.program_signals_p && !cs.program_signals[signo])
    {
      if (debug_threads)
	debug_printf ("GPS: lwp %s had signal %s, but it is in nopass state\n",
		      target_pid_to_str (ptid_of (thread)),
		      gdb_signal_to_string (signo));
      return 0;
    }
  else if (!cs.program_signals_p
	   /* If we have no way to know which signals GDB does not
	      want to have passed to the program, assume
	      SIGTRAP/SIGINT, which is GDB's default.  */
	   && (signo == GDB_SIGNAL_TRAP || signo == GDB_SIGNAL_INT))
    {
      if (debug_threads)
	debug_printf ("GPS: lwp %s had signal %s, "
		      "but we don't know if we should pass it. "
		      "Default to not.\n",
		      target_pid_to_str (ptid_of (thread)),
		      gdb_signal_to_string (signo));
      return 0;
    }
  else
    {
      if (debug_threads)
	debug_printf ("GPS: lwp %s has pending signal %s: delivering it.\n",
		      target_pid_to_str (ptid_of (thread)),
		      gdb_signal_to_string (signo));

      return WSTOPSIG (status);
    }
}

/* Detach from LWP.  */

static void
netbsd_detach_one_lwp (struct lwp_info *lwp)
{
  struct thread_info *thread = get_lwp_thread (lwp);
  int sig;
  int lwpid;

  /* If there is a pending SIGSTOP, get rid of it.  */
  if (lwp->stop_expected)
    {
      if (debug_threads)
	debug_printf ("Sending SIGCONT to %s\n",
		      target_pid_to_str (ptid_of (thread)));

      kill_lwp (lwpid_of (thread), SIGCONT);
      lwp->stop_expected = 0;
    }

  /* Pass on any pending signal for this thread.  */
  sig = get_detach_signal (thread);

  /* Preparing to resume may try to write registers, and fail if the
     lwp is zombie.  If that happens, ignore the error.  We'll handle
     it below, when detach fails with ESRCH.  */
  try
    {
      /* Flush any pending changes to the process's registers.  */
      regcache_invalidate_thread (thread);

      /* Finally, let it resume.  */
      if (the_low_target.prepare_to_resume != NULL)
	the_low_target.prepare_to_resume (lwp);
    }
  catch (const gdb_exception_error &ex)
    {
      if (!check_ptrace_stopped_lwp_gone (lwp))
	throw;
    }

  lwpid = lwpid_of (thread);
  if (ptrace (PTRACE_DETACH, lwpid, (PTRACE_TYPE_ARG3) 0,
	      (PTRACE_TYPE_ARG4) (long) sig) < 0)
    {
      int save_errno = errno;

      /* We know the thread exists, so ESRCH must mean the lwp is
	 zombie.  This can happen if one of the already-detached
	 threads exits the whole thread group.  In that case we're
	 still attached, and must reap the lwp.  */
      if (save_errno == ESRCH)
	{
	  int ret, status;

	  ret = my_waitpid (lwpid, &status, __WALL);
	  if (ret == -1)
	    {
	      warning (_("Couldn't reap LWP %d while detaching: %s"),
		       lwpid, strerror (errno));
	    }
	  else if (!WIFEXITED (status) && !WIFSIGNALED (status))
	    {
	      warning (_("Reaping LWP %d while detaching "
			 "returned unexpected status 0x%x"),
		       lwpid, status);
	    }
	}
      else
	{
	  error (_("Can't detach %s: %s"),
		 target_pid_to_str (ptid_of (thread)),
		 strerror (save_errno));
	}
    }
  else if (debug_threads)
    {
      debug_printf ("PTRACE_DETACH (%s, %s, 0) (OK)\n",
		    target_pid_to_str (ptid_of (thread)),
		    strsignal (sig));
    }

  delete_lwp (lwp);
}

/* Callback for for_each_thread.  Detaches from non-leader threads of a
   given process.  */

static void
netbsd_detach_lwp_callback (thread_info *thread)
{
  /* We don't actually detach from the thread group leader just yet.
     If the thread group exits, we must reap the zombie clone lwps
     before we're able to reap the leader.  */
  if (thread->id.pid () == thread->id.lwp ())
    return;

  lwp_info *lwp = get_thread_lwp (thread);
  netbsd_detach_one_lwp (lwp);
}

static int
netbsd_detach (process_info *process)
{
  struct lwp_info *main_lwp;

  /* As there's a step over already in progress, let it finish first,
     otherwise nesting a stabilize_threads operation on top gets real
     messy.  */
  complete_ongoing_step_over ();

  /* Stop all threads before detaching.  First, ptrace requires that
     the thread is stopped to sucessfully detach.  Second, thread_db
     may need to uninstall thread event breakpoints from memory, which
     only works with a stopped process anyway.  */
  stop_all_lwps (0, NULL);

#ifdef USE_THREAD_DB
  thread_db_detach (process);
#endif

  /* Stabilize threads (move out of jump pads).  */
  stabilize_threads ();

  /* Detach from the clone lwps first.  If the thread group exits just
     while we're detaching, we must reap the clone lwps before we're
     able to reap the leader.  */
  for_each_thread (process->pid, netbsd_detach_lwp_callback);

  main_lwp = find_lwp_pid (ptid_t (process->pid));
  netbsd_detach_one_lwp (main_lwp);

  the_target->mourn (process);

  /* Since we presently can only stop all lwps of all processes, we
     need to unstop lwps of other processes.  */
  unstop_all_lwps (0, NULL);
  return 0;
}

/* Remove all LWPs that belong to process PROC from the lwp list.  */

static void
netbsd_mourn (struct process_info *process)
{
  struct process_info_private *priv;

#ifdef USE_THREAD_DB
  thread_db_mourn (process);
#endif

  for_each_thread (process->pid, [] (thread_info *thread)
    {
      delete_lwp (get_thread_lwp (thread));
    });

  /* Freeing all private data.  */
  priv = process->priv;
  if (the_low_target.delete_process != NULL)
    the_low_target.delete_process (priv->arch_private);
  else
    gdb_assert (priv->arch_private == NULL);
  free (priv);
  process->priv = NULL;

  remove_process (process);
}

static void
netbsd_join (int pid)
{
  int status, ret;

  do {
    ret = my_waitpid (pid, &status, 0);
    if (WIFEXITED (status) || WIFSIGNALED (status))
      break;
  } while (ret != -1 || errno != ECHILD);
}

/* Return nonzero if the given thread is still alive.  */
static int
netbsd_thread_alive (ptid_t ptid)
{
  struct lwp_info *lwp = find_lwp_pid (ptid);

  /* We assume we always know if a thread exits.  If a whole process
     exited but we still haven't been able to report it to GDB, we'll
     hold on to the last lwp of the dead process.  */
  if (lwp != NULL)
    return !lwp_is_marked_dead (lwp);
  else
    return 0;
}

/* Return 1 if this lwp still has an interesting status pending.  If
   not (e.g., it had stopped for a breakpoint that is gone), return
   false.  */

static int
thread_still_has_status_pending_p (struct thread_info *thread)
{
  struct lwp_info *lp = get_thread_lwp (thread);

  if (!lp->status_pending_p)
    return 0;

  if (thread->last_resume_kind != resume_stop
      && (lp->stop_reason == TARGET_STOPPED_BY_SW_BREAKPOINT
	  || lp->stop_reason == TARGET_STOPPED_BY_HW_BREAKPOINT))
    {
      struct thread_info *saved_thread;
      CORE_ADDR pc;
      int discard = 0;

      gdb_assert (lp->last_status != 0);

      pc = get_pc (lp);

      saved_thread = current_thread;
      current_thread = thread;

      if (pc != lp->stop_pc)
	{
	  if (debug_threads)
	    debug_printf ("PC of %ld changed\n",
			  lwpid_of (thread));
	  discard = 1;
	}

#if !USE_SIGTRAP_SIGINFO
      else if (lp->stop_reason == TARGET_STOPPED_BY_SW_BREAKPOINT
	       && !(*the_low_target.breakpoint_at) (pc))
	{
	  if (debug_threads)
	    debug_printf ("previous SW breakpoint of %ld gone\n",
			  lwpid_of (thread));
	  discard = 1;
	}
      else if (lp->stop_reason == TARGET_STOPPED_BY_HW_BREAKPOINT
	       && !hardware_breakpoint_inserted_here (pc))
	{
	  if (debug_threads)
	    debug_printf ("previous HW breakpoint of %ld gone\n",
			  lwpid_of (thread));
	  discard = 1;
	}
#endif

      current_thread = saved_thread;

      if (discard)
	{
	  if (debug_threads)
	    debug_printf ("discarding pending breakpoint status\n");
	  lp->status_pending_p = 0;
	  return 0;
	}
    }

  return 1;
}

/* Returns true if LWP is resumed from the client's perspective.  */

static int
lwp_resumed (struct lwp_info *lwp)
{
  struct thread_info *thread = get_lwp_thread (lwp);

  if (thread->last_resume_kind != resume_stop)
    return 1;

  /* Did gdb send us a `vCont;t', but we haven't reported the
     corresponding stop to gdb yet?  If so, the thread is still
     resumed/running from gdb's perspective.  */
  if (thread->last_resume_kind == resume_stop
      && thread->last_status.kind == TARGET_WAITKIND_IGNORE)
    return 1;

  return 0;
}

/* Return true if this lwp has an interesting status pending.  */
static bool
status_pending_p_callback (thread_info *thread, ptid_t ptid)
{
  struct lwp_info *lp = get_thread_lwp (thread);

  /* Check if we're only interested in events from a specific process
     or a specific LWP.  */
  if (!thread->id.matches (ptid))
    return 0;

  if (!lwp_resumed (lp))
    return 0;

  if (lp->status_pending_p
      && !thread_still_has_status_pending_p (thread))
    {
      netbsd_resume_one_lwp (lp, lp->stepping, GDB_SIGNAL_0, NULL);
      return 0;
    }

  return lp->status_pending_p;
}

struct lwp_info *
find_lwp_pid (ptid_t ptid)
{
  thread_info *thread = find_thread ([&] (thread_info *thr_arg)
    {
      int lwp = ptid.lwp () != 0 ? ptid.lwp () : ptid.pid ();
      return thr_arg->id.lwp () == lwp;
    });

  if (thread == NULL)
    return NULL;

  return get_thread_lwp (thread);
}

/* Return the number of known LWPs in the tgid given by PID.  */

static int
num_lwps (int pid)
{
  int count = 0;

  for_each_thread (pid, [&] (thread_info *thread)
    {
      count++;
    });

  return count;
}

/* See nat/netbsd-nat.h.  */

struct lwp_info *
iterate_over_lwps (ptid_t filter,
		   gdb::function_view<iterate_over_lwps_ftype> callback)
{
  thread_info *thread = find_thread (filter, [&] (thread_info *thr_arg)
    {
      lwp_info *lwp = get_thread_lwp (thr_arg);

      return callback (lwp);
    });

  if (thread == NULL)
    return NULL;

  return get_thread_lwp (thread);
}

/* Detect zombie thread group leaders, and "exit" them.  We can't reap
   their exits until all other threads in the group have exited.  */

static void
check_zombie_leaders (void)
{
  for_each_process ([] (process_info *proc) {
    pid_t leader_pid = pid_of (proc);
    struct lwp_info *leader_lp;

    leader_lp = find_lwp_pid (ptid_t (leader_pid));

    if (debug_threads)
      debug_printf ("leader_pid=%d, leader_lp!=NULL=%d, "
		    "num_lwps=%d, zombie=%d\n",
		    leader_pid, leader_lp!= NULL, num_lwps (leader_pid),
		    netbsd_proc_pid_is_zombie (leader_pid));

    if (leader_lp != NULL && !leader_lp->stopped
	/* Check if there are other threads in the group, as we may
	   have raced with the inferior simply exiting.  */
	&& !last_thread_of_process_p (leader_pid)
	&& netbsd_proc_pid_is_zombie (leader_pid))
      {
	/* A leader zombie can mean one of two things:

	   - It exited, and there's an exit status pending
	   available, or only the leader exited (not the whole
	   program).  In the latter case, we can't waitpid the
	   leader's exit status until all other threads are gone.

	   - There are 3 or more threads in the group, and a thread
	   other than the leader exec'd.  On an exec, the netbsd
	   kernel destroys all other threads (except the execing
	   one) in the thread group, and resets the execing thread's
	   tid to the tgid.  No exit notification is sent for the
	   execing thread -- from the ptracer's perspective, it
	   appears as though the execing thread just vanishes.
	   Until we reap all other threads except the leader and the
	   execing thread, the leader will be zombie, and the
	   execing thread will be in `D (disc sleep)'.  As soon as
	   all other threads are reaped, the execing thread changes
	   it's tid to the tgid, and the previous (zombie) leader
	   vanishes, giving place to the "new" leader.  We could try
	   distinguishing the exit and exec cases, by waiting once
	   more, and seeing if something comes out, but it doesn't
	   sound useful.  The previous leader _does_ go away, and
	   we'll re-add the new one once we see the exec event
	   (which is just the same as what would happen if the
	   previous leader did exit voluntarily before some other
	   thread execs).  */

	if (debug_threads)
	  debug_printf ("CZL: Thread group leader %d zombie "
			"(it exited, or another thread execd).\n",
			leader_pid);

	delete_lwp (leader_lp);
      }
    });
}

/* Callback for `find_thread'.  Returns the first LWP that is not
   stopped.  */

static bool
not_stopped_callback (thread_info *thread, ptid_t filter)
{
  if (!thread->id.matches (filter))
    return false;

  lwp_info *lwp = get_thread_lwp (thread);

  return !lwp->stopped;
}

/* Increment LWP's suspend count.  */

static void
lwp_suspended_inc (struct lwp_info *lwp)
{
  lwp->suspended++;

  if (debug_threads && lwp->suspended > 4)
    {
      struct thread_info *thread = get_lwp_thread (lwp);

      debug_printf ("LWP %ld has a suspiciously high suspend count,"
		    " suspended=%d\n", lwpid_of (thread), lwp->suspended);
    }
}

/* Decrement LWP's suspend count.  */

static void
lwp_suspended_decr (struct lwp_info *lwp)
{
  lwp->suspended--;

  if (lwp->suspended < 0)
    {
      struct thread_info *thread = get_lwp_thread (lwp);

      internal_error (__FILE__, __LINE__,
		      "unsuspend LWP %ld, suspended=%d\n", lwpid_of (thread),
		      lwp->suspended);
    }
}

/* This function should only be called if the LWP got a SIGTRAP.

   Handle any tracepoint steps or hits.  Return true if a tracepoint
   event was handled, 0 otherwise.  */

static int
handle_tracepoints (struct lwp_info *lwp)
{
  struct thread_info *tinfo = get_lwp_thread (lwp);
  int tpoint_related_event = 0;

  gdb_assert (lwp->suspended == 0);

  /* If this tracepoint hit causes a tracing stop, we'll immediately
     uninsert tracepoints.  To do this, we temporarily pause all
     threads, unpatch away, and then unpause threads.  We need to make
     sure the unpausing doesn't resume LWP too.  */
  lwp_suspended_inc (lwp);

  /* And we need to be sure that any all-threads-stopping doesn't try
     to move threads out of the jump pads, as it could deadlock the
     inferior (LWP could be in the jump pad, maybe even holding the
     lock.)  */

  /* Do any necessary step collect actions.  */
  tpoint_related_event |= tracepoint_finished_step (tinfo, lwp->stop_pc);

  tpoint_related_event |= handle_tracepoint_bkpts (tinfo, lwp->stop_pc);

  /* See if we just hit a tracepoint and do its main collect
     actions.  */
  tpoint_related_event |= tracepoint_was_hit (tinfo, lwp->stop_pc);

  lwp_suspended_decr (lwp);

  gdb_assert (lwp->suspended == 0);
  gdb_assert (!stabilizing_threads
	      || (lwp->collecting_fast_tracepoint
		  != fast_tpoint_collect_result::not_collecting));

  if (tpoint_related_event)
    {
      if (debug_threads)
	debug_printf ("got a tracepoint event\n");
      return 1;
    }

  return 0;
}

/* Convenience wrapper.  Returns information about LWP's fast tracepoint
   collection status.  */

static fast_tpoint_collect_result
netbsd_fast_tracepoint_collecting (struct lwp_info *lwp,
				  struct fast_tpoint_collect_status *status)
{
  CORE_ADDR thread_area;
  struct thread_info *thread = get_lwp_thread (lwp);

  if (the_low_target.get_thread_area == NULL)
    return fast_tpoint_collect_result::not_collecting;

  /* Get the thread area address.  This is used to recognize which
     thread is which when tracing with the in-process agent library.
     We don't read anything from the address, and treat it as opaque;
     it's the address itself that we assume is unique per-thread.  */
  if ((*the_low_target.get_thread_area) (lwpid_of (thread), &thread_area) == -1)
    return fast_tpoint_collect_result::not_collecting;

  return fast_tracepoint_collecting (thread_area, lwp->stop_pc, status);
}

/* The reason we resume in the caller, is because we want to be able
   to pass lwp->status_pending as WSTAT, and we need to clear
   status_pending_p before resuming, otherwise, netbsd_resume_one_lwp
   refuses to resume.  */

static int
maybe_move_out_of_jump_pad (struct lwp_info *lwp, int *wstat)
{
  struct thread_info *saved_thread;

  saved_thread = current_thread;
  current_thread = get_lwp_thread (lwp);

  if ((wstat == NULL
       || (WIFSTOPPED (*wstat) && WSTOPSIG (*wstat) != SIGTRAP))
      && supports_fast_tracepoints ()
      && agent_loaded_p ())
    {
      struct fast_tpoint_collect_status status;

      if (debug_threads)
	debug_printf ("Checking whether LWP %ld needs to move out of the "
		      "jump pad.\n",
		      lwpid_of (current_thread));

      fast_tpoint_collect_result r
	= netbsd_fast_tracepoint_collecting (lwp, &status);

      if (wstat == NULL
	  || (WSTOPSIG (*wstat) != SIGILL
	      && WSTOPSIG (*wstat) != SIGFPE
	      && WSTOPSIG (*wstat) != SIGSEGV
	      && WSTOPSIG (*wstat) != SIGBUS))
	{
	  lwp->collecting_fast_tracepoint = r;

	  if (r != fast_tpoint_collect_result::not_collecting)
	    {
	      if (r == fast_tpoint_collect_result::before_insn
		  && lwp->exit_jump_pad_bkpt == NULL)
		{
		  /* Haven't executed the original instruction yet.
		     Set breakpoint there, and wait till it's hit,
		     then single-step until exiting the jump pad.  */
		  lwp->exit_jump_pad_bkpt
		    = set_breakpoint_at (status.adjusted_insn_addr, NULL);
		}

	      if (debug_threads)
		debug_printf ("Checking whether LWP %ld needs to move out of "
			      "the jump pad...it does\n",
			      lwpid_of (current_thread));
	      current_thread = saved_thread;

	      return 1;
	    }
	}
      else
	{
	  /* If we get a synchronous signal while collecting, *and*
	     while executing the (relocated) original instruction,
	     reset the PC to point at the tpoint address, before
	     reporting to GDB.  Otherwise, it's an IPA lib bug: just
	     report the signal to GDB, and pray for the best.  */

	  lwp->collecting_fast_tracepoint
	    = fast_tpoint_collect_result::not_collecting;

	  if (r != fast_tpoint_collect_result::not_collecting
	      && (status.adjusted_insn_addr <= lwp->stop_pc
		  && lwp->stop_pc < status.adjusted_insn_addr_end))
	    {
	      siginfo_t info;
	      struct regcache *regcache;

	      /* The si_addr on a few signals references the address
		 of the faulting instruction.  Adjust that as
		 well.  */
	      if ((WSTOPSIG (*wstat) == SIGILL
		   || WSTOPSIG (*wstat) == SIGFPE
		   || WSTOPSIG (*wstat) == SIGBUS
		   || WSTOPSIG (*wstat) == SIGSEGV)
		  && ptrace (PTRACE_GETSIGINFO, lwpid_of (current_thread),
			     (PTRACE_TYPE_ARG3) 0, &info) == 0
		  /* Final check just to make sure we don't clobber
		     the siginfo of non-kernel-sent signals.  */
		  && (uintptr_t) info.si_addr == lwp->stop_pc)
		{
		  info.si_addr = (void *) (uintptr_t) status.tpoint_addr;
		  ptrace (PTRACE_SETSIGINFO, lwpid_of (current_thread),
			  (PTRACE_TYPE_ARG3) 0, &info);
		}

	      regcache = get_thread_regcache (current_thread, 1);
	      (*the_low_target.set_pc) (regcache, status.tpoint_addr);
	      lwp->stop_pc = status.tpoint_addr;

	      /* Cancel any fast tracepoint lock this thread was
		 holding.  */
	      force_unlock_trace_buffer ();
	    }

	  if (lwp->exit_jump_pad_bkpt != NULL)
	    {
	      if (debug_threads)
		debug_printf ("Cancelling fast exit-jump-pad: removing bkpt. "
			      "stopping all threads momentarily.\n");

	      stop_all_lwps (1, lwp);

	      delete_breakpoint (lwp->exit_jump_pad_bkpt);
	      lwp->exit_jump_pad_bkpt = NULL;

	      unstop_all_lwps (1, lwp);

	      gdb_assert (lwp->suspended >= 0);
	    }
	}
    }

  if (debug_threads)
    debug_printf ("Checking whether LWP %ld needs to move out of the "
		  "jump pad...no\n",
		  lwpid_of (current_thread));

  current_thread = saved_thread;
  return 0;
}

/* Enqueue one signal in the "signals to report later when out of the
   jump pad" list.  */

static void
enqueue_one_deferred_signal (struct lwp_info *lwp, int *wstat)
{
  struct pending_signals *p_sig;
  struct thread_info *thread = get_lwp_thread (lwp);

  if (debug_threads)
    debug_printf ("Deferring signal %d for LWP %ld.\n",
		  WSTOPSIG (*wstat), lwpid_of (thread));

  if (debug_threads)
    {
      struct pending_signals *sig;

      for (sig = lwp->pending_signals_to_report;
	   sig != NULL;
	   sig = sig->prev)
	debug_printf ("   Already queued %d\n",
		      sig->signal);

      debug_printf ("   (no more currently queued signals)\n");
    }

  /* Don't enqueue non-RT signals if they are already in the deferred
     queue.  (SIGSTOP being the easiest signal to see ending up here
     twice)  */
  if (WSTOPSIG (*wstat) < __SIGRTMIN)
    {
      struct pending_signals *sig;

      for (sig = lwp->pending_signals_to_report;
	   sig != NULL;
	   sig = sig->prev)
	{
	  if (sig->signal == WSTOPSIG (*wstat))
	    {
	      if (debug_threads)
		debug_printf ("Not requeuing already queued non-RT signal %d"
			      " for LWP %ld\n",
			      sig->signal,
			      lwpid_of (thread));
	      return;
	    }
	}
    }

  p_sig = XCNEW (struct pending_signals);
  p_sig->prev = lwp->pending_signals_to_report;
  p_sig->signal = WSTOPSIG (*wstat);

  ptrace (PTRACE_GETSIGINFO, lwpid_of (thread), (PTRACE_TYPE_ARG3) 0,
	  &p_sig->info);

  lwp->pending_signals_to_report = p_sig;
}

/* Dequeue one signal from the "signals to report later when out of
   the jump pad" list.  */

static int
dequeue_one_deferred_signal (struct lwp_info *lwp, int *wstat)
{
  struct thread_info *thread = get_lwp_thread (lwp);

  if (lwp->pending_signals_to_report != NULL)
    {
      struct pending_signals **p_sig;

      p_sig = &lwp->pending_signals_to_report;
      while ((*p_sig)->prev != NULL)
	p_sig = &(*p_sig)->prev;

      *wstat = W_STOPCODE ((*p_sig)->signal);
      if ((*p_sig)->info.si_signo != 0)
	ptrace (PTRACE_SETSIGINFO, lwpid_of (thread), (PTRACE_TYPE_ARG3) 0,
		&(*p_sig)->info);
      free (*p_sig);
      *p_sig = NULL;

      if (debug_threads)
	debug_printf ("Reporting deferred signal %d for LWP %ld.\n",
		      WSTOPSIG (*wstat), lwpid_of (thread));

      if (debug_threads)
	{
	  struct pending_signals *sig;

	  for (sig = lwp->pending_signals_to_report;
	       sig != NULL;
	       sig = sig->prev)
	    debug_printf ("   Still queued %d\n",
			  sig->signal);

	  debug_printf ("   (no more queued signals)\n");
	}

      return 1;
    }

  return 0;
}

/* Fetch the possibly triggered data watchpoint info and store it in
   CHILD.

   On some archs, like x86, that use debug registers to set
   watchpoints, it's possible that the way to know which watched
   address trapped, is to check the register that is used to select
   which address to watch.  Problem is, between setting the watchpoint
   and reading back which data address trapped, the user may change
   the set of watchpoints, and, as a consequence, GDB changes the
   debug registers in the inferior.  To avoid reading back a stale
   stopped-data-address when that happens, we cache in LP the fact
   that a watchpoint trapped, and the corresponding data address, as
   soon as we see CHILD stop with a SIGTRAP.  If GDB changes the debug
   registers meanwhile, we have the cached data we can rely on.  */

static int
check_stopped_by_watchpoint (struct lwp_info *child)
{
  if (the_low_target.stopped_by_watchpoint != NULL)
    {
      struct thread_info *saved_thread;

      saved_thread = current_thread;
      current_thread = get_lwp_thread (child);

      if (the_low_target.stopped_by_watchpoint ())
	{
	  child->stop_reason = TARGET_STOPPED_BY_WATCHPOINT;

	  if (the_low_target.stopped_data_address != NULL)
	    child->stopped_data_address
	      = the_low_target.stopped_data_address ();
	  else
	    child->stopped_data_address = 0;
	}

      current_thread = saved_thread;
    }

  return child->stop_reason == TARGET_STOPPED_BY_WATCHPOINT;
}

/* Return the ptrace options that we want to try to enable.  */

static int
netbsd_low_ptrace_options (int attached)
{
  client_state &cs = get_client_state ();
  int options = 0;

  if (!attached)
    options |= PTRACE_O_EXITKILL;

  if (cs.report_fork_events)
    options |= PTRACE_O_TRACEFORK;

  if (cs.report_vfork_events)
    options |= (PTRACE_O_TRACEVFORK | PTRACE_O_TRACEVFORKDONE);

  if (cs.report_exec_events)
    options |= PTRACE_O_TRACEEXEC;

  options |= PTRACE_O_TRACESYSGOOD;

  return options;
}

/* Do low-level handling of the event, and check if we should go on
   and pass it to caller code.  Return the affected lwp if we are, or
   NULL otherwise.  */

static struct lwp_info *
netbsd_low_filter_event (int lwpid, int wstat)
{
  client_state &cs = get_client_state ();
  struct lwp_info *child;
  struct thread_info *thread;
  int have_stop_pc = 0;

  child = find_lwp_pid (ptid_t (lwpid));

  /* Check for stop events reported by a process we didn't already
     know about - anything not already in our LWP list.

     If we're expecting to receive stopped processes after
     fork, vfork, and clone events, then we'll just add the
     new one to our list and go back to waiting for the event
     to be reported - the stopped process might be returned
     from waitpid before or after the event is.

     But note the case of a non-leader thread exec'ing after the
     leader having exited, and gone from our lists (because
     check_zombie_leaders deleted it).  The non-leader thread
     changes its tid to the tgid.  */

  if (WIFSTOPPED (wstat) && child == NULL && WSTOPSIG (wstat) == SIGTRAP
      && netbsd_ptrace_get_extended_event (wstat) == PTRACE_EVENT_EXEC)
    {
      ptid_t child_ptid;

      /* A multi-thread exec after we had seen the leader exiting.  */
      if (debug_threads)
	{
	  debug_printf ("LLW: Re-adding thread group leader LWP %d"
			"after exec.\n", lwpid);
	}

      child_ptid = ptid_t (lwpid, lwpid, 0);
      child = add_lwp (child_ptid);
      child->stopped = 1;
      current_thread = child->thread;
    }

  /* If we didn't find a process, one of two things presumably happened:
     - A process we started and then detached from has exited.  Ignore it.
     - A process we are controlling has forked and the new child's stop
     was reported to us by the kernel.  Save its PID.  */
  if (child == NULL && WIFSTOPPED (wstat))
    {
      add_to_pid_list (&stopped_pids, lwpid, wstat);
      return NULL;
    }
  else if (child == NULL)
    return NULL;

  thread = get_lwp_thread (child);

  child->stopped = 1;

  child->last_status = wstat;

  /* Check if the thread has exited.  */
  if ((WIFEXITED (wstat) || WIFSIGNALED (wstat)))
    {
      if (debug_threads)
	debug_printf ("LLFE: %d exited.\n", lwpid);

      if (finish_step_over (child))
	{
	  /* Unsuspend all other LWPs, and set them back running again.  */
	  unsuspend_all_lwps (child);
	}

      /* If there is at least one more LWP, then the exit signal was
	 not the end of the debugged application and should be
	 ignored, unless GDB wants to hear about thread exits.  */
      if (cs.report_thread_events
	  || last_thread_of_process_p (pid_of (thread)))
	{
	  /* Since events are serialized to GDB core, and we can't
	     report this one right now.  Leave the status pending for
	     the next time we're able to report it.  */
	  mark_lwp_dead (child, wstat);
	  return child;
	}
      else
	{
	  delete_lwp (child);
	  return NULL;
	}
    }

  gdb_assert (WIFSTOPPED (wstat));

  if (WIFSTOPPED (wstat))
    {
      struct process_info *proc;

      /* Architecture-specific setup after inferior is running.  */
      proc = find_process_pid (pid_of (thread));
      if (proc->tdesc == NULL)
	{
	  if (proc->attached)
	    {
	      /* This needs to happen after we have attached to the
		 inferior and it is stopped for the first time, but
		 before we access any inferior registers.  */
	      netbsd_arch_setup_thread (thread);
	    }
	  else
	    {
	      /* The process is started, but GDBserver will do
		 architecture-specific setup after the program stops at
		 the first instruction.  */
	      child->status_pending_p = 1;
	      child->status_pending = wstat;
	      return child;
	    }
	}
    }

  if (WIFSTOPPED (wstat) && child->must_set_ptrace_flags)
    {
      struct process_info *proc = find_process_pid (pid_of (thread));
      int options = netbsd_low_ptrace_options (proc->attached);

      netbsd_enable_event_reporting (lwpid, options);
      child->must_set_ptrace_flags = 0;
    }

  /* Always update syscall_state, even if it will be filtered later.  */
  if (WIFSTOPPED (wstat) && WSTOPSIG (wstat) == SYSCALL_SIGTRAP)
    {
      child->syscall_state
	= (child->syscall_state == TARGET_WAITKIND_SYSCALL_ENTRY
	   ? TARGET_WAITKIND_SYSCALL_RETURN
	   : TARGET_WAITKIND_SYSCALL_ENTRY);
    }
  else
    {
      /* Almost all other ptrace-stops are known to be outside of system
	 calls, with further exceptions in handle_extended_wait.  */
      child->syscall_state = TARGET_WAITKIND_IGNORE;
    }

  /* Be careful to not overwrite stop_pc until save_stop_reason is
     called.  */
  if (WIFSTOPPED (wstat) && WSTOPSIG (wstat) == SIGTRAP
      && netbsd_is_extended_waitstatus (wstat))
    {
      child->stop_pc = get_pc (child);
      if (handle_extended_wait (&child, wstat))
	{
	  /* The event has been handled, so just return without
	     reporting it.  */
	  return NULL;
	}
    }

  if (netbsd_wstatus_maybe_breakpoint (wstat))
    {
      if (save_stop_reason (child))
	have_stop_pc = 1;
    }

  if (!have_stop_pc)
    child->stop_pc = get_pc (child);

  if (WIFSTOPPED (wstat) && WSTOPSIG (wstat) == SIGSTOP
      && child->stop_expected)
    {
      if (debug_threads)
	debug_printf ("Expected stop.\n");
      child->stop_expected = 0;

      if (thread->last_resume_kind == resume_stop)
	{
	  /* We want to report the stop to the core.  Treat the
	     SIGSTOP as a normal event.  */
	  if (debug_threads)
	    debug_printf ("LLW: resume_stop SIGSTOP caught for %s.\n",
			  target_pid_to_str (ptid_of (thread)));
	}
      else if (stopping_threads != NOT_STOPPING_THREADS)
	{
	  /* Stopping threads.  We don't want this SIGSTOP to end up
	     pending.  */
	  if (debug_threads)
	    debug_printf ("LLW: SIGSTOP caught for %s "
			  "while stopping threads.\n",
			  target_pid_to_str (ptid_of (thread)));
	  return NULL;
	}
      else
	{
	  /* This is a delayed SIGSTOP.  Filter out the event.  */
	  if (debug_threads)
	    debug_printf ("LLW: %s %s, 0, 0 (discard delayed SIGSTOP)\n",
			  child->stepping ? "step" : "continue",
			  target_pid_to_str (ptid_of (thread)));

	  netbsd_resume_one_lwp (child, child->stepping, 0, NULL);
	  return NULL;
	}
    }

  child->status_pending_p = 1;
  child->status_pending = wstat;
  return child;
}

/* Return true if THREAD is doing hardware single step.  */

static int
maybe_hw_step (struct thread_info *thread)
{
  if (can_hardware_single_step ())
    return 1;
  else
    {
      /* GDBserver must insert single-step breakpoint for software
	 single step.  */
      gdb_assert (has_single_step_breakpoints (thread));
      return 0;
    }
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
   * Polling on traced parent always simplifies the code.
   */
  ptid = inferior_ptid;

  if (debug_nbsd_lwp)
    fprintf_unfiltered (gdb_stdlog, "NLWP: calling super_wait (%d, %ld, %ld) target_options=%#x\n",
                        ptid.pid (), ptid.lwp (), ptid.tid (), target_options);

  wptid = inf_ptrace_target::wait (ptid, ourstatus, target_options);

  if (debug_nbsd_lwp)
    fprintf_unfiltered (gdb_stdlog, "NLWP: returned from super_wait (%d, %ld, %ld) target_options=%#x with ourstatus->kind=%d\n",
                        ptid.pid (), ptid.lwp (), ptid.tid (),
			target_options, ourstatus->kind);

  if (ourstatus->kind == TARGET_WAITKIND_STOPPED)
    {
      ptrace_state_t pst;
      ptrace_siginfo_t psi, child_psi;
      int status;
      pid_t pid, child, wchild;
      ptid_t child_ptid;
      lwpid_t lwp;

      pid = wptid.pid ();
      // Find the lwp that caused the wait status change
      if (ptrace(PT_GET_SIGINFO, pid, &psi, sizeof(psi)) == -1)
        perror_with_name (("ptrace"));

      /* For whole-process signals pick random thread */
      if (psi.psi_lwpid == 0) {
        // XXX: Is this always valid?
        lwp = inferior_ptid.lwp ();
      } else {
        lwp = psi.psi_lwpid;
      }

      wptid = ptid_t (pid, lwp, 0);

      /* Set LWP in the process */
      if (in_thread_list (ptid_t (pid))) {
          if (debug_nbsd_lwp)
            fprintf_unfiltered (gdb_stdlog,
                                "NLWP: using LWP %d for first thread\n",
                                lwp);
          thread_change_ptid (ptid_t (pid), wptid);                                                                                                 
      }

      if (debug_nbsd_lwp)
         fprintf_unfiltered (gdb_stdlog,
                             "NLWP: received signal=%d si_code=%d in process=%d lwp=%d\n",
                             psi.psi_siginfo.si_signo, psi.psi_siginfo.si_code, pid, lwp);

      switch (psi.psi_siginfo.si_signo) {
      case SIGTRAP:
        switch (psi.psi_siginfo.si_code) {
        case TRAP_BRKPT:
//          lp->stop_reason = TARGET_STOPPED_BY_SW_BREAKPOINT;
          break;
        case TRAP_DBREG:
//          if (hardware_breakpoint_inserted_here_p (get_regcache_aspace (regcache), pc))
//            lp->stop_reason = TARGET_STOPPED_BY_HW_BREAKPOINT;
//          else
//            lp->stop_reason = TARGET_STOPPED_BY_WATCHPOINT;
          break;
        case TRAP_TRACE:
//          lp->stop_reason = TARGET_STOPPED_BY_SINGLE_STEP;
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
          switch (pst.pe_report_event) {
          case PTRACE_FORK:
          case PTRACE_VFORK:
            if (pst.pe_report_event == PTRACE_FORK)
              ourstatus->kind = TARGET_WAITKIND_FORKED;
            else
              ourstatus->kind = TARGET_WAITKIND_VFORKED;
            child = pst.pe_other_pid;

            if (debug_nbsd_lwp)
              fprintf_unfiltered (gdb_stdlog,
                                  "NLWP: registered %s event for PID %d\n",
                                  (pst.pe_report_event == PTRACE_FORK) ? "FORK" : "VFORK", child);

            wchild = waitpid (child, &status, 0);

            if (wchild == -1)
              perror_with_name (("waitpid"));

            gdb_assert (wchild == child);

            if (!WIFSTOPPED(status)) {
              /* Abnormal situation (SIGKILLed?).. bail out */
              ourstatus->kind = TARGET_WAITKIND_SPURIOUS;
              return wptid;
            }

            if (ptrace(PT_GET_SIGINFO, child, &child_psi, sizeof(child_psi)) == -1)
              perror_with_name (("ptrace"));

            if (child_psi.psi_siginfo.si_signo != SIGTRAP) {
              /* Abnormal situation.. bail out */
              ourstatus->kind = TARGET_WAITKIND_SPURIOUS;
              return wptid;
            }

            if (child_psi.psi_siginfo.si_code != TRAP_CHLD) {
              /* Abnormal situation.. bail out */
              ourstatus->kind = TARGET_WAITKIND_SPURIOUS;
              return wptid;
            }

            child_ptid = ptid_t (child, child_psi.psi_lwpid, 0);
            nbsd_enable_proc_events (child_ptid.pid ());
            ourstatus->value.related_pid = child_ptid;
            break;
          case PTRACE_VFORK_DONE:
            ourstatus->kind = TARGET_WAITKIND_VFORK_DONE;
            if (debug_nbsd_lwp)
              fprintf_unfiltered (gdb_stdlog, "NLWP: reported VFORK_DONE parent=%d child=%d\n", pid, pst.pe_other_pid);
            break;
          case PTRACE_LWP_CREATE:
            wptid = ptid_t (pid, pst.pe_lwp, 0);
            if (in_thread_list (wptid)) {
              /* Newborn reported after attach? */
              ourstatus->kind = TARGET_WAITKIND_SPURIOUS;
              return wptid;
            }
            add_thread (wptid);
            ourstatus->kind = TARGET_WAITKIND_THREAD_CREATED;
            if (debug_nbsd_lwp)
              fprintf_unfiltered (gdb_stdlog, "NLWP: created LWP %d\n", pst.pe_lwp);
            break;
          case PTRACE_LWP_EXIT:
            wptid = ptid_t (pid, pst.pe_lwp, 0);
            if (!in_thread_list (wptid)) {
              /* Dead child reported after attach? */
              ourstatus->kind = TARGET_WAITKIND_SPURIOUS;
              return wptid;
            }
            delete_thread (find_thread_ptid (wptid));
            ourstatus->kind = TARGET_WAITKIND_THREAD_EXITED;
            if (debug_nbsd_lwp)
              fprintf_unfiltered (gdb_stdlog, "NLWP: exited LWP %d\n", pst.pe_lwp);
            if (ptrace (PT_CONTINUE, pid, (void *)1, 0) == -1)
              perror_with_name (("ptrace"));
            break;
          }
          break;
        }
        break;
      }

      if (debug_nbsd_lwp)
	fprintf_unfiltered (gdb_stdlog,
		"NLWP: nbsd_wait returned (%d, %ld, %ld)\n",
		wptid.pid (), wptid.lwp (),
		wptid.tid ());
      inferior_ptid = wptid;

    }
    return wptid;
}

/* Send a signal to an LWP.  */

static int
kill_lwp (unsigned long lwpid, int signo)
{
  int ret;

  errno = 0;
  ret = syscall (__NR_tkill, lwpid, signo);
  if (errno == ENOSYS)
    {
      /* If tkill fails, then we are not using nptl threads, a
	 configuration we no longer support.  */
      perror_with_name (("tkill"));
    }
  return ret;
}

void
netbsd_stop_lwp (struct lwp_info *lwp)
{
  send_sigstop (lwp);
}

static void
send_sigstop (struct lwp_info *lwp)
{
  int pid;

  pid = lwpid_of (get_lwp_thread (lwp));

  /* If we already have a pending stop signal for this process, don't
     send another.  */
  if (lwp->stop_expected)
    {
      if (debug_threads)
	debug_printf ("Have pending sigstop for lwp %d\n", pid);

      return;
    }

  if (debug_threads)
    debug_printf ("Sending sigstop to lwp %d\n", pid);

  lwp->stop_expected = 1;
  kill_lwp (pid, SIGSTOP);
}

static void
send_sigstop (thread_info *thread, lwp_info *except)
{
  struct lwp_info *lwp = get_thread_lwp (thread);

  /* Ignore EXCEPT.  */
  if (lwp == except)
    return;

  if (lwp->stopped)
    return;

  send_sigstop (lwp);
}

/* Increment the suspend count of an LWP, and stop it, if not stopped
   yet.  */
static void
suspend_and_send_sigstop (thread_info *thread, lwp_info *except)
{
  struct lwp_info *lwp = get_thread_lwp (thread);

  /* Ignore EXCEPT.  */
  if (lwp == except)
    return;

  lwp_suspended_inc (lwp);

  send_sigstop (thread, except);
}

static void
mark_lwp_dead (struct lwp_info *lwp, int wstat)
{
  /* Store the exit status for later.  */
  lwp->status_pending_p = 1;
  lwp->status_pending = wstat;

  /* Store in waitstatus as well, as there's nothing else to process
     for this event.  */
  if (WIFEXITED (wstat))
    {
      lwp->waitstatus.kind = TARGET_WAITKIND_EXITED;
      lwp->waitstatus.value.integer = WEXITSTATUS (wstat);
    }
  else if (WIFSIGNALED (wstat))
    {
      lwp->waitstatus.kind = TARGET_WAITKIND_SIGNALLED;
      lwp->waitstatus.value.sig = gdb_signal_from_host (WTERMSIG (wstat));
    }

  /* Prevent trying to stop it.  */
  lwp->stopped = 1;

  /* No further stops are expected from a dead lwp.  */
  lwp->stop_expected = 0;
}

/* Return true if LWP has exited already, and has a pending exit event
   to report to GDB.  */

static int
lwp_is_marked_dead (struct lwp_info *lwp)
{
  return (lwp->status_pending_p
	  && (WIFEXITED (lwp->status_pending)
	      || WIFSIGNALED (lwp->status_pending)));
}

/* Wait for all children to stop for the SIGSTOPs we just queued.  */

static void
wait_for_sigstop (void)
{
  struct thread_info *saved_thread;
  ptid_t saved_tid;
  int wstat;
  int ret;

  saved_thread = current_thread;
  if (saved_thread != NULL)
    saved_tid = saved_thread->id;
  else
    saved_tid = null_ptid; /* avoid bogus unused warning */

  if (debug_threads)
    debug_printf ("wait_for_sigstop: pulling events\n");

  /* Passing NULL_PTID as filter indicates we want all events to be
     left pending.  Eventually this returns when there are no
     unwaited-for children left.  */
  ret = netbsd_wait_for_event_filtered (minus_one_ptid, null_ptid,
				       &wstat, __WALL);
  gdb_assert (ret == -1);

  if (saved_thread == NULL || netbsd_thread_alive (saved_tid))
    current_thread = saved_thread;
  else
    {
      if (debug_threads)
	debug_printf ("Previously current thread died.\n");

      /* We can't change the current inferior behind GDB's back,
	 otherwise, a subsequent command may apply to the wrong
	 process.  */
      current_thread = NULL;
    }
}

/* Returns true if THREAD is stopped in a jump pad, and we can't
   move it out, because we need to report the stop event to GDB.  For
   example, if the user puts a breakpoint in the jump pad, it's
   because she wants to debug it.  */

static bool
stuck_in_jump_pad_callback (thread_info *thread)
{
  struct lwp_info *lwp = get_thread_lwp (thread);

  if (lwp->suspended != 0)
    {
      internal_error (__FILE__, __LINE__,
		      "LWP %ld is suspended, suspended=%d\n",
		      lwpid_of (thread), lwp->suspended);
    }
  gdb_assert (lwp->stopped);

  /* Allow debugging the jump pad, gdb_collect, etc..  */
  return (supports_fast_tracepoints ()
	  && agent_loaded_p ()
	  && (gdb_breakpoint_here (lwp->stop_pc)
	      || lwp->stop_reason == TARGET_STOPPED_BY_WATCHPOINT
	      || thread->last_resume_kind == resume_step)
	  && (netbsd_fast_tracepoint_collecting (lwp, NULL)
	      != fast_tpoint_collect_result::not_collecting));
}

static void
move_out_of_jump_pad_callback (thread_info *thread)
{
  struct thread_info *saved_thread;
  struct lwp_info *lwp = get_thread_lwp (thread);
  int *wstat;

  if (lwp->suspended != 0)
    {
      internal_error (__FILE__, __LINE__,
		      "LWP %ld is suspended, suspended=%d\n",
		      lwpid_of (thread), lwp->suspended);
    }
  gdb_assert (lwp->stopped);

  /* For gdb_breakpoint_here.  */
  saved_thread = current_thread;
  current_thread = thread;

  wstat = lwp->status_pending_p ? &lwp->status_pending : NULL;

  /* Allow debugging the jump pad, gdb_collect, etc.  */
  if (!gdb_breakpoint_here (lwp->stop_pc)
      && lwp->stop_reason != TARGET_STOPPED_BY_WATCHPOINT
      && thread->last_resume_kind != resume_step
      && maybe_move_out_of_jump_pad (lwp, wstat))
    {
      if (debug_threads)
	debug_printf ("LWP %ld needs stabilizing (in jump pad)\n",
		      lwpid_of (thread));

      if (wstat)
	{
	  lwp->status_pending_p = 0;
	  enqueue_one_deferred_signal (lwp, wstat);

	  if (debug_threads)
	    debug_printf ("Signal %d for LWP %ld deferred "
			  "(in jump pad)\n",
			  WSTOPSIG (*wstat), lwpid_of (thread));
	}

      netbsd_resume_one_lwp (lwp, 0, 0, NULL);
    }
  else
    lwp_suspended_inc (lwp);

  current_thread = saved_thread;
}

static bool
lwp_running (thread_info *thread)
{
  struct lwp_info *lwp = get_thread_lwp (thread);

  if (lwp_is_marked_dead (lwp))
    return false;

  return !lwp->stopped;
}

/* Stop all lwps that aren't stopped yet, except EXCEPT, if not NULL.
   If SUSPEND, then also increase the suspend count of every LWP,
   except EXCEPT.  */

static void
stop_all_lwps (int suspend, struct lwp_info *except)
{
  /* Should not be called recursively.  */
  gdb_assert (stopping_threads == NOT_STOPPING_THREADS);

  if (debug_threads)
    {
      debug_enter ();
      debug_printf ("stop_all_lwps (%s, except=%s)\n",
		    suspend ? "stop-and-suspend" : "stop",
		    except != NULL
		    ? target_pid_to_str (ptid_of (get_lwp_thread (except)))
		    : "none");
    }

  stopping_threads = (suspend
		      ? STOPPING_AND_SUSPENDING_THREADS
		      : STOPPING_THREADS);

  if (suspend)
    for_each_thread ([&] (thread_info *thread)
      {
	suspend_and_send_sigstop (thread, except);
      });
  else
    for_each_thread ([&] (thread_info *thread)
      {
	 send_sigstop (thread, except);
      });

  wait_for_sigstop ();
  stopping_threads = NOT_STOPPING_THREADS;

  if (debug_threads)
    {
      debug_printf ("stop_all_lwps done, setting stopping_threads "
		    "back to !stopping\n");
      debug_exit ();
    }
}

/* Enqueue one signal in the chain of signals which need to be
   delivered to this process on next resume.  */

static void
enqueue_pending_signal (struct lwp_info *lwp, int signal, siginfo_t *info)
{
  struct pending_signals *p_sig = XNEW (struct pending_signals);

  p_sig->prev = lwp->pending_signals;
  p_sig->signal = signal;
  if (info == NULL)
    memset (&p_sig->info, 0, sizeof (siginfo_t));
  else
    memcpy (&p_sig->info, info, sizeof (siginfo_t));
  lwp->pending_signals = p_sig;
}

/* Install breakpoints for software single stepping.  */

static void
install_software_single_step_breakpoints (struct lwp_info *lwp)
{
  struct thread_info *thread = get_lwp_thread (lwp);
  struct regcache *regcache = get_thread_regcache (thread, 1);

  scoped_restore save_current_thread = make_scoped_restore (&current_thread);

  current_thread = thread;
  std::vector<CORE_ADDR> next_pcs = the_low_target.get_next_pcs (regcache);

  for (CORE_ADDR pc : next_pcs)
    set_single_step_breakpoint (pc, current_ptid);
}

/* Single step via hardware or software single step.
   Return 1 if hardware single stepping, 0 if software single stepping
   or can't single step.  */

static int
single_step (struct lwp_info* lwp)
{
  int step = 0;

  if (can_hardware_single_step ())
    {
      step = 1;
    }
  else if (can_software_single_step ())
    {
      install_software_single_step_breakpoints (lwp);
      step = 0;
    }
  else
    {
      if (debug_threads)
	debug_printf ("stepping is not implemented on this target");
    }

  return step;
}

/* The signal can be delivered to the inferior if we are not trying to
   finish a fast tracepoint collect.  Since signal can be delivered in
   the step-over, the program may go to signal handler and trap again
   after return from the signal handler.  We can live with the spurious
   double traps.  */

static int
lwp_signal_can_be_delivered (struct lwp_info *lwp)
{
  return (lwp->collecting_fast_tracepoint
	  == fast_tpoint_collect_result::not_collecting);
}

/* Resume execution of LWP.  If STEP is nonzero, single-step it.  If
   SIGNAL is nonzero, give it that signal.  */

static void
netbsd_resume_one_lwp_throw (struct lwp_info *lwp,
			    int step, int signal, siginfo_t *info)
{
  struct thread_info *thread = get_lwp_thread (lwp);
  struct thread_info *saved_thread;
  int ptrace_request;
  struct process_info *proc = get_thread_process (thread);

  /* Note that target description may not be initialised
     (proc->tdesc == NULL) at this point because the program hasn't
     stopped at the first instruction yet.  It means GDBserver skips
     the extra traps from the wrapper program (see option --wrapper).
     Code in this function that requires register access should be
     guarded by proc->tdesc == NULL or something else.  */

  if (lwp->stopped == 0)
    return;

  gdb_assert (lwp->waitstatus.kind == TARGET_WAITKIND_IGNORE);

  fast_tpoint_collect_result fast_tp_collecting
    = lwp->collecting_fast_tracepoint;

  gdb_assert (!stabilizing_threads
	      || (fast_tp_collecting
		  != fast_tpoint_collect_result::not_collecting));

  /* Cancel actions that rely on GDB not changing the PC (e.g., the
     user used the "jump" command, or "set $pc = foo").  */
  if (thread->while_stepping != NULL && lwp->stop_pc != get_pc (lwp))
    {
      /* Collecting 'while-stepping' actions doesn't make sense
	 anymore.  */
      release_while_stepping_state_list (thread);
    }

  /* If we have pending signals or status, and a new signal, enqueue the
     signal.  Also enqueue the signal if it can't be delivered to the
     inferior right now.  */
  if (signal != 0
      && (lwp->status_pending_p
	  || lwp->pending_signals != NULL
	  || !lwp_signal_can_be_delivered (lwp)))
    {
      enqueue_pending_signal (lwp, signal, info);

      /* Postpone any pending signal.  It was enqueued above.  */
      signal = 0;
    }

  if (lwp->status_pending_p)
    {
      if (debug_threads)
	debug_printf ("Not resuming lwp %ld (%s, stop %s);"
		      " has pending status\n",
		      lwpid_of (thread), step ? "step" : "continue",
		      lwp->stop_expected ? "expected" : "not expected");
      return;
    }

  saved_thread = current_thread;
  current_thread = thread;

  /* This bit needs some thinking about.  If we get a signal that
     we must report while a single-step reinsert is still pending,
     we often end up resuming the thread.  It might be better to
     (ew) allow a stack of pending events; then we could be sure that
     the reinsert happened right away and not lose any signals.

     Making this stack would also shrink the window in which breakpoints are
     uninserted (see comment in netbsd_wait_for_lwp) but not enough for
     complete correctness, so it won't solve that problem.  It may be
     worthwhile just to solve this one, however.  */
  if (lwp->bp_reinsert != 0)
    {
      if (debug_threads)
	debug_printf ("  pending reinsert at 0x%s\n",
		      paddress (lwp->bp_reinsert));

      if (can_hardware_single_step ())
	{
	  if (fast_tp_collecting == fast_tpoint_collect_result::not_collecting)
	    {
	      if (step == 0)
		warning ("BAD - reinserting but not stepping.");
	      if (lwp->suspended)
		warning ("BAD - reinserting and suspended(%d).",
				 lwp->suspended);
	    }
	}

      step = maybe_hw_step (thread);
    }

  if (fast_tp_collecting == fast_tpoint_collect_result::before_insn)
    {
      if (debug_threads)
	debug_printf ("lwp %ld wants to get out of fast tracepoint jump pad"
		      " (exit-jump-pad-bkpt)\n",
		      lwpid_of (thread));
    }
  else if (fast_tp_collecting == fast_tpoint_collect_result::at_insn)
    {
      if (debug_threads)
	debug_printf ("lwp %ld wants to get out of fast tracepoint jump pad"
		      " single-stepping\n",
		      lwpid_of (thread));

      if (can_hardware_single_step ())
	step = 1;
      else
	{
	  internal_error (__FILE__, __LINE__,
			  "moving out of jump pad single-stepping"
			  " not implemented on this target");
	}
    }

  /* If we have while-stepping actions in this thread set it stepping.
     If we have a signal to deliver, it may or may not be set to
     SIG_IGN, we don't know.  Assume so, and allow collecting
     while-stepping into a signal handler.  A possible smart thing to
     do would be to set an internal breakpoint at the signal return
     address, continue, and carry on catching this while-stepping
     action only when that breakpoint is hit.  A future
     enhancement.  */
  if (thread->while_stepping != NULL)
    {
      if (debug_threads)
	debug_printf ("lwp %ld has a while-stepping action -> forcing step.\n",
		      lwpid_of (thread));

      step = single_step (lwp);
    }

  if (proc->tdesc != NULL && the_low_target.get_pc != NULL)
    {
      struct regcache *regcache = get_thread_regcache (current_thread, 1);

      lwp->stop_pc = (*the_low_target.get_pc) (regcache);

      if (debug_threads)
	{
	  debug_printf ("  %s from pc 0x%lx\n", step ? "step" : "continue",
			(long) lwp->stop_pc);
	}
    }

  /* If we have pending signals, consume one if it can be delivered to
     the inferior.  */
  if (lwp->pending_signals != NULL && lwp_signal_can_be_delivered (lwp))
    {
      struct pending_signals **p_sig;

      p_sig = &lwp->pending_signals;
      while ((*p_sig)->prev != NULL)
	p_sig = &(*p_sig)->prev;

      signal = (*p_sig)->signal;
      if ((*p_sig)->info.si_signo != 0)
	ptrace (PTRACE_SETSIGINFO, lwpid_of (thread), (PTRACE_TYPE_ARG3) 0,
		&(*p_sig)->info);

      free (*p_sig);
      *p_sig = NULL;
    }

  if (debug_threads)
    debug_printf ("Resuming lwp %ld (%s, signal %d, stop %s)\n",
		  lwpid_of (thread), step ? "step" : "continue", signal,
		  lwp->stop_expected ? "expected" : "not expected");

  if (the_low_target.prepare_to_resume != NULL)
    the_low_target.prepare_to_resume (lwp);

  regcache_invalidate_thread (thread);
  errno = 0;
  lwp->stepping = step;
  if (step)
    ptrace_request = PTRACE_SINGLESTEP;
  else if (gdb_catching_syscalls_p (lwp))
    ptrace_request = PTRACE_SYSCALL;
  else
    ptrace_request = PTRACE_CONT;
  ptrace (ptrace_request,
	  lwpid_of (thread),
	  (PTRACE_TYPE_ARG3) 0,
	  /* Coerce to a uintptr_t first to avoid potential gcc warning
	     of coercing an 8 byte integer to a 4 byte pointer.  */
	  (PTRACE_TYPE_ARG4) (uintptr_t) signal);

  current_thread = saved_thread;
  if (errno)
    perror_with_name ("resuming thread");

  /* Successfully resumed.  Clear state that no longer makes sense,
     and mark the LWP as running.  Must not do this before resuming
     otherwise if that fails other code will be confused.  E.g., we'd
     later try to stop the LWP and hang forever waiting for a stop
     status.  Note that we must not throw after this is cleared,
     otherwise handle_zombie_lwp_error would get confused.  */
  lwp->stopped = 0;
  lwp->stop_reason = TARGET_STOPPED_BY_NO_REASON;
}

/* Called when we try to resume a stopped LWP and that errors out.  If
   the LWP is no longer in ptrace-stopped state (meaning it's zombie,
   or about to become), discard the error, clear any pending status
   the LWP may have, and return true (we'll collect the exit status
   soon enough).  Otherwise, return false.  */

static int
check_ptrace_stopped_lwp_gone (struct lwp_info *lp)
{
  struct thread_info *thread = get_lwp_thread (lp);

  /* If we get an error after resuming the LWP successfully, we'd
     confuse !T state for the LWP being gone.  */
  gdb_assert (lp->stopped);

  /* We can't just check whether the LWP is in 'Z (Zombie)' state,
     because even if ptrace failed with ESRCH, the tracee may be "not
     yet fully dead", but already refusing ptrace requests.  In that
     case the tracee has 'R (Running)' state for a little bit
     (observed in netbsd 3.18).  See also the note on ESRCH in the
     ptrace(2) man page.  Instead, check whether the LWP has any state
     other than ptrace-stopped.  */

  /* Don't assume anything if /proc/PID/status can't be read.  */
  if (netbsd_proc_pid_is_trace_stopped_nowarn (lwpid_of (thread)) == 0)
    {
      lp->stop_reason = TARGET_STOPPED_BY_NO_REASON;
      lp->status_pending_p = 0;
      return 1;
    }
  return 0;
}

/* Like netbsd_resume_one_lwp_throw, but no error is thrown if the LWP
   disappears while we try to resume it.  */

static void
netbsd_resume_one_lwp (struct lwp_info *lwp,
		      int step, int signal, siginfo_t *info)
{
  try
    {
      netbsd_resume_one_lwp_throw (lwp, step, signal, info);
    }
  catch (const gdb_exception_error &ex)
    {
      if (!check_ptrace_stopped_lwp_gone (lwp))
	throw;
    }
}

/* This function is called once per thread via for_each_thread.
   We look up which resume request applies to THREAD and mark it with a
   pointer to the appropriate resume request.

   This algorithm is O(threads * resume elements), but resume elements
   is small (and will remain small at least until GDB supports thread
   suspension).  */

static void
netbsd_set_resume_request (thread_info *thread, thread_resume *resume, size_t n)
{
  struct lwp_info *lwp = get_thread_lwp (thread);

  for (int ndx = 0; ndx < n; ndx++)
    {
      ptid_t ptid = resume[ndx].thread;
      if (ptid == minus_one_ptid
	  || ptid == thread->id
	  /* Handle both 'pPID' and 'pPID.-1' as meaning 'all threads
	     of PID'.  */
	  || (ptid.pid () == pid_of (thread)
	      && (ptid.is_pid ()
		  || ptid.lwp () == -1)))
	{
	  if (resume[ndx].kind == resume_stop
	      && thread->last_resume_kind == resume_stop)
	    {
	      if (debug_threads)
		debug_printf ("already %s LWP %ld at GDB's request\n",
			      (thread->last_status.kind
			       == TARGET_WAITKIND_STOPPED)
			      ? "stopped"
			      : "stopping",
			      lwpid_of (thread));

	      continue;
	    }

	  /* Ignore (wildcard) resume requests for already-resumed
	     threads.  */
	  if (resume[ndx].kind != resume_stop
	      && thread->last_resume_kind != resume_stop)
	    {
	      if (debug_threads)
		debug_printf ("already %s LWP %ld at GDB's request\n",
			      (thread->last_resume_kind
			       == resume_step)
			      ? "stepping"
			      : "continuing",
			      lwpid_of (thread));
	      continue;
	    }

	  /* Don't let wildcard resumes resume fork children that GDB
	     does not yet know are new fork children.  */
	  if (lwp->fork_relative != NULL)
	    {
	      struct lwp_info *rel = lwp->fork_relative;

	      if (rel->status_pending_p
		  && (rel->waitstatus.kind == TARGET_WAITKIND_FORKED
		      || rel->waitstatus.kind == TARGET_WAITKIND_VFORKED))
		{
		  if (debug_threads)
		    debug_printf ("not resuming LWP %ld: has queued stop reply\n",
				  lwpid_of (thread));
		  continue;
		}
	    }

	  /* If the thread has a pending event that has already been
	     reported to GDBserver core, but GDB has not pulled the
	     event out of the vStopped queue yet, likewise, ignore the
	     (wildcard) resume request.  */
	  if (in_queued_stop_replies (thread->id))
	    {
	      if (debug_threads)
		debug_printf ("not resuming LWP %ld: has queued stop reply\n",
			      lwpid_of (thread));
	      continue;
	    }

	  lwp->resume = &resume[ndx];
	  thread->last_resume_kind = lwp->resume->kind;

	  lwp->step_range_start = lwp->resume->step_range_start;
	  lwp->step_range_end = lwp->resume->step_range_end;

	  /* If we had a deferred signal to report, dequeue one now.
	     This can happen if LWP gets more than one signal while
	     trying to get out of a jump pad.  */
	  if (lwp->stopped
	      && !lwp->status_pending_p
	      && dequeue_one_deferred_signal (lwp, &lwp->status_pending))
	    {
	      lwp->status_pending_p = 1;

	      if (debug_threads)
		debug_printf ("Dequeueing deferred signal %d for LWP %ld, "
			      "leaving status pending.\n",
			      WSTOPSIG (lwp->status_pending),
			      lwpid_of (thread));
	    }

	  return;
	}
    }

  /* No resume action for this thread.  */
  lwp->resume = NULL;
}

/* find_thread callback for netbsd_resume.  Return true if this lwp has an
   interesting status pending.  */

static bool
resume_status_pending_p (thread_info *thread)
{
  struct lwp_info *lwp = get_thread_lwp (thread);

  /* LWPs which will not be resumed are not interesting, because
     we might not wait for them next time through netbsd_wait.  */
  if (lwp->resume == NULL)
    return false;

  return thread_still_has_status_pending_p (thread);
}

/* Return 1 if this lwp that GDB wants running is stopped at an
   internal breakpoint that we need to step over.  It assumes that any
   required STOP_PC adjustment has already been propagated to the
   inferior's regcache.  */

static bool
need_step_over_p (thread_info *thread)
{
  struct lwp_info *lwp = get_thread_lwp (thread);
  struct thread_info *saved_thread;
  CORE_ADDR pc;
  struct process_info *proc = get_thread_process (thread);

  /* GDBserver is skipping the extra traps from the wrapper program,
     don't have to do step over.  */
  if (proc->tdesc == NULL)
    return false;

  /* LWPs which will not be resumed are not interesting, because we
     might not wait for them next time through netbsd_wait.  */

  if (!lwp->stopped)
    {
      if (debug_threads)
	debug_printf ("Need step over [LWP %ld]? Ignoring, not stopped\n",
		      lwpid_of (thread));
      return false;
    }

  if (thread->last_resume_kind == resume_stop)
    {
      if (debug_threads)
	debug_printf ("Need step over [LWP %ld]? Ignoring, should remain"
		      " stopped\n",
		      lwpid_of (thread));
      return false;
    }

  gdb_assert (lwp->suspended >= 0);

  if (lwp->suspended)
    {
      if (debug_threads)
	debug_printf ("Need step over [LWP %ld]? Ignoring, suspended\n",
		      lwpid_of (thread));
      return false;
    }

  if (lwp->status_pending_p)
    {
      if (debug_threads)
	debug_printf ("Need step over [LWP %ld]? Ignoring, has pending"
		      " status.\n",
		      lwpid_of (thread));
      return false;
    }

  /* Note: PC, not STOP_PC.  Either GDB has adjusted the PC already,
     or we have.  */
  pc = get_pc (lwp);

  /* If the PC has changed since we stopped, then don't do anything,
     and let the breakpoint/tracepoint be hit.  This happens if, for
     instance, GDB handled the decr_pc_after_break subtraction itself,
     GDB is OOL stepping this thread, or the user has issued a "jump"
     command, or poked thread's registers herself.  */
  if (pc != lwp->stop_pc)
    {
      if (debug_threads)
	debug_printf ("Need step over [LWP %ld]? Cancelling, PC was changed. "
		      "Old stop_pc was 0x%s, PC is now 0x%s\n",
		      lwpid_of (thread),
		      paddress (lwp->stop_pc), paddress (pc));
      return false;
    }

  /* On software single step target, resume the inferior with signal
     rather than stepping over.  */
  if (can_software_single_step ()
      && lwp->pending_signals != NULL
      && lwp_signal_can_be_delivered (lwp))
    {
      if (debug_threads)
	debug_printf ("Need step over [LWP %ld]? Ignoring, has pending"
		      " signals.\n",
		      lwpid_of (thread));

      return false;
    }

  saved_thread = current_thread;
  current_thread = thread;

  /* We can only step over breakpoints we know about.  */
  if (breakpoint_here (pc) || fast_tracepoint_jump_here (pc))
    {
      /* Don't step over a breakpoint that GDB expects to hit
	 though.  If the condition is being evaluated on the target's side
	 and it evaluate to false, step over this breakpoint as well.  */
      if (gdb_breakpoint_here (pc)
	  && gdb_condition_true_at_breakpoint (pc)
	  && gdb_no_commands_at_breakpoint (pc))
	{
	  if (debug_threads)
	    debug_printf ("Need step over [LWP %ld]? yes, but found"
			  " GDB breakpoint at 0x%s; skipping step over\n",
			  lwpid_of (thread), paddress (pc));

	  current_thread = saved_thread;
	  return false;
	}
      else
	{
	  if (debug_threads)
	    debug_printf ("Need step over [LWP %ld]? yes, "
			  "found breakpoint at 0x%s\n",
			  lwpid_of (thread), paddress (pc));

	  /* We've found an lwp that needs stepping over --- return 1 so
	     that find_thread stops looking.  */
	  current_thread = saved_thread;

	  return true;
	}
    }

  current_thread = saved_thread;

  if (debug_threads)
    debug_printf ("Need step over [LWP %ld]? No, no breakpoint found"
		  " at 0x%s\n",
		  lwpid_of (thread), paddress (pc));

  return false;
}

/* Start a step-over operation on LWP.  When LWP stopped at a
   breakpoint, to make progress, we need to remove the breakpoint out
   of the way.  If we let other threads run while we do that, they may
   pass by the breakpoint location and miss hitting it.  To avoid
   that, a step-over momentarily stops all threads while LWP is
   single-stepped by either hardware or software while the breakpoint
   is temporarily uninserted from the inferior.  When the single-step
   finishes, we reinsert the breakpoint, and let all threads that are
   supposed to be running, run again.  */

static int
start_step_over (struct lwp_info *lwp)
{
  struct thread_info *thread = get_lwp_thread (lwp);
  struct thread_info *saved_thread;
  CORE_ADDR pc;
  int step;

  if (debug_threads)
    debug_printf ("Starting step-over on LWP %ld.  Stopping all threads\n",
		  lwpid_of (thread));

  stop_all_lwps (1, lwp);

  if (lwp->suspended != 0)
    {
      internal_error (__FILE__, __LINE__,
		      "LWP %ld suspended=%d\n", lwpid_of (thread),
		      lwp->suspended);
    }

  if (debug_threads)
    debug_printf ("Done stopping all threads for step-over.\n");

  /* Note, we should always reach here with an already adjusted PC,
     either by GDB (if we're resuming due to GDB's request), or by our
     caller, if we just finished handling an internal breakpoint GDB
     shouldn't care about.  */
  pc = get_pc (lwp);

  saved_thread = current_thread;
  current_thread = thread;

  lwp->bp_reinsert = pc;
  uninsert_breakpoints_at (pc);
  uninsert_fast_tracepoint_jumps_at (pc);

  step = single_step (lwp);

  current_thread = saved_thread;

  netbsd_resume_one_lwp (lwp, step, 0, NULL);

  /* Require next event from this LWP.  */
  step_over_bkpt = thread->id;
  return 1;
}

/* Finish a step-over.  Reinsert the breakpoint we had uninserted in
   start_step_over, if still there, and delete any single-step
   breakpoints we've set, on non hardware single-step targets.  */

static int
finish_step_over (struct lwp_info *lwp)
{
  if (lwp->bp_reinsert != 0)
    {
      struct thread_info *saved_thread = current_thread;

      if (debug_threads)
	debug_printf ("Finished step over.\n");

      current_thread = get_lwp_thread (lwp);

      /* Reinsert any breakpoint at LWP->BP_REINSERT.  Note that there
	 may be no breakpoint to reinsert there by now.  */
      reinsert_breakpoints_at (lwp->bp_reinsert);
      reinsert_fast_tracepoint_jumps_at (lwp->bp_reinsert);

      lwp->bp_reinsert = 0;

      /* Delete any single-step breakpoints.  No longer needed.  We
	 don't have to worry about other threads hitting this trap,
	 and later not being able to explain it, because we were
	 stepping over a breakpoint, and we hold all threads but
	 LWP stopped while doing that.  */
      if (!can_hardware_single_step ())
	{
	  gdb_assert (has_single_step_breakpoints (current_thread));
	  delete_single_step_breakpoints (current_thread);
	}

      step_over_bkpt = null_ptid;
      current_thread = saved_thread;
      return 1;
    }
  else
    return 0;
}

/* If there's a step over in progress, wait until all threads stop
   (that is, until the stepping thread finishes its step), and
   unsuspend all lwps.  The stepping thread ends with its status
   pending, which is processed later when we get back to processing
   events.  */

static void
complete_ongoing_step_over (void)
{
  if (step_over_bkpt != null_ptid)
    {
      struct lwp_info *lwp;
      int wstat;
      int ret;

      if (debug_threads)
	debug_printf ("detach: step over in progress, finish it first\n");

      /* Passing NULL_PTID as filter indicates we want all events to
	 be left pending.  Eventually this returns when there are no
	 unwaited-for children left.  */
      ret = netbsd_wait_for_event_filtered (minus_one_ptid, null_ptid,
					   &wstat, __WALL);
      gdb_assert (ret == -1);

      lwp = find_lwp_pid (step_over_bkpt);
      if (lwp != NULL)
	finish_step_over (lwp);
      step_over_bkpt = null_ptid;
      unsuspend_all_lwps (lwp);
    }
}

/* This function is called once per thread.  We check the thread's resume
   request, which will tell us whether to resume, step, or leave the thread
   stopped; and what signal, if any, it should be sent.

   For threads which we aren't explicitly told otherwise, we preserve
   the stepping flag; this is used for stepping over gdbserver-placed
   breakpoints.

   If pending_flags was set in any thread, we queue any needed
   signals, since we won't actually resume.  We already have a pending
   event to report, so we don't need to preserve any step requests;
   they should be re-issued if necessary.  */

static void
netbsd_resume_one_thread (thread_info *thread, bool leave_all_stopped)
{
  struct lwp_info *lwp = get_thread_lwp (thread);
  int leave_pending;

  if (lwp->resume == NULL)
    return;

  if (lwp->resume->kind == resume_stop)
    {
      if (debug_threads)
	debug_printf ("resume_stop request for LWP %ld\n", lwpid_of (thread));

      if (!lwp->stopped)
	{
	  if (debug_threads)
	    debug_printf ("stopping LWP %ld\n", lwpid_of (thread));

	  /* Stop the thread, and wait for the event asynchronously,
	     through the event loop.  */
	  send_sigstop (lwp);
	}
      else
	{
	  if (debug_threads)
	    debug_printf ("already stopped LWP %ld\n",
			  lwpid_of (thread));

	  /* The LWP may have been stopped in an internal event that
	     was not meant to be notified back to GDB (e.g., gdbserver
	     breakpoint), so we should be reporting a stop event in
	     this case too.  */

	  /* If the thread already has a pending SIGSTOP, this is a
	     no-op.  Otherwise, something later will presumably resume
	     the thread and this will cause it to cancel any pending
	     operation, due to last_resume_kind == resume_stop.  If
	     the thread already has a pending status to report, we
	     will still report it the next time we wait - see
	     status_pending_p_callback.  */

	  /* If we already have a pending signal to report, then
	     there's no need to queue a SIGSTOP, as this means we're
	     midway through moving the LWP out of the jumppad, and we
	     will report the pending signal as soon as that is
	     finished.  */
	  if (lwp->pending_signals_to_report == NULL)
	    send_sigstop (lwp);
	}

      /* For stop requests, we're done.  */
      lwp->resume = NULL;
      thread->last_status.kind = TARGET_WAITKIND_IGNORE;
      return;
    }

  /* If this thread which is about to be resumed has a pending status,
     then don't resume it - we can just report the pending status.
     Likewise if it is suspended, because e.g., another thread is
     stepping past a breakpoint.  Make sure to queue any signals that
     would otherwise be sent.  In all-stop mode, we do this decision
     based on if *any* thread has a pending status.  If there's a
     thread that needs the step-over-breakpoint dance, then don't
     resume any other thread but that particular one.  */
  leave_pending = (lwp->suspended
		   || lwp->status_pending_p
		   || leave_all_stopped);

  /* If we have a new signal, enqueue the signal.  */
  if (lwp->resume->sig != 0)
    {
      siginfo_t info, *info_p;

      /* If this is the same signal we were previously stopped by,
	 make sure to queue its siginfo.  */
      if (WIFSTOPPED (lwp->last_status)
	  && WSTOPSIG (lwp->last_status) == lwp->resume->sig
	  && ptrace (PTRACE_GETSIGINFO, lwpid_of (thread),
		     (PTRACE_TYPE_ARG3) 0, &info) == 0)
	info_p = &info;
      else
	info_p = NULL;

      enqueue_pending_signal (lwp, lwp->resume->sig, info_p);
    }

  if (!leave_pending)
    {
      if (debug_threads)
	debug_printf ("resuming LWP %ld\n", lwpid_of (thread));

      proceed_one_lwp (thread, NULL);
    }
  else
    {
      if (debug_threads)
	debug_printf ("leaving LWP %ld stopped\n", lwpid_of (thread));
    }

  thread->last_status.kind = TARGET_WAITKIND_IGNORE;
  lwp->resume = NULL;
}

static void
netbsd_resume (struct thread_resume *resume_info, size_t n)
{
  struct thread_info *need_step_over = NULL;

  if (debug_threads)
    {
      debug_enter ();
      debug_printf ("netbsd_resume:\n");
    }

  for_each_thread ([&] (thread_info *thread)
    {
      netbsd_set_resume_request (thread, resume_info, n);
    });

  /* If there is a thread which would otherwise be resumed, which has
     a pending status, then don't resume any threads - we can just
     report the pending status.  Make sure to queue any signals that
     would otherwise be sent.  In non-stop mode, we'll apply this
     logic to each thread individually.  We consume all pending events
     before considering to start a step-over (in all-stop).  */
  bool any_pending = false;
  if (!non_stop)
    any_pending = find_thread (resume_status_pending_p) != NULL;

  /* If there is a thread which would otherwise be resumed, which is
     stopped at a breakpoint that needs stepping over, then don't
     resume any threads - have it step over the breakpoint with all
     other threads stopped, then resume all threads again.  Make sure
     to queue any signals that would otherwise be delivered or
     queued.  */
  if (!any_pending && supports_breakpoints ())
    need_step_over = find_thread (need_step_over_p);

  bool leave_all_stopped = (need_step_over != NULL || any_pending);

  if (debug_threads)
    {
      if (need_step_over != NULL)
	debug_printf ("Not resuming all, need step over\n");
      else if (any_pending)
	debug_printf ("Not resuming, all-stop and found "
		      "an LWP with pending status\n");
      else
	debug_printf ("Resuming, no pending status or step over needed\n");
    }

  /* Even if we're leaving threads stopped, queue all signals we'd
     otherwise deliver.  */
  for_each_thread ([&] (thread_info *thread)
    {
      netbsd_resume_one_thread (thread, leave_all_stopped);
    });

  if (need_step_over)
    start_step_over (get_thread_lwp (need_step_over));

  if (debug_threads)
    {
      debug_printf ("netbsd_resume done\n");
      debug_exit ();
    }

  /* We may have events that were pending that can/should be sent to
     the client now.  Trigger a netbsd_wait call.  */
  if (target_is_async_p ())
    async_file_mark ();
}

/* This function is called once per thread.  We check the thread's
   last resume request, which will tell us whether to resume, step, or
   leave the thread stopped.  Any signal the client requested to be
   delivered has already been enqueued at this point.

   If any thread that GDB wants running is stopped at an internal
   breakpoint that needs stepping over, we start a step-over operation
   on that particular thread, and leave all others stopped.  */

static void
proceed_one_lwp (thread_info *thread, lwp_info *except)
{
  struct lwp_info *lwp = get_thread_lwp (thread);
  int step;

  if (lwp == except)
    return;

  if (debug_threads)
    debug_printf ("proceed_one_lwp: lwp %ld\n", lwpid_of (thread));

  if (!lwp->stopped)
    {
      if (debug_threads)
	debug_printf ("   LWP %ld already running\n", lwpid_of (thread));
      return;
    }

  if (thread->last_resume_kind == resume_stop
      && thread->last_status.kind != TARGET_WAITKIND_IGNORE)
    {
      if (debug_threads)
	debug_printf ("   client wants LWP to remain %ld stopped\n",
		      lwpid_of (thread));
      return;
    }

  if (lwp->status_pending_p)
    {
      if (debug_threads)
	debug_printf ("   LWP %ld has pending status, leaving stopped\n",
		      lwpid_of (thread));
      return;
    }

  gdb_assert (lwp->suspended >= 0);

  if (lwp->suspended)
    {
      if (debug_threads)
	debug_printf ("   LWP %ld is suspended\n", lwpid_of (thread));
      return;
    }

  if (thread->last_resume_kind == resume_stop
      && lwp->pending_signals_to_report == NULL
      && (lwp->collecting_fast_tracepoint
	  == fast_tpoint_collect_result::not_collecting))
    {
      /* We haven't reported this LWP as stopped yet (otherwise, the
	 last_status.kind check above would catch it, and we wouldn't
	 reach here.  This LWP may have been momentarily paused by a
	 stop_all_lwps call while handling for example, another LWP's
	 step-over.  In that case, the pending expected SIGSTOP signal
	 that was queued at vCont;t handling time will have already
	 been consumed by wait_for_sigstop, and so we need to requeue
	 another one here.  Note that if the LWP already has a SIGSTOP
	 pending, this is a no-op.  */

      if (debug_threads)
	debug_printf ("Client wants LWP %ld to stop. "
		      "Making sure it has a SIGSTOP pending\n",
		      lwpid_of (thread));

      send_sigstop (lwp);
    }

  if (thread->last_resume_kind == resume_step)
    {
      if (debug_threads)
	debug_printf ("   stepping LWP %ld, client wants it stepping\n",
		      lwpid_of (thread));

      /* If resume_step is requested by GDB, install single-step
	 breakpoints when the thread is about to be actually resumed if
	 the single-step breakpoints weren't removed.  */
      if (can_software_single_step ()
	  && !has_single_step_breakpoints (thread))
	install_software_single_step_breakpoints (lwp);

      step = maybe_hw_step (thread);
    }
  else if (lwp->bp_reinsert != 0)
    {
      if (debug_threads)
	debug_printf ("   stepping LWP %ld, reinsert set\n",
		      lwpid_of (thread));

      step = maybe_hw_step (thread);
    }
  else
    step = 0;

  netbsd_resume_one_lwp (lwp, step, 0, NULL);
}

static void
unsuspend_and_proceed_one_lwp (thread_info *thread, lwp_info *except)
{
  struct lwp_info *lwp = get_thread_lwp (thread);

  if (lwp == except)
    return;

  lwp_suspended_decr (lwp);

  proceed_one_lwp (thread, except);
}

/* When we finish a step-over, set threads running again.  If there's
   another thread that may need a step-over, now's the time to start
   it.  Eventually, we'll move all threads past their breakpoints.  */

static void
proceed_all_lwps (void)
{
  struct thread_info *need_step_over;

  /* If there is a thread which would otherwise be resumed, which is
     stopped at a breakpoint that needs stepping over, then don't
     resume any threads - have it step over the breakpoint with all
     other threads stopped, then resume all threads again.  */

  if (supports_breakpoints ())
    {
      need_step_over = find_thread (need_step_over_p);

      if (need_step_over != NULL)
	{
	  if (debug_threads)
	    debug_printf ("proceed_all_lwps: found "
			  "thread %ld needing a step-over\n",
			  lwpid_of (need_step_over));

	  start_step_over (get_thread_lwp (need_step_over));
	  return;
	}
    }

  if (debug_threads)
    debug_printf ("Proceeding, no step-over needed\n");

  for_each_thread ([] (thread_info *thread)
    {
      proceed_one_lwp (thread, NULL);
    });
}

/* Stopped LWPs that the client wanted to be running, that don't have
   pending statuses, are set to run again, except for EXCEPT, if not
   NULL.  This undoes a stop_all_lwps call.  */

static void
unstop_all_lwps (int unsuspend, struct lwp_info *except)
{
  if (debug_threads)
    {
      debug_enter ();
      if (except)
	debug_printf ("unstopping all lwps, except=(LWP %ld)\n",
		      lwpid_of (get_lwp_thread (except)));
      else
	debug_printf ("unstopping all lwps\n");
    }

  if (unsuspend)
    for_each_thread ([&] (thread_info *thread)
      {
	unsuspend_and_proceed_one_lwp (thread, except);
      });
  else
    for_each_thread ([&] (thread_info *thread)
      {
	proceed_one_lwp (thread, except);
      });

  if (debug_threads)
    {
      debug_printf ("unstop_all_lwps done\n");
      debug_exit ();
    }
}


#ifdef HAVE_NETBSD_REGSETS

#define use_netbsd_regsets 1

/* Returns true if REGSET has been disabled.  */

static int
regset_disabled (struct regsets_info *info, struct regset_info *regset)
{
  return (info->disabled_regsets != NULL
	  && info->disabled_regsets[regset - info->regsets]);
}

/* Disable REGSET.  */

static void
disable_regset (struct regsets_info *info, struct regset_info *regset)
{
  int dr_offset;

  dr_offset = regset - info->regsets;
  if (info->disabled_regsets == NULL)
    info->disabled_regsets = (char *) xcalloc (1, info->num_regsets);
  info->disabled_regsets[dr_offset] = 1;
}

static int
regsets_fetch_inferior_registers (struct regsets_info *regsets_info,
				  struct regcache *regcache)
{
  struct regset_info *regset;
  int saw_general_regs = 0;
  int pid;
  struct iovec iov;

  pid = lwpid_of (current_thread);
  for (regset = regsets_info->regsets; regset->size >= 0; regset++)
    {
      void *buf, *data;
      int nt_type, res;

      if (regset->size == 0 || regset_disabled (regsets_info, regset))
	continue;

      buf = xmalloc (regset->size);

      nt_type = regset->nt_type;
      if (nt_type)
	{
	  iov.iov_base = buf;
	  iov.iov_len = regset->size;
	  data = (void *) &iov;
	}
      else
	data = buf;

#ifndef __sparc__
      res = ptrace (regset->get_request, pid,
		    (PTRACE_TYPE_ARG3) (long) nt_type, data);
#else
      res = ptrace (regset->get_request, pid, data, nt_type);
#endif
      if (res < 0)
	{
	  if (errno == EIO
	      || (errno == EINVAL && regset->type == OPTIONAL_REGS))
	    {
	      /* If we get EIO on a regset, or an EINVAL and the regset is
		 optional, do not try it again for this process mode.  */
	      disable_regset (regsets_info, regset);
	    }
	  else if (errno == ENODATA)
	    {
	      /* ENODATA may be returned if the regset is currently
		 not "active".  This can happen in normal operation,
		 so suppress the warning in this case.  */
	    }
	  else if (errno == ESRCH)
	    {
	      /* At this point, ESRCH should mean the process is
		 already gone, in which case we simply ignore attempts
		 to read its registers.  */
	    }
	  else
	    {
	      char s[256];
	      sprintf (s, "ptrace(regsets_fetch_inferior_registers) PID=%d",
		       pid);
	      perror (s);
	    }
	}
      else
	{
	  if (regset->type == GENERAL_REGS)
	    saw_general_regs = 1;
	  regset->store_function (regcache, buf);
	}
      free (buf);
    }
  if (saw_general_regs)
    return 0;
  else
    return 1;
}

static int
regsets_store_inferior_registers (struct regsets_info *regsets_info,
				  struct regcache *regcache)
{
  struct regset_info *regset;
  int saw_general_regs = 0;
  int pid;
  struct iovec iov;

  pid = lwpid_of (current_thread);
  for (regset = regsets_info->regsets; regset->size >= 0; regset++)
    {
      void *buf, *data;
      int nt_type, res;

      if (regset->size == 0 || regset_disabled (regsets_info, regset)
	  || regset->fill_function == NULL)
	continue;

      buf = xmalloc (regset->size);

      /* First fill the buffer with the current register set contents,
	 in case there are any items in the kernel's regset that are
	 not in gdbserver's regcache.  */

      nt_type = regset->nt_type;
      if (nt_type)
	{
	  iov.iov_base = buf;
	  iov.iov_len = regset->size;
	  data = (void *) &iov;
	}
      else
	data = buf;

#ifndef __sparc__
      res = ptrace (regset->get_request, pid,
		    (PTRACE_TYPE_ARG3) (long) nt_type, data);
#else
      res = ptrace (regset->get_request, pid, data, nt_type);
#endif

      if (res == 0)
	{
	  /* Then overlay our cached registers on that.  */
	  regset->fill_function (regcache, buf);

	  /* Only now do we write the register set.  */
#ifndef __sparc__
	  res = ptrace (regset->set_request, pid,
			(PTRACE_TYPE_ARG3) (long) nt_type, data);
#else
	  res = ptrace (regset->set_request, pid, data, nt_type);
#endif
	}

      if (res < 0)
	{
	  if (errno == EIO
	      || (errno == EINVAL && regset->type == OPTIONAL_REGS))
	    {
	      /* If we get EIO on a regset, or an EINVAL and the regset is
		 optional, do not try it again for this process mode.  */
	      disable_regset (regsets_info, regset);
	    }
	  else if (errno == ESRCH)
	    {
	      /* At this point, ESRCH should mean the process is
		 already gone, in which case we simply ignore attempts
		 to change its registers.  See also the related
		 comment in netbsd_resume_one_lwp.  */
	      free (buf);
	      return 0;
	    }
	  else
	    {
	      perror ("Warning: ptrace(regsets_store_inferior_registers)");
	    }
	}
      else if (regset->type == GENERAL_REGS)
	saw_general_regs = 1;
      free (buf);
    }
  if (saw_general_regs)
    return 0;
  else
    return 1;
}

#else /* !HAVE_NETBSD_REGSETS */

#define use_netbsd_regsets 0
#define regsets_fetch_inferior_registers(regsets_info, regcache) 1
#define regsets_store_inferior_registers(regsets_info, regcache) 1

#endif

/* Return 1 if register REGNO is supported by one of the regset ptrace
   calls or 0 if it has to be transferred individually.  */

static int
netbsd_register_in_regsets (const struct regs_info *regs_info, int regno)
{
  unsigned char mask = 1 << (regno % 8);
  size_t index = regno / 8;

  return (use_netbsd_regsets
	  && (regs_info->regset_bitmap == NULL
	      || (regs_info->regset_bitmap[index] & mask) != 0));
}

#ifdef HAVE_NETBSD_USRREGS

static int
register_addr (const struct usrregs_info *usrregs, int regnum)
{
  int addr;

  if (regnum < 0 || regnum >= usrregs->num_regs)
    error ("Invalid register number %d.", regnum);

  addr = usrregs->regmap[regnum];

  return addr;
}

/* Fetch one register.  */
static void
fetch_register (const struct usrregs_info *usrregs,
		struct regcache *regcache, int regno)
{
  CORE_ADDR regaddr;
  int i, size;
  char *buf;
  int pid;

  if (regno >= usrregs->num_regs)
    return;
  if ((*the_low_target.cannot_fetch_register) (regno))
    return;

  regaddr = register_addr (usrregs, regno);
  if (regaddr == -1)
    return;

  size = ((register_size (regcache->tdesc, regno)
	   + sizeof (PTRACE_XFER_TYPE) - 1)
	  & -sizeof (PTRACE_XFER_TYPE));
  buf = (char *) alloca (size);

  pid = lwpid_of (current_thread);
  for (i = 0; i < size; i += sizeof (PTRACE_XFER_TYPE))
    {
      errno = 0;
      *(PTRACE_XFER_TYPE *) (buf + i) =
	ptrace (PTRACE_PEEKUSER, pid,
		/* Coerce to a uintptr_t first to avoid potential gcc warning
		   of coercing an 8 byte integer to a 4 byte pointer.  */
		(PTRACE_TYPE_ARG3) (uintptr_t) regaddr, (PTRACE_TYPE_ARG4) 0);
      regaddr += sizeof (PTRACE_XFER_TYPE);
      if (errno != 0)
	{
	  /* Mark register REGNO unavailable.  */
	  supply_register (regcache, regno, NULL);
	  return;
	}
    }

  if (the_low_target.supply_ptrace_register)
    the_low_target.supply_ptrace_register (regcache, regno, buf);
  else
    supply_register (regcache, regno, buf);
}

/* Store one register.  */
static void
store_register (const struct usrregs_info *usrregs,
		struct regcache *regcache, int regno)
{
  CORE_ADDR regaddr;
  int i, size;
  char *buf;
  int pid;

  if (regno >= usrregs->num_regs)
    return;
  if ((*the_low_target.cannot_store_register) (regno))
    return;

  regaddr = register_addr (usrregs, regno);
  if (regaddr == -1)
    return;

  size = ((register_size (regcache->tdesc, regno)
	   + sizeof (PTRACE_XFER_TYPE) - 1)
	  & -sizeof (PTRACE_XFER_TYPE));
  buf = (char *) alloca (size);
  memset (buf, 0, size);

  if (the_low_target.collect_ptrace_register)
    the_low_target.collect_ptrace_register (regcache, regno, buf);
  else
    collect_register (regcache, regno, buf);

  pid = lwpid_of (current_thread);
  for (i = 0; i < size; i += sizeof (PTRACE_XFER_TYPE))
    {
      errno = 0;
      ptrace (PTRACE_POKEUSER, pid,
	    /* Coerce to a uintptr_t first to avoid potential gcc warning
	       about coercing an 8 byte integer to a 4 byte pointer.  */
	      (PTRACE_TYPE_ARG3) (uintptr_t) regaddr,
	      (PTRACE_TYPE_ARG4) *(PTRACE_XFER_TYPE *) (buf + i));
      if (errno != 0)
	{
	  /* At this point, ESRCH should mean the process is
	     already gone, in which case we simply ignore attempts
	     to change its registers.  See also the related
	     comment in netbsd_resume_one_lwp.  */
	  if (errno == ESRCH)
	    return;

	  if ((*the_low_target.cannot_store_register) (regno) == 0)
	    error ("writing register %d: %s", regno, strerror (errno));
	}
      regaddr += sizeof (PTRACE_XFER_TYPE);
    }
}

/* Fetch all registers, or just one, from the child process.
   If REGNO is -1, do this for all registers, skipping any that are
   assumed to have been retrieved by regsets_fetch_inferior_registers,
   unless ALL is non-zero.
   Otherwise, REGNO specifies which register (so we can save time).  */
static void
usr_fetch_inferior_registers (const struct regs_info *regs_info,
			      struct regcache *regcache, int regno, int all)
{
  struct usrregs_info *usr = regs_info->usrregs;

  if (regno == -1)
    {
      for (regno = 0; regno < usr->num_regs; regno++)
	if (all || !netbsd_register_in_regsets (regs_info, regno))
	  fetch_register (usr, regcache, regno);
    }
  else
    fetch_register (usr, regcache, regno);
}

/* Store our register values back into the inferior.
   If REGNO is -1, do this for all registers, skipping any that are
   assumed to have been saved by regsets_store_inferior_registers,
   unless ALL is non-zero.
   Otherwise, REGNO specifies which register (so we can save time).  */
static void
usr_store_inferior_registers (const struct regs_info *regs_info,
			      struct regcache *regcache, int regno, int all)
{
  struct usrregs_info *usr = regs_info->usrregs;

  if (regno == -1)
    {
      for (regno = 0; regno < usr->num_regs; regno++)
	if (all || !netbsd_register_in_regsets (regs_info, regno))
	  store_register (usr, regcache, regno);
    }
  else
    store_register (usr, regcache, regno);
}

#else /* !HAVE_NETBSD_USRREGS */

#define usr_fetch_inferior_registers(regs_info, regcache, regno, all) do {} while (0)
#define usr_store_inferior_registers(regs_info, regcache, regno, all) do {} while (0)

#endif


static void
netbsd_fetch_registers (struct regcache *regcache, int regno)
{
  int use_regsets;
  int all = 0;
  const struct regs_info *regs_info = (*the_low_target.regs_info) ();

  if (regno == -1)
    {
      if (the_low_target.fetch_register != NULL
	  && regs_info->usrregs != NULL)
	for (regno = 0; regno < regs_info->usrregs->num_regs; regno++)
	  (*the_low_target.fetch_register) (regcache, regno);

      all = regsets_fetch_inferior_registers (regs_info->regsets_info, regcache);
      if (regs_info->usrregs != NULL)
	usr_fetch_inferior_registers (regs_info, regcache, -1, all);
    }
  else
    {
      if (the_low_target.fetch_register != NULL
	  && (*the_low_target.fetch_register) (regcache, regno))
	return;

      use_regsets = netbsd_register_in_regsets (regs_info, regno);
      if (use_regsets)
	all = regsets_fetch_inferior_registers (regs_info->regsets_info,
						regcache);
      if ((!use_regsets || all) && regs_info->usrregs != NULL)
	usr_fetch_inferior_registers (regs_info, regcache, regno, 1);
    }
}

static void
netbsd_store_registers (struct regcache *regcache, int regno)
{
  int use_regsets;
  int all = 0;
  const struct regs_info *regs_info = (*the_low_target.regs_info) ();

  if (regno == -1)
    {
      all = regsets_store_inferior_registers (regs_info->regsets_info,
					      regcache);
      if (regs_info->usrregs != NULL)
	usr_store_inferior_registers (regs_info, regcache, regno, all);
    }
  else
    {
      use_regsets = netbsd_register_in_regsets (regs_info, regno);
      if (use_regsets)
	all = regsets_store_inferior_registers (regs_info->regsets_info,
						regcache);
      if ((!use_regsets || all) && regs_info->usrregs != NULL)
	usr_store_inferior_registers (regs_info, regcache, regno, 1);
    }
}


/* Copy LEN bytes from inferior's memory starting at MEMADDR
   to debugger memory starting at MYADDR.  */

static int
netbsd_read_memory (CORE_ADDR memaddr, unsigned char *myaddr, int len)
{
  int pid = lwpid_of (current_thread);
  PTRACE_XFER_TYPE *buffer;
  CORE_ADDR addr;
  int count;
  char filename[64];
  int i;
  int ret;
  int fd;

  /* Try using /proc.  Don't bother for one word.  */
  if (len >= 3 * sizeof (long))
    {
      int bytes;

      /* We could keep this file open and cache it - possibly one per
	 thread.  That requires some juggling, but is even faster.  */
      sprintf (filename, "/proc/%d/mem", pid);
      fd = open (filename, O_RDONLY | O_LARGEFILE);
      if (fd == -1)
	goto no_proc;

      /* If pread64 is available, use it.  It's faster if the kernel
	 supports it (only one syscall), and it's 64-bit safe even on
	 32-bit platforms (for instance, SPARC debugging a SPARC64
	 application).  */
#ifdef HAVE_PREAD64
      bytes = pread64 (fd, myaddr, len, memaddr);
#else
      bytes = -1;
      if (lseek (fd, memaddr, SEEK_SET) != -1)
	bytes = read (fd, myaddr, len);
#endif

      close (fd);
      if (bytes == len)
	return 0;

      /* Some data was read, we'll try to get the rest with ptrace.  */
      if (bytes > 0)
	{
	  memaddr += bytes;
	  myaddr += bytes;
	  len -= bytes;
	}
    }

 no_proc:
  /* Round starting address down to longword boundary.  */
  addr = memaddr & -(CORE_ADDR) sizeof (PTRACE_XFER_TYPE);
  /* Round ending address up; get number of longwords that makes.  */
  count = ((((memaddr + len) - addr) + sizeof (PTRACE_XFER_TYPE) - 1)
	   / sizeof (PTRACE_XFER_TYPE));
  /* Allocate buffer of that many longwords.  */
  buffer = XALLOCAVEC (PTRACE_XFER_TYPE, count);

  /* Read all the longwords */
  errno = 0;
  for (i = 0; i < count; i++, addr += sizeof (PTRACE_XFER_TYPE))
    {
      /* Coerce the 3rd arg to a uintptr_t first to avoid potential gcc warning
	 about coercing an 8 byte integer to a 4 byte pointer.  */
      buffer[i] = ptrace (PTRACE_PEEKTEXT, pid,
			  (PTRACE_TYPE_ARG3) (uintptr_t) addr,
			  (PTRACE_TYPE_ARG4) 0);
      if (errno)
	break;
    }
  ret = errno;

  /* Copy appropriate bytes out of the buffer.  */
  if (i > 0)
    {
      i *= sizeof (PTRACE_XFER_TYPE);
      i -= memaddr & (sizeof (PTRACE_XFER_TYPE) - 1);
      memcpy (myaddr,
	      (char *) buffer + (memaddr & (sizeof (PTRACE_XFER_TYPE) - 1)),
	      i < len ? i : len);
    }

  return ret;
}

/* Copy LEN bytes of data from debugger memory at MYADDR to inferior's
   memory at MEMADDR.  On failure (cannot write to the inferior)
   returns the value of errno.  Always succeeds if LEN is zero.  */

static int
netbsd_write_memory (CORE_ADDR memaddr, const unsigned char *myaddr, int len)
{
  int i;
  /* Round starting address down to longword boundary.  */
  CORE_ADDR addr = memaddr & -(CORE_ADDR) sizeof (PTRACE_XFER_TYPE);
  /* Round ending address up; get number of longwords that makes.  */
  int count
    = (((memaddr + len) - addr) + sizeof (PTRACE_XFER_TYPE) - 1)
    / sizeof (PTRACE_XFER_TYPE);

  /* Allocate buffer of that many longwords.  */
  PTRACE_XFER_TYPE *buffer = XALLOCAVEC (PTRACE_XFER_TYPE, count);

  int pid = lwpid_of (current_thread);

  if (len == 0)
    {
      /* Zero length write always succeeds.  */
      return 0;
    }

  if (debug_threads)
    {
      /* Dump up to four bytes.  */
      char str[4 * 2 + 1];
      char *p = str;
      int dump = len < 4 ? len : 4;

      for (i = 0; i < dump; i++)
	{
	  sprintf (p, "%02x", myaddr[i]);
	  p += 2;
	}
      *p = '\0';

      debug_printf ("Writing %s to 0x%08lx in process %d\n",
		    str, (long) memaddr, pid);
    }

  /* Fill start and end extra bytes of buffer with existing memory data.  */

  errno = 0;
  /* Coerce the 3rd arg to a uintptr_t first to avoid potential gcc warning
     about coercing an 8 byte integer to a 4 byte pointer.  */
  buffer[0] = ptrace (PTRACE_PEEKTEXT, pid,
		      (PTRACE_TYPE_ARG3) (uintptr_t) addr,
		      (PTRACE_TYPE_ARG4) 0);
  if (errno)
    return errno;

  if (count > 1)
    {
      errno = 0;
      buffer[count - 1]
	= ptrace (PTRACE_PEEKTEXT, pid,
		  /* Coerce to a uintptr_t first to avoid potential gcc warning
		     about coercing an 8 byte integer to a 4 byte pointer.  */
		  (PTRACE_TYPE_ARG3) (uintptr_t) (addr + (count - 1)
						  * sizeof (PTRACE_XFER_TYPE)),
		  (PTRACE_TYPE_ARG4) 0);
      if (errno)
	return errno;
    }

  /* Copy data to be written over corresponding part of buffer.  */

  memcpy ((char *) buffer + (memaddr & (sizeof (PTRACE_XFER_TYPE) - 1)),
	  myaddr, len);

  /* Write the entire buffer.  */

  for (i = 0; i < count; i++, addr += sizeof (PTRACE_XFER_TYPE))
    {
      errno = 0;
      ptrace (PTRACE_POKETEXT, pid,
	      /* Coerce to a uintptr_t first to avoid potential gcc warning
		 about coercing an 8 byte integer to a 4 byte pointer.  */
	      (PTRACE_TYPE_ARG3) (uintptr_t) addr,
	      (PTRACE_TYPE_ARG4) buffer[i]);
      if (errno)
	return errno;
    }

  return 0;
}

static void
netbsd_look_up_symbols (void)
{
#ifdef USE_THREAD_DB
  struct process_info *proc = current_process ();

  if (proc->priv->thread_db != NULL)
    return;

  thread_db_init ();
#endif
}

static void
netbsd_request_interrupt (void)
{
  /* Send a SIGINT to the process group.  This acts just like the user
     typed a ^C on the controlling terminal.  */
  kill (-signal_pid, SIGINT);
}

/* Copy LEN bytes from inferior's auxiliary vector starting at OFFSET
   to debugger memory starting at MYADDR.  */

static int
netbsd_read_auxv (CORE_ADDR offset, unsigned char *myaddr, unsigned int len)
{
  char filename[PATH_MAX];
  int fd, n;
  int pid = lwpid_of (current_thread);

  xsnprintf (filename, sizeof filename, "/proc/%d/auxv", pid);

  fd = open (filename, O_RDONLY);
  if (fd < 0)
    return -1;

  if (offset != (CORE_ADDR) 0
      && lseek (fd, (off_t) offset, SEEK_SET) != (off_t) offset)
    n = -1;
  else
    n = read (fd, myaddr, len);

  close (fd);

  return n;
}

/* These breakpoint and watchpoint related wrapper functions simply
   pass on the function call if the target has registered a
   corresponding function.  */

static int
netbsd_supports_z_point_type (char z_type)
{
  return (the_low_target.supports_z_point_type != NULL
	  && the_low_target.supports_z_point_type (z_type));
}

static int
netbsd_insert_point (enum raw_bkpt_type type, CORE_ADDR addr,
		    int size, struct raw_breakpoint *bp)
{
  if (type == raw_bkpt_type_sw)
    return insert_memory_breakpoint (bp);
  else if (the_low_target.insert_point != NULL)
    return the_low_target.insert_point (type, addr, size, bp);
  else
    /* Unsupported (see target.h).  */
    return 1;
}

static int
netbsd_remove_point (enum raw_bkpt_type type, CORE_ADDR addr,
		    int size, struct raw_breakpoint *bp)
{
  if (type == raw_bkpt_type_sw)
    return remove_memory_breakpoint (bp);
  else if (the_low_target.remove_point != NULL)
    return the_low_target.remove_point (type, addr, size, bp);
  else
    /* Unsupported (see target.h).  */
    return 1;
}

/* Implement the to_stopped_by_sw_breakpoint target_ops
   method.  */

static int
netbsd_stopped_by_sw_breakpoint (void)
{
  struct lwp_info *lwp = get_thread_lwp (current_thread);

  return (lwp->stop_reason == TARGET_STOPPED_BY_SW_BREAKPOINT);
}

/* Implement the to_supports_stopped_by_sw_breakpoint target_ops
   method.  */

static int
netbsd_supports_stopped_by_sw_breakpoint (void)
{
  return USE_SIGTRAP_SIGINFO;
}

/* Implement the to_stopped_by_hw_breakpoint target_ops
   method.  */

static int
netbsd_stopped_by_hw_breakpoint (void)
{
  struct lwp_info *lwp = get_thread_lwp (current_thread);

  return (lwp->stop_reason == TARGET_STOPPED_BY_HW_BREAKPOINT);
}

/* Implement the to_supports_stopped_by_hw_breakpoint target_ops
   method.  */

static int
netbsd_supports_stopped_by_hw_breakpoint (void)
{
  return USE_SIGTRAP_SIGINFO;
}

/* Implement the supports_hardware_single_step target_ops method.  */

static int
netbsd_supports_hardware_single_step (void)
{
  return can_hardware_single_step ();
}

static int
netbsd_supports_software_single_step (void)
{
  return can_software_single_step ();
}

static int
netbsd_stopped_by_watchpoint (void)
{
  struct lwp_info *lwp = get_thread_lwp (current_thread);

  return lwp->stop_reason == TARGET_STOPPED_BY_WATCHPOINT;
}

static CORE_ADDR
netbsd_stopped_data_address (void)
{
  struct lwp_info *lwp = get_thread_lwp (current_thread);

  return lwp->stopped_data_address;
}

#if defined(__UCLIBC__) && defined(HAS_NOMMU)	      \
    && defined(PT_TEXT_ADDR) && defined(PT_DATA_ADDR) \
    && defined(PT_TEXT_END_ADDR)

/* This is only used for targets that define PT_TEXT_ADDR,
   PT_DATA_ADDR and PT_TEXT_END_ADDR.  If those are not defined, supposedly
   the target has different ways of acquiring this information, like
   loadmaps.  */

/* Under uCnetbsd, programs are loaded at non-zero offsets, which we need
   to tell gdb about.  */

static int
netbsd_read_offsets (CORE_ADDR *text_p, CORE_ADDR *data_p)
{
  unsigned long text, text_end, data;
  int pid = lwpid_of (current_thread);

  errno = 0;

  text = ptrace (PTRACE_PEEKUSER, pid, (PTRACE_TYPE_ARG3) PT_TEXT_ADDR,
		 (PTRACE_TYPE_ARG4) 0);
  text_end = ptrace (PTRACE_PEEKUSER, pid, (PTRACE_TYPE_ARG3) PT_TEXT_END_ADDR,
		     (PTRACE_TYPE_ARG4) 0);
  data = ptrace (PTRACE_PEEKUSER, pid, (PTRACE_TYPE_ARG3) PT_DATA_ADDR,
		 (PTRACE_TYPE_ARG4) 0);

  if (errno == 0)
    {
      /* Both text and data offsets produced at compile-time (and so
	 used by gdb) are relative to the beginning of the program,
	 with the data segment immediately following the text segment.
	 However, the actual runtime layout in memory may put the data
	 somewhere else, so when we send gdb a data base-address, we
	 use the real data base address and subtract the compile-time
	 data base-address from it (which is just the length of the
	 text segment).  BSS immediately follows data in both
	 cases.  */
      *text_p = text;
      *data_p = data - (text_end - text);

      return 1;
    }
 return 0;
}
#endif

static int
netbsd_qxfer_osdata (const char *annex,
		    unsigned char *readbuf, unsigned const char *writebuf,
		    CORE_ADDR offset, int len)
{
  return netbsd_common_xfer_osdata (annex, readbuf, offset, len);
}

/* Convert a native/host siginfo object, into/from the siginfo in the
   layout of the inferiors' architecture.  */

static void
siginfo_fixup (siginfo_t *siginfo, gdb_byte *inf_siginfo, int direction)
{
  int done = 0;

  if (the_low_target.siginfo_fixup != NULL)
    done = the_low_target.siginfo_fixup (siginfo, inf_siginfo, direction);

  /* If there was no callback, or the callback didn't do anything,
     then just do a straight memcpy.  */
  if (!done)
    {
      if (direction == 1)
	memcpy (siginfo, inf_siginfo, sizeof (siginfo_t));
      else
	memcpy (inf_siginfo, siginfo, sizeof (siginfo_t));
    }
}

static int
netbsd_xfer_siginfo (const char *annex, unsigned char *readbuf,
		    unsigned const char *writebuf, CORE_ADDR offset, int len)
{
  int pid;
  siginfo_t siginfo;
  gdb_byte inf_siginfo[sizeof (siginfo_t)];

  if (current_thread == NULL)
    return -1;

  pid = lwpid_of (current_thread);

  if (debug_threads)
    debug_printf ("%s siginfo for lwp %d.\n",
		  readbuf != NULL ? "Reading" : "Writing",
		  pid);

  if (offset >= sizeof (siginfo))
    return -1;

  if (ptrace (PTRACE_GETSIGINFO, pid, (PTRACE_TYPE_ARG3) 0, &siginfo) != 0)
    return -1;

  /* When GDBSERVER is built as a 64-bit application, ptrace writes into
     SIGINFO an object with 64-bit layout.  Since debugging a 32-bit
     inferior with a 64-bit GDBSERVER should look the same as debugging it
     with a 32-bit GDBSERVER, we need to convert it.  */
  siginfo_fixup (&siginfo, inf_siginfo, 0);

  if (offset + len > sizeof (siginfo))
    len = sizeof (siginfo) - offset;

  if (readbuf != NULL)
    memcpy (readbuf, inf_siginfo + offset, len);
  else
    {
      memcpy (inf_siginfo + offset, writebuf, len);

      /* Convert back to ptrace layout before flushing it out.  */
      siginfo_fixup (&siginfo, inf_siginfo, 1);

      if (ptrace (PTRACE_SETSIGINFO, pid, (PTRACE_TYPE_ARG3) 0, &siginfo) != 0)
	return -1;
    }

  return len;
}

/* SIGCHLD handler that serves two purposes: In non-stop/async mode,
   so we notice when children change state; as the handler for the
   sigsuspend in my_waitpid.  */

static void
sigchld_handler (int signo)
{
  int old_errno = errno;

  if (debug_threads)
    {
      do
	{
	  /* Use the async signal safe debug function.  */
	  if (debug_write ("sigchld_handler\n",
			   sizeof ("sigchld_handler\n") - 1) < 0)
	    break; /* just ignore */
	} while (0);
    }

  if (target_is_async_p ())
    async_file_mark (); /* trigger a netbsd_wait */

  errno = old_errno;
}

static int
netbsd_supports_non_stop (void)
{
  return 1;
}

static int
netbsd_async (int enable)
{
  int previous = target_is_async_p ();

  if (debug_threads)
    debug_printf ("netbsd_async (%d), previous=%d\n",
		  enable, previous);

  if (previous != enable)
    {
      sigset_t mask;
      sigemptyset (&mask);
      sigaddset (&mask, SIGCHLD);

      sigprocmask (SIG_BLOCK, &mask, NULL);

      if (enable)
	{
	  if (pipe (netbsd_event_pipe) == -1)
	    {
	      netbsd_event_pipe[0] = -1;
	      netbsd_event_pipe[1] = -1;
	      sigprocmask (SIG_UNBLOCK, &mask, NULL);

	      warning ("creating event pipe failed.");
	      return previous;
	    }

	  fcntl (netbsd_event_pipe[0], F_SETFL, O_NONBLOCK);
	  fcntl (netbsd_event_pipe[1], F_SETFL, O_NONBLOCK);

	  /* Register the event loop handler.  */
	  add_file_handler (netbsd_event_pipe[0],
			    handle_target_event, NULL);

	  /* Always trigger a netbsd_wait.  */
	  async_file_mark ();
	}
      else
	{
	  delete_file_handler (netbsd_event_pipe[0]);

	  close (netbsd_event_pipe[0]);
	  close (netbsd_event_pipe[1]);
	  netbsd_event_pipe[0] = -1;
	  netbsd_event_pipe[1] = -1;
	}

      sigprocmask (SIG_UNBLOCK, &mask, NULL);
    }

  return previous;
}

static int
netbsd_start_non_stop (int nonstop)
{
  /* Register or unregister from event-loop accordingly.  */
  netbsd_async (nonstop);

  if (target_is_async_p () != (nonstop != 0))
    return -1;

  return 0;
}

static int
netbsd_supports_multi_process (void)
{
  return 1;
}

/* Check if fork events are supported.  */

static int
netbsd_supports_fork_events (void)
{
  return netbsd_supports_tracefork ();
}

/* Check if vfork events are supported.  */

static int
netbsd_supports_vfork_events (void)
{
  return netbsd_supports_tracefork ();
}

/* Check if exec events are supported.  */

static int
netbsd_supports_exec_events (void)
{
  return netbsd_supports_traceexec ();
}

/* Target hook for 'handle_new_gdb_connection'.  Causes a reset of the
   ptrace flags for all inferiors.  This is in case the new GDB connection
   doesn't support the same set of events that the previous one did.  */

static void
netbsd_handle_new_gdb_connection (void)
{
  /* Request that all the lwps reset their ptrace options.  */
  for_each_thread ([] (thread_info *thread)
    {
      struct lwp_info *lwp = get_thread_lwp (thread);

      if (!lwp->stopped)
	{
	  /* Stop the lwp so we can modify its ptrace options.  */
	  lwp->must_set_ptrace_flags = 1;
	  netbsd_stop_lwp (lwp);
	}
      else
	{
	  /* Already stopped; go ahead and set the ptrace options.  */
	  struct process_info *proc = find_process_pid (pid_of (thread));
	  int options = netbsd_low_ptrace_options (proc->attached);

	  netbsd_enable_event_reporting (lwpid_of (thread), options);
	  lwp->must_set_ptrace_flags = 0;
	}
    });
}

static int
netbsd_supports_disable_randomization (void)
{
#ifdef HAVE_PERSONALITY
  return 1;
#else
  return 0;
#endif
}

static int
netbsd_supports_agent (void)
{
  return 1;
}

static int
netbsd_supports_range_stepping (void)
{
  if (can_software_single_step ())
    return 1;
  if (*the_low_target.supports_range_stepping == NULL)
    return 0;

  return (*the_low_target.supports_range_stepping) ();
}

/* Enumerate spufs IDs for process PID.  */
static int
spu_enumerate_spu_ids (long pid, unsigned char *buf, CORE_ADDR offset, int len)
{
  int pos = 0;
  int written = 0;
  char path[128];
  DIR *dir;
  struct dirent *entry;

  sprintf (path, "/proc/%ld/fd", pid);
  dir = opendir (path);
  if (!dir)
    return -1;

  rewinddir (dir);
  while ((entry = readdir (dir)) != NULL)
    {
      struct stat st;
      struct statfs stfs;
      int fd;

      fd = atoi (entry->d_name);
      if (!fd)
        continue;

      sprintf (path, "/proc/%ld/fd/%d", pid, fd);
      if (stat (path, &st) != 0)
        continue;
      if (!S_ISDIR (st.st_mode))
        continue;

      if (statfs (path, &stfs) != 0)
        continue;
      if (stfs.f_type != SPUFS_MAGIC)
        continue;

      if (pos >= offset && pos + 4 <= offset + len)
        {
          *(unsigned int *)(buf + pos - offset) = fd;
          written += 4;
        }
      pos += 4;
    }

  closedir (dir);
  return written;
}

/* Implements the to_xfer_partial interface for the TARGET_OBJECT_SPU
   object type, using the /proc file system.  */
static int
netbsd_qxfer_spu (const char *annex, unsigned char *readbuf,
		 unsigned const char *writebuf,
		 CORE_ADDR offset, int len)
{
  long pid = lwpid_of (current_thread);
  char buf[128];
  int fd = 0;
  int ret = 0;

  if (!writebuf && !readbuf)
    return -1;

  if (!*annex)
    {
      if (!readbuf)
	return -1;
      else
	return spu_enumerate_spu_ids (pid, readbuf, offset, len);
    }

  sprintf (buf, "/proc/%ld/fd/%s", pid, annex);
  fd = open (buf, writebuf? O_WRONLY : O_RDONLY);
  if (fd <= 0)
    return -1;

  if (offset != 0
      && lseek (fd, (off_t) offset, SEEK_SET) != (off_t) offset)
    {
      close (fd);
      return 0;
    }

  if (writebuf)
    ret = write (fd, writebuf, (size_t) len);
  else
    ret = read (fd, readbuf, (size_t) len);

  close (fd);
  return ret;
}

#if defined PT_GETDSBT || defined PTRACE_GETFDPIC
struct target_loadseg
{
  /* Core address to which the segment is mapped.  */
  Elf32_Addr addr;
  /* VMA recorded in the program header.  */
  Elf32_Addr p_vaddr;
  /* Size of this segment in memory.  */
  Elf32_Word p_memsz;
};

# if defined PT_GETDSBT
struct target_loadmap
{
  /* Protocol version number, must be zero.  */
  Elf32_Word version;
  /* Pointer to the DSBT table, its size, and the DSBT index.  */
  unsigned *dsbt_table;
  unsigned dsbt_size, dsbt_index;
  /* Number of segments in this map.  */
  Elf32_Word nsegs;
  /* The actual memory map.  */
  struct target_loadseg segs[/*nsegs*/];
};
#  define NETBSD_LOADMAP		PT_GETDSBT
#  define NETBSD_LOADMAP_EXEC	PTRACE_GETDSBT_EXEC
#  define NETBSD_LOADMAP_INTERP	PTRACE_GETDSBT_INTERP
# else
struct target_loadmap
{
  /* Protocol version number, must be zero.  */
  Elf32_Half version;
  /* Number of segments in this map.  */
  Elf32_Half nsegs;
  /* The actual memory map.  */
  struct target_loadseg segs[/*nsegs*/];
};
#  define NETBSD_LOADMAP		PTRACE_GETFDPIC
#  define NETBSD_LOADMAP_EXEC	PTRACE_GETFDPIC_EXEC
#  define NETBSD_LOADMAP_INTERP	PTRACE_GETFDPIC_INTERP
# endif

static int
netbsd_read_loadmap (const char *annex, CORE_ADDR offset,
		    unsigned char *myaddr, unsigned int len)
{
  int pid = lwpid_of (current_thread);
  int addr = -1;
  struct target_loadmap *data = NULL;
  unsigned int actual_length, copy_length;

  if (strcmp (annex, "exec") == 0)
    addr = (int) NETBSD_LOADMAP_EXEC;
  else if (strcmp (annex, "interp") == 0)
    addr = (int) NETBSD_LOADMAP_INTERP;
  else
    return -1;

  if (ptrace (NETBSD_LOADMAP, pid, addr, &data) != 0)
    return -1;

  if (data == NULL)
    return -1;

  actual_length = sizeof (struct target_loadmap)
    + sizeof (struct target_loadseg) * data->nsegs;

  if (offset < 0 || offset > actual_length)
    return -1;

  copy_length = actual_length - offset < len ? actual_length - offset : len;
  memcpy (myaddr, (char *) data + offset, copy_length);
  return copy_length;
}
#else
# define netbsd_read_loadmap NULL
#endif /* defined PT_GETDSBT || defined PTRACE_GETFDPIC */

static void
netbsd_process_qsupported (char **features, int count)
{
  if (the_low_target.process_qsupported != NULL)
    the_low_target.process_qsupported (features, count);
}

static int
netbsd_supports_catch_syscall (void)
{
  return (the_low_target.get_syscall_trapinfo != NULL
	  && netbsd_supports_tracesysgood ());
}

static int
netbsd_get_ipa_tdesc_idx (void)
{
  if (the_low_target.get_ipa_tdesc_idx == NULL)
    return 0;

  return (*the_low_target.get_ipa_tdesc_idx) ();
}

static int
netbsd_supports_tracepoints (void)
{
  if (*the_low_target.supports_tracepoints == NULL)
    return 0;

  return (*the_low_target.supports_tracepoints) ();
}

static CORE_ADDR
netbsd_read_pc (struct regcache *regcache)
{
  if (the_low_target.get_pc == NULL)
    return 0;

  return (*the_low_target.get_pc) (regcache);
}

static void
netbsd_write_pc (struct regcache *regcache, CORE_ADDR pc)
{
  gdb_assert (the_low_target.set_pc != NULL);

  (*the_low_target.set_pc) (regcache, pc);
}

static int
netbsd_thread_stopped (struct thread_info *thread)
{
  return get_thread_lwp (thread)->stopped;
}

/* This exposes stop-all-threads functionality to other modules.  */

static void
netbsd_pause_all (int freeze)
{
  stop_all_lwps (freeze, NULL);
}

/* This exposes unstop-all-threads functionality to other gdbserver
   modules.  */

static void
netbsd_unpause_all (int unfreeze)
{
  unstop_all_lwps (unfreeze, NULL);
}

static int
netbsd_prepare_to_access_memory (void)
{
  /* Neither ptrace nor /proc/PID/mem allow accessing memory through a
     running LWP.  */
  if (non_stop)
    netbsd_pause_all (1);
  return 0;
}

static void
netbsd_done_accessing_memory (void)
{
  /* Neither ptrace nor /proc/PID/mem allow accessing memory through a
     running LWP.  */
  if (non_stop)
    netbsd_unpause_all (1);
}

static int
netbsd_install_fast_tracepoint_jump_pad (CORE_ADDR tpoint, CORE_ADDR tpaddr,
					CORE_ADDR collector,
					CORE_ADDR lockaddr,
					ULONGEST orig_size,
					CORE_ADDR *jump_entry,
					CORE_ADDR *trampoline,
					ULONGEST *trampoline_size,
					unsigned char *jjump_pad_insn,
					ULONGEST *jjump_pad_insn_size,
					CORE_ADDR *adjusted_insn_addr,
					CORE_ADDR *adjusted_insn_addr_end,
					char *err)
{
  return (*the_low_target.install_fast_tracepoint_jump_pad)
    (tpoint, tpaddr, collector, lockaddr, orig_size,
     jump_entry, trampoline, trampoline_size,
     jjump_pad_insn, jjump_pad_insn_size,
     adjusted_insn_addr, adjusted_insn_addr_end,
     err);
}

static struct emit_ops *
netbsd_emit_ops (void)
{
  if (the_low_target.emit_ops != NULL)
    return (*the_low_target.emit_ops) ();
  else
    return NULL;
}

static int
netbsd_get_min_fast_tracepoint_insn_len (void)
{
  return (*the_low_target.get_min_fast_tracepoint_insn_len) ();
}

/* Extract &phdr and num_phdr in the inferior.  Return 0 on success.  */

static int
get_phdr_phnum_from_proc_auxv (const int pid, const int is_elf64,
			       CORE_ADDR *phdr_memaddr, int *num_phdr)
{
  char filename[PATH_MAX];
  int fd;
  const int auxv_size = is_elf64
    ? sizeof (Elf64_auxv_t) : sizeof (Elf32_auxv_t);
  char buf[sizeof (Elf64_auxv_t)];  /* The larger of the two.  */

  xsnprintf (filename, sizeof filename, "/proc/%d/auxv", pid);

  fd = open (filename, O_RDONLY);
  if (fd < 0)
    return 1;

  *phdr_memaddr = 0;
  *num_phdr = 0;
  while (read (fd, buf, auxv_size) == auxv_size
	 && (*phdr_memaddr == 0 || *num_phdr == 0))
    {
      if (is_elf64)
	{
	  Elf64_auxv_t *const aux = (Elf64_auxv_t *) buf;

	  switch (aux->a_type)
	    {
	    case AT_PHDR:
	      *phdr_memaddr = aux->a_un.a_val;
	      break;
	    case AT_PHNUM:
	      *num_phdr = aux->a_un.a_val;
	      break;
	    }
	}
      else
	{
	  Elf32_auxv_t *const aux = (Elf32_auxv_t *) buf;

	  switch (aux->a_type)
	    {
	    case AT_PHDR:
	      *phdr_memaddr = aux->a_un.a_val;
	      break;
	    case AT_PHNUM:
	      *num_phdr = aux->a_un.a_val;
	      break;
	    }
	}
    }

  close (fd);

  if (*phdr_memaddr == 0 || *num_phdr == 0)
    {
      warning ("Unexpected missing AT_PHDR and/or AT_PHNUM: "
	       "phdr_memaddr = %ld, phdr_num = %d",
	       (long) *phdr_memaddr, *num_phdr);
      return 2;
    }

  return 0;
}

/* Return &_DYNAMIC (via PT_DYNAMIC) in the inferior, or 0 if not present.  */

static CORE_ADDR
get_dynamic (const int pid, const int is_elf64)
{
  CORE_ADDR phdr_memaddr, relocation;
  int num_phdr, i;
  unsigned char *phdr_buf;
  const int phdr_size = is_elf64 ? sizeof (Elf64_Phdr) : sizeof (Elf32_Phdr);

  if (get_phdr_phnum_from_proc_auxv (pid, is_elf64, &phdr_memaddr, &num_phdr))
    return 0;

  gdb_assert (num_phdr < 100);  /* Basic sanity check.  */
  phdr_buf = (unsigned char *) alloca (num_phdr * phdr_size);

  if (netbsd_read_memory (phdr_memaddr, phdr_buf, num_phdr * phdr_size))
    return 0;

  /* Compute relocation: it is expected to be 0 for "regular" executables,
     non-zero for PIE ones.  */
  relocation = -1;
  for (i = 0; relocation == -1 && i < num_phdr; i++)
    if (is_elf64)
      {
	Elf64_Phdr *const p = (Elf64_Phdr *) (phdr_buf + i * phdr_size);

	if (p->p_type == PT_PHDR)
	  relocation = phdr_memaddr - p->p_vaddr;
      }
    else
      {
	Elf32_Phdr *const p = (Elf32_Phdr *) (phdr_buf + i * phdr_size);

	if (p->p_type == PT_PHDR)
	  relocation = phdr_memaddr - p->p_vaddr;
      }

  if (relocation == -1)
    {
      /* PT_PHDR is optional, but necessary for PIE in general.  Fortunately
	 any real world executables, including PIE executables, have always
	 PT_PHDR present.  PT_PHDR is not present in some shared libraries or
	 in fpc (Free Pascal 2.4) binaries but neither of those have a need for
	 or present DT_DEBUG anyway (fpc binaries are statically linked).

	 Therefore if there exists DT_DEBUG there is always also PT_PHDR.

	 GDB could find RELOCATION also from AT_ENTRY - e_entry.  */

      return 0;
    }

  for (i = 0; i < num_phdr; i++)
    {
      if (is_elf64)
	{
	  Elf64_Phdr *const p = (Elf64_Phdr *) (phdr_buf + i * phdr_size);

	  if (p->p_type == PT_DYNAMIC)
	    return p->p_vaddr + relocation;
	}
      else
	{
	  Elf32_Phdr *const p = (Elf32_Phdr *) (phdr_buf + i * phdr_size);

	  if (p->p_type == PT_DYNAMIC)
	    return p->p_vaddr + relocation;
	}
    }

  return 0;
}

/* Return &_r_debug in the inferior, or -1 if not present.  Return value
   can be 0 if the inferior does not yet have the library list initialized.
   We look for DT_MIPS_RLD_MAP first.  MIPS executables use this instead of
   DT_DEBUG, although they sometimes contain an unused DT_DEBUG entry too.  */

static CORE_ADDR
get_r_debug (const int pid, const int is_elf64)
{
  CORE_ADDR dynamic_memaddr;
  const int dyn_size = is_elf64 ? sizeof (Elf64_Dyn) : sizeof (Elf32_Dyn);
  unsigned char buf[sizeof (Elf64_Dyn)];  /* The larger of the two.  */
  CORE_ADDR map = -1;

  dynamic_memaddr = get_dynamic (pid, is_elf64);
  if (dynamic_memaddr == 0)
    return map;

  while (netbsd_read_memory (dynamic_memaddr, buf, dyn_size) == 0)
    {
      if (is_elf64)
	{
	  Elf64_Dyn *const dyn = (Elf64_Dyn *) buf;
#if defined DT_MIPS_RLD_MAP || defined DT_MIPS_RLD_MAP_REL
	  union
	    {
	      Elf64_Xword map;
	      unsigned char buf[sizeof (Elf64_Xword)];
	    }
	  rld_map;
#endif
#ifdef DT_MIPS_RLD_MAP
	  if (dyn->d_tag == DT_MIPS_RLD_MAP)
	    {
	      if (netbsd_read_memory (dyn->d_un.d_val,
				     rld_map.buf, sizeof (rld_map.buf)) == 0)
		return rld_map.map;
	      else
		break;
	    }
#endif	/* DT_MIPS_RLD_MAP */
#ifdef DT_MIPS_RLD_MAP_REL
	  if (dyn->d_tag == DT_MIPS_RLD_MAP_REL)
	    {
	      if (netbsd_read_memory (dyn->d_un.d_val + dynamic_memaddr,
				     rld_map.buf, sizeof (rld_map.buf)) == 0)
		return rld_map.map;
	      else
		break;
	    }
#endif	/* DT_MIPS_RLD_MAP_REL */

	  if (dyn->d_tag == DT_DEBUG && map == -1)
	    map = dyn->d_un.d_val;

	  if (dyn->d_tag == DT_NULL)
	    break;
	}
      else
	{
	  Elf32_Dyn *const dyn = (Elf32_Dyn *) buf;
#if defined DT_MIPS_RLD_MAP || defined DT_MIPS_RLD_MAP_REL
	  union
	    {
	      Elf32_Word map;
	      unsigned char buf[sizeof (Elf32_Word)];
	    }
	  rld_map;
#endif
#ifdef DT_MIPS_RLD_MAP
	  if (dyn->d_tag == DT_MIPS_RLD_MAP)
	    {
	      if (netbsd_read_memory (dyn->d_un.d_val,
				     rld_map.buf, sizeof (rld_map.buf)) == 0)
		return rld_map.map;
	      else
		break;
	    }
#endif	/* DT_MIPS_RLD_MAP */
#ifdef DT_MIPS_RLD_MAP_REL
	  if (dyn->d_tag == DT_MIPS_RLD_MAP_REL)
	    {
	      if (netbsd_read_memory (dyn->d_un.d_val + dynamic_memaddr,
				     rld_map.buf, sizeof (rld_map.buf)) == 0)
		return rld_map.map;
	      else
		break;
	    }
#endif	/* DT_MIPS_RLD_MAP_REL */

	  if (dyn->d_tag == DT_DEBUG && map == -1)
	    map = dyn->d_un.d_val;

	  if (dyn->d_tag == DT_NULL)
	    break;
	}

      dynamic_memaddr += dyn_size;
    }

  return map;
}

/* Read one pointer from MEMADDR in the inferior.  */

static int
read_one_ptr (CORE_ADDR memaddr, CORE_ADDR *ptr, int ptr_size)
{
  int ret;

  /* Go through a union so this works on either big or little endian
     hosts, when the inferior's pointer size is smaller than the size
     of CORE_ADDR.  It is assumed the inferior's endianness is the
     same of the superior's.  */
  union
  {
    CORE_ADDR core_addr;
    unsigned int ui;
    unsigned char uc;
  } addr;

  ret = netbsd_read_memory (memaddr, &addr.uc, ptr_size);
  if (ret == 0)
    {
      if (ptr_size == sizeof (CORE_ADDR))
	*ptr = addr.core_addr;
      else if (ptr_size == sizeof (unsigned int))
	*ptr = addr.ui;
      else
	gdb_assert_not_reached ("unhandled pointer size");
    }
  return ret;
}

struct link_map_offsets
  {
    /* Offset and size of r_debug.r_version.  */
    int r_version_offset;

    /* Offset and size of r_debug.r_map.  */
    int r_map_offset;

    /* Offset to l_addr field in struct link_map.  */
    int l_addr_offset;

    /* Offset to l_name field in struct link_map.  */
    int l_name_offset;

    /* Offset to l_ld field in struct link_map.  */
    int l_ld_offset;

    /* Offset to l_next field in struct link_map.  */
    int l_next_offset;

    /* Offset to l_prev field in struct link_map.  */
    int l_prev_offset;
  };

/* Construct qXfer:libraries-svr4:read reply.  */

static int
netbsd_qxfer_libraries_svr4 (const char *annex, unsigned char *readbuf,
			    unsigned const char *writebuf,
			    CORE_ADDR offset, int len)
{
  struct process_info_private *const priv = current_process ()->priv;
  char filename[PATH_MAX];
  int pid, is_elf64;

  static const struct link_map_offsets lmo_32bit_offsets =
    {
      0,     /* r_version offset. */
      4,     /* r_debug.r_map offset.  */
      0,     /* l_addr offset in link_map.  */
      4,     /* l_name offset in link_map.  */
      8,     /* l_ld offset in link_map.  */
      12,    /* l_next offset in link_map.  */
      16     /* l_prev offset in link_map.  */
    };

  static const struct link_map_offsets lmo_64bit_offsets =
    {
      0,     /* r_version offset. */
      8,     /* r_debug.r_map offset.  */
      0,     /* l_addr offset in link_map.  */
      8,     /* l_name offset in link_map.  */
      16,    /* l_ld offset in link_map.  */
      24,    /* l_next offset in link_map.  */
      32     /* l_prev offset in link_map.  */
    };
  const struct link_map_offsets *lmo;
  unsigned int machine;
  int ptr_size;
  CORE_ADDR lm_addr = 0, lm_prev = 0;
  CORE_ADDR l_name, l_addr, l_ld, l_next, l_prev;
  int header_done = 0;

  if (writebuf != NULL)
    return -2;
  if (readbuf == NULL)
    return -1;

  pid = lwpid_of (current_thread);
  xsnprintf (filename, sizeof filename, "/proc/%d/exe", pid);
  is_elf64 = elf_64_file_p (filename, &machine);
  lmo = is_elf64 ? &lmo_64bit_offsets : &lmo_32bit_offsets;
  ptr_size = is_elf64 ? 8 : 4;

  while (annex[0] != '\0')
    {
      const char *sep;
      CORE_ADDR *addrp;
      int name_len;

      sep = strchr (annex, '=');
      if (sep == NULL)
	break;

      name_len = sep - annex;
      if (name_len == 5 && startswith (annex, "start"))
	addrp = &lm_addr;
      else if (name_len == 4 && startswith (annex, "prev"))
	addrp = &lm_prev;
      else
	{
	  annex = strchr (sep, ';');
	  if (annex == NULL)
	    break;
	  annex++;
	  continue;
	}

      annex = decode_address_to_semicolon (addrp, sep + 1);
    }

  if (lm_addr == 0)
    {
      int r_version = 0;

      if (priv->r_debug == 0)
	priv->r_debug = get_r_debug (pid, is_elf64);

      /* We failed to find DT_DEBUG.  Such situation will not change
	 for this inferior - do not retry it.  Report it to GDB as
	 E01, see for the reasons at the GDB solib-svr4.c side.  */
      if (priv->r_debug == (CORE_ADDR) -1)
	return -1;

      if (priv->r_debug != 0)
	{
	  if (netbsd_read_memory (priv->r_debug + lmo->r_version_offset,
				 (unsigned char *) &r_version,
				 sizeof (r_version)) != 0
	      || r_version != 1)
	    {
	      warning ("unexpected r_debug version %d", r_version);
	    }
	  else if (read_one_ptr (priv->r_debug + lmo->r_map_offset,
				 &lm_addr, ptr_size) != 0)
	    {
	      warning ("unable to read r_map from 0x%lx",
		       (long) priv->r_debug + lmo->r_map_offset);
	    }
	}
    }

  std::string document = "<library-list-svr4 version=\"1.0\"";

  while (lm_addr
	 && read_one_ptr (lm_addr + lmo->l_name_offset,
			  &l_name, ptr_size) == 0
	 && read_one_ptr (lm_addr + lmo->l_addr_offset,
			  &l_addr, ptr_size) == 0
	 && read_one_ptr (lm_addr + lmo->l_ld_offset,
			  &l_ld, ptr_size) == 0
	 && read_one_ptr (lm_addr + lmo->l_prev_offset,
			  &l_prev, ptr_size) == 0
	 && read_one_ptr (lm_addr + lmo->l_next_offset,
			  &l_next, ptr_size) == 0)
    {
      unsigned char libname[PATH_MAX];

      if (lm_prev != l_prev)
	{
	  warning ("Corrupted shared library list: 0x%lx != 0x%lx",
		   (long) lm_prev, (long) l_prev);
	  break;
	}

      /* Ignore the first entry even if it has valid name as the first entry
	 corresponds to the main executable.  The first entry should not be
	 skipped if the dynamic loader was loaded late by a static executable
	 (see solib-svr4.c parameter ignore_first).  But in such case the main
	 executable does not have PT_DYNAMIC present and this function already
	 exited above due to failed get_r_debug.  */
      if (lm_prev == 0)
	string_appendf (document, " main-lm=\"0x%lx\"", (unsigned long) lm_addr);
      else
	{
	  /* Not checking for error because reading may stop before
	     we've got PATH_MAX worth of characters.  */
	  libname[0] = '\0';
	  netbsd_read_memory (l_name, libname, sizeof (libname) - 1);
	  libname[sizeof (libname) - 1] = '\0';
	  if (libname[0] != '\0')
	    {
	      if (!header_done)
		{
		  /* Terminate `<library-list-svr4'.  */
		  document += '>';
		  header_done = 1;
		}

	      string_appendf (document, "<library name=\"");
	      xml_escape_text_append (&document, (char *) libname);
	      string_appendf (document, "\" lm=\"0x%lx\" "
			      "l_addr=\"0x%lx\" l_ld=\"0x%lx\"/>",
			      (unsigned long) lm_addr, (unsigned long) l_addr,
			      (unsigned long) l_ld);
	    }
	}

      lm_prev = lm_addr;
      lm_addr = l_next;
    }

  if (!header_done)
    {
      /* Empty list; terminate `<library-list-svr4'.  */
      document += "/>";
    }
  else
    document += "</library-list-svr4>";

  int document_len = document.length ();
  if (offset < document_len)
    document_len -= offset;
  else
    document_len = 0;
  if (len > document_len)
    len = document_len;

  memcpy (readbuf, document.data () + offset, len);

  return len;
}

#ifdef HAVE_NETBSD_BTRACE

/* See to_disable_btrace target method.  */

static int
netbsd_low_disable_btrace (struct btrace_target_info *tinfo)
{
  enum btrace_error err;

  err = netbsd_disable_btrace (tinfo);
  return (err == BTRACE_ERR_NONE ? 0 : -1);
}

/* Encode an Intel Processor Trace configuration.  */

static void
netbsd_low_encode_pt_config (struct buffer *buffer,
			    const struct btrace_data_pt_config *config)
{
  buffer_grow_str (buffer, "<pt-config>\n");

  switch (config->cpu.vendor)
    {
    case CV_INTEL:
      buffer_xml_printf (buffer, "<cpu vendor=\"GenuineIntel\" family=\"%u\" "
			 "model=\"%u\" stepping=\"%u\"/>\n",
			 config->cpu.family, config->cpu.model,
			 config->cpu.stepping);
      break;

    default:
      break;
    }

  buffer_grow_str (buffer, "</pt-config>\n");
}

/* Encode a raw buffer.  */

static void
netbsd_low_encode_raw (struct buffer *buffer, const gdb_byte *data,
		      unsigned int size)
{
  if (size == 0)
    return;

  /* We use hex encoding - see common/rsp-low.h.  */
  buffer_grow_str (buffer, "<raw>\n");

  while (size-- > 0)
    {
      char elem[2];

      elem[0] = tohex ((*data >> 4) & 0xf);
      elem[1] = tohex (*data++ & 0xf);

      buffer_grow (buffer, elem, 2);
    }

  buffer_grow_str (buffer, "</raw>\n");
}

/* See to_read_btrace target method.  */

static int
netbsd_low_read_btrace (struct btrace_target_info *tinfo, struct buffer *buffer,
		       enum btrace_read_type type)
{
  struct btrace_data btrace;
  struct btrace_block *block;
  enum btrace_error err;
  int i;

  err = netbsd_read_btrace (&btrace, tinfo, type);
  if (err != BTRACE_ERR_NONE)
    {
      if (err == BTRACE_ERR_OVERFLOW)
	buffer_grow_str0 (buffer, "E.Overflow.");
      else
	buffer_grow_str0 (buffer, "E.Generic Error.");

      return -1;
    }

  switch (btrace.format)
    {
    case BTRACE_FORMAT_NONE:
      buffer_grow_str0 (buffer, "E.No Trace.");
      return -1;

    case BTRACE_FORMAT_BTS:
      buffer_grow_str (buffer, "<!DOCTYPE btrace SYSTEM \"btrace.dtd\">\n");
      buffer_grow_str (buffer, "<btrace version=\"1.0\">\n");

      for (i = 0;
	   VEC_iterate (btrace_block_s, btrace.variant.bts.blocks, i, block);
	   i++)
	buffer_xml_printf (buffer, "<block begin=\"0x%s\" end=\"0x%s\"/>\n",
			   paddress (block->begin), paddress (block->end));

      buffer_grow_str0 (buffer, "</btrace>\n");
      break;

    case BTRACE_FORMAT_PT:
      buffer_grow_str (buffer, "<!DOCTYPE btrace SYSTEM \"btrace.dtd\">\n");
      buffer_grow_str (buffer, "<btrace version=\"1.0\">\n");
      buffer_grow_str (buffer, "<pt>\n");

      netbsd_low_encode_pt_config (buffer, &btrace.variant.pt.config);

      netbsd_low_encode_raw (buffer, btrace.variant.pt.data,
			    btrace.variant.pt.size);

      buffer_grow_str (buffer, "</pt>\n");
      buffer_grow_str0 (buffer, "</btrace>\n");
      break;

    default:
      buffer_grow_str0 (buffer, "E.Unsupported Trace Format.");
      return -1;
    }

  return 0;
}

/* See to_btrace_conf target method.  */

static int
netbsd_low_btrace_conf (const struct btrace_target_info *tinfo,
		       struct buffer *buffer)
{
  const struct btrace_config *conf;

  buffer_grow_str (buffer, "<!DOCTYPE btrace-conf SYSTEM \"btrace-conf.dtd\">\n");
  buffer_grow_str (buffer, "<btrace-conf version=\"1.0\">\n");

  conf = netbsd_btrace_conf (tinfo);
  if (conf != NULL)
    {
      switch (conf->format)
	{
	case BTRACE_FORMAT_NONE:
	  break;

	case BTRACE_FORMAT_BTS:
	  buffer_xml_printf (buffer, "<bts");
	  buffer_xml_printf (buffer, " size=\"0x%x\"", conf->bts.size);
	  buffer_xml_printf (buffer, " />\n");
	  break;

	case BTRACE_FORMAT_PT:
	  buffer_xml_printf (buffer, "<pt");
	  buffer_xml_printf (buffer, " size=\"0x%x\"", conf->pt.size);
	  buffer_xml_printf (buffer, "/>\n");
	  break;
	}
    }

  buffer_grow_str0 (buffer, "</btrace-conf>\n");
  return 0;
}
#endif /* HAVE_NETBSD_BTRACE */

/* See nat/netbsd-nat.h.  */

ptid_t
current_lwp_ptid (void)
{
  return ptid_of (current_thread);
}

/* Implementation of the target_ops method "breakpoint_kind_from_pc".  */

static int
netbsd_breakpoint_kind_from_pc (CORE_ADDR *pcptr)
{
  if (the_low_target.breakpoint_kind_from_pc != NULL)
    return (*the_low_target.breakpoint_kind_from_pc) (pcptr);
  else
    return default_breakpoint_kind_from_pc (pcptr);
}

/* Implementation of the target_ops method "sw_breakpoint_from_kind".  */

static const gdb_byte *
netbsd_sw_breakpoint_from_kind (int kind, int *size)
{
  gdb_assert (the_low_target.sw_breakpoint_from_kind != NULL);

  return (*the_low_target.sw_breakpoint_from_kind) (kind, size);
}

/* Implementation of the target_ops method
   "breakpoint_kind_from_current_state".  */

static int
netbsd_breakpoint_kind_from_current_state (CORE_ADDR *pcptr)
{
  if (the_low_target.breakpoint_kind_from_current_state != NULL)
    return (*the_low_target.breakpoint_kind_from_current_state) (pcptr);
  else
    return netbsd_breakpoint_kind_from_pc (pcptr);
}

/* Default implementation of netbsd_target_ops method "set_pc" for
   32-bit pc register which is literally named "pc".  */

void
netbsd_set_pc_32bit (struct regcache *regcache, CORE_ADDR pc)
{
  uint32_t newpc = pc;

  supply_register_by_name (regcache, "pc", &newpc);
}

/* Default implementation of netbsd_target_ops method "get_pc" for
   32-bit pc register which is literally named "pc".  */

CORE_ADDR
netbsd_get_pc_32bit (struct regcache *regcache)
{
  uint32_t pc;

  collect_register_by_name (regcache, "pc", &pc);
  if (debug_threads)
    debug_printf ("stop pc is 0x%" PRIx32 "\n", pc);
  return pc;
}

/* Default implementation of netbsd_target_ops method "set_pc" for
   64-bit pc register which is literally named "pc".  */

void
netbsd_set_pc_64bit (struct regcache *regcache, CORE_ADDR pc)
{
  uint64_t newpc = pc;

  supply_register_by_name (regcache, "pc", &newpc);
}

/* Default implementation of netbsd_target_ops method "get_pc" for
   64-bit pc register which is literally named "pc".  */

CORE_ADDR
netbsd_get_pc_64bit (struct regcache *regcache)
{
  uint64_t pc;

  collect_register_by_name (regcache, "pc", &pc);
  if (debug_threads)
    debug_printf ("stop pc is 0x%" PRIx64 "\n", pc);
  return pc;
}

/* See netbsd-low.h.  */

int
netbsd_get_auxv (int wordsize, CORE_ADDR match, CORE_ADDR *valp)
{
  gdb_byte *data = (gdb_byte *) alloca (2 * wordsize);
  int offset = 0;

  gdb_assert (wordsize == 4 || wordsize == 8);

  while ((*the_target->read_auxv) (offset, data, 2 * wordsize) == 2 * wordsize)
    {
      if (wordsize == 4)
	{
	  uint32_t *data_p = (uint32_t *) data;
	  if (data_p[0] == match)
	    {
	      *valp = data_p[1];
	      return 1;
	    }
	}
      else
	{
	  uint64_t *data_p = (uint64_t *) data;
	  if (data_p[0] == match)
	    {
	      *valp = data_p[1];
	      return 1;
	    }
	}

      offset += 2 * wordsize;
    }

  return 0;
}

/* See netbsd-low.h.  */

CORE_ADDR
netbsd_get_hwcap (int wordsize)
{
  CORE_ADDR hwcap = 0;
  netbsd_get_auxv (wordsize, AT_HWCAP, &hwcap);
  return hwcap;
}

/* See netbsd-low.h.  */

CORE_ADDR
netbsd_get_hwcap2 (int wordsize)
{
  CORE_ADDR hwcap2 = 0;
  netbsd_get_auxv (wordsize, AT_HWCAP2, &hwcap2);
  return hwcap2;
}

static struct target_ops netbsd_target_ops = {
  netbsd_create_inferior,
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
#if defined(__UCLIBC__) && defined(HAS_NOMMU)	      \
    && defined(PT_TEXT_ADDR) && defined(PT_DATA_ADDR) \
    && defined(PT_TEXT_END_ADDR)
  netbsd_read_offsets,
#else
  NULL,
#endif
#ifdef USE_THREAD_DB
  thread_db_get_tls_address,
#else
  NULL,
#endif
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
#ifdef USE_THREAD_DB
  thread_db_handle_monitor_command,
#else
  NULL,
#endif
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
#ifdef HAVE_NETBSD_BTRACE
  netbsd_enable_btrace,
  netbsd_low_disable_btrace,
  netbsd_low_read_btrace,
  netbsd_low_btrace_conf,
#else
  NULL,
  NULL,
  NULL,
  NULL,
#endif
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
  netbsd_get_ipa_tdesc_idx,
#if USE_THREAD_DB
  thread_db_thread_handle,
#else
  NULL,
#endif
};

#ifdef HAVE_NETBSD_REGSETS
void
initialize_regsets_info (struct regsets_info *info)
{
  for (info->num_regsets = 0;
       info->regsets[info->num_regsets].size >= 0;
       info->num_regsets++)
    ;
}
#endif

void
initialize_low (void)
{
  struct sigaction sigchld_action;

  memset (&sigchld_action, 0, sizeof (sigchld_action));
  set_target_ops (&netbsd_target_ops);

  netbsd_ptrace_init_warnings ();
  netbsd_proc_init_warnings ();

  sigchld_action.sa_handler = sigchld_handler;
  sigemptyset (&sigchld_action.sa_mask);
  sigchld_action.sa_flags = SA_RESTART;
  sigaction (SIGCHLD, &sigchld_action, NULL);

  initialize_low_arch ();

  netbsd_check_ptrace_features ();
}
