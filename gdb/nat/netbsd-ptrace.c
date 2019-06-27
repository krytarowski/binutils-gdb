/* NetBSD-specific ptrace manipulation routines.
   Copyright (C) 2012-2019 Free Software Foundation, Inc.

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

#include "common/common-defs.h"
#include "netbsd-ptrace.h"
#include "netbsd-waitpid.h"
#include "common/buffer.h"

#include <signal.h>

/* Kill CHILD.  WHO is used to report warnings.  */

static void
kill_child (pid_t child, const char *who)
{
  pid_t got_pid;
  int kill_status;

  if (kill (child, SIGKILL) != 0)
    {
      warning (_("%s: failed to kill child pid %ld %s"),
	       who, (long) child, safe_strerror (errno));
      return;
    }

  errno = 0;
  got_pid = my_waitpid (child, &kill_status, 0);
  if (got_pid != child)
    {
      warning (_("%s: "
		 "kill waitpid returned %ld: %s"),
	       who, (long) got_pid, safe_strerror (errno));
      return;
    }
  if (!WIFSIGNALED (kill_status))
    {
      warning (_("%s: "
		 "kill status %d is not WIFSIGNALED!"),
	       who, kill_status);
      return;
    }
}

/* Helper function to fork a process and make the child process call
   the function FUNCTION, passing CHILD_STACK as parameter.

   For MMU-less targets, clone is used instead of fork, and
   CHILD_STACK is used as stack space for the cloned child.  If NULL,
   stack space is allocated via malloc (and subsequently passed to
   FUNCTION).  For MMU targets, CHILD_STACK is ignored.  */

static int
netbsd_fork_to_function (gdb_byte *child_stack, int (*function) (void *))
{
  int child_pid;

  /* Sanity check the function pointer.  */
  gdb_assert (function != NULL);

#if defined(__UCLIBC__) && defined(HAS_NOMMU)
#define STACK_SIZE 4096

    if (child_stack == NULL)
      child_stack = (gdb_byte *) xmalloc (STACK_SIZE * 4);

    /* Use CLONE_VM instead of fork, to support uCnetbsd (no MMU).  */
#ifdef __ia64__
      child_pid = __clone2 (function, child_stack, STACK_SIZE,
			    CLONE_VM | SIGCHLD, child_stack + STACK_SIZE * 2);
#else /* !__ia64__ */
      child_pid = clone (function, child_stack + STACK_SIZE,
			 CLONE_VM | SIGCHLD, child_stack + STACK_SIZE * 2);
#endif /* !__ia64__ */
#else /* !defined(__UCLIBC) && defined(HAS_NOMMU) */
  child_pid = fork ();

  if (child_pid == 0)
    function (NULL);
#endif /* defined(__UCLIBC) && defined(HAS_NOMMU) */

  if (child_pid == -1)
    perror_with_name (("fork"));

  return child_pid;
}

/* A helper function for netbsd_check_ptrace_features, called after
   the child forks a grandchild.  */

static int
netbsd_grandchild_function (void *child_stack)
{
  /* Free any allocated stack.  */
  xfree (child_stack);

  /* This code is only reacheable by the grandchild (child's child)
     process.  */
  _exit (0);
}

/* A helper function for netbsd_check_ptrace_features, called after
   the parent process forks a child.  The child allows itself to
   be traced by its parent.  */

static int
netbsd_child_function (void *child_stack)
{
  ptrace (PTRACE_TRACEME, 0, (PTRACE_TYPE_ARG3) 0, (PTRACE_TYPE_ARG4) 0);
  kill (getpid (), SIGSTOP);

  /* Fork a grandchild.  */
  netbsd_fork_to_function ((gdb_byte *) child_stack, netbsd_grandchild_function);

  /* This code is only reacheable by the child (grandchild's parent)
     process.  */
  _exit (0);
}

/* Enable reporting of all currently supported ptrace events.
   OPTIONS is a bit mask of extended features we want enabled,
   if supported by the kernel.  PTRACE_O_TRACECLONE is always
   enabled, if supported.  */

void
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

  ptrace (PT_SET_EVENT_MASK, pid, &event, sizeof(event));
}

/* Disable reporting of all currently supported ptrace events.  */

void
netbsd_disable_event_reporting (pid_t pid)
{
  /* Set the options.  */
  ptrace (PTRACE_SETOPTIONS, pid, (PTRACE_TYPE_ARG3) 0, 0);
}

/* Returns non-zero if PTRACE_OPTIONS is contained within
   SUPPORTED_PTRACE_OPTIONS, therefore supported.  Returns 0
   otherwise.  */

static int
ptrace_supports_feature (int ptrace_options)
{
  if (supported_ptrace_options == -1)
    netbsd_check_ptrace_features ();

  return ((supported_ptrace_options & ptrace_options) == ptrace_options);
}

/* Returns non-zero if PTRACE_EVENT_FORK is supported by ptrace,
   0 otherwise.  Note that if PTRACE_EVENT_FORK is supported so is
   PTRACE_EVENT_CLONE, PTRACE_EVENT_EXEC and PTRACE_EVENT_VFORK,
   since they were all added to the kernel at the same time.  */

int
netbsd_supports_tracefork (void)
{
  return ptrace_supports_feature (PTRACE_O_TRACEFORK);
}

/* Returns non-zero if PTRACE_EVENT_EXEC is supported by ptrace,
   0 otherwise.  Note that if PTRACE_EVENT_FORK is supported so is
   PTRACE_EVENT_CLONE, PTRACE_EVENT_FORK and PTRACE_EVENT_VFORK,
   since they were all added to the kernel at the same time.  */

int
netbsd_supports_traceexec (void)
{
  return ptrace_supports_feature (PTRACE_O_TRACEEXEC);
}

/* Returns non-zero if PTRACE_EVENT_CLONE is supported by ptrace,
   0 otherwise.  Note that if PTRACE_EVENT_CLONE is supported so is
   PTRACE_EVENT_FORK, PTRACE_EVENT_EXEC and PTRACE_EVENT_VFORK,
   since they were all added to the kernel at the same time.  */

int
netbsd_supports_traceclone (void)
{
  return ptrace_supports_feature (PTRACE_O_TRACECLONE);
}

/* Returns non-zero if PTRACE_O_TRACEVFORKDONE is supported by
   ptrace, 0 otherwise.  */

int
netbsd_supports_tracevforkdone (void)
{
  return ptrace_supports_feature (PTRACE_O_TRACEVFORKDONE);
}

/* Returns non-zero if PTRACE_O_TRACESYSGOOD is supported by ptrace,
   0 otherwise.  */

int
netbsd_supports_tracesysgood (void)
{
  return ptrace_supports_feature (PTRACE_O_TRACESYSGOOD);
}

/* Display possible problems on this system.  Display them only once per GDB
   execution.  */

void
netbsd_ptrace_init_warnings (void)
{
  static int warned = 0;

  if (warned)
    return;
  warned = 1;

  netbsd_ptrace_test_ret_to_nx ();
}

/* Extract extended ptrace event from wait status.  */

int
netbsd_ptrace_get_extended_event (int wstat)
{
  return (wstat >> 16);
}

/* Determine whether wait status denotes an extended event.  */

int
netbsd_is_extended_waitstatus (int wstat)
{
  return (netbsd_ptrace_get_extended_event (wstat) != 0);
}

/* Return true if the event in LP may be caused by breakpoint.  */

int
netbsd_wstatus_maybe_breakpoint (int wstat)
{
  return (WIFSTOPPED (wstat)
	  && (WSTOPSIG (wstat) == SIGTRAP
	      /* SIGILL and SIGSEGV are also treated as traps in case a
		 breakpoint is inserted at the current PC.  */
	      || WSTOPSIG (wstat) == SIGILL
	      || WSTOPSIG (wstat) == SIGSEGV));
}
