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
  ptrace (PT_TRACE_ME, 0, NULL, 0);
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
