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
