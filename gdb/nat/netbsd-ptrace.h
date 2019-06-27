/* Copyright (C) 2011-2019 Free Software Foundation, Inc.

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

#ifndef NAT_NETBSD_PTRACE_H
#define NAT_NETBSD_PTRACE_H

struct buffer;

#include "nat/gdb_ptrace.h"
#include "common/gdb_wait.h"

#if !defined(PTRACE_TYPE_ARG3)
#define PTRACE_TYPE_ARG3 void *
#endif

#if !defined(PTRACE_TYPE_ARG4)
#define PTRACE_TYPE_ARG4 int
#endif

extern std::string netbsd_ptrace_attach_fail_reason (pid_t pid);

/* Find all possible reasons we could have failed to attach to PTID
   and return them as a string.  ERR is the error PTRACE_ATTACH failed
   with (an errno).  */
extern std::string netbsd_ptrace_attach_fail_reason_string (ptid_t ptid, int err);

extern void netbsd_ptrace_init_warnings (void);
extern void netbsd_check_ptrace_features (void);
extern void netbsd_enable_event_reporting (pid_t pid);
extern void netbsd_disable_event_reporting (pid_t pid);
extern int netbsd_ptrace_get_extended_event (int wstat);
extern int netbsd_is_extended_waitstatus (int wstat);
extern int netbsd_wstatus_maybe_breakpoint (int wstat);

#endif /* NAT_NETBSD_PTRACE_H */
