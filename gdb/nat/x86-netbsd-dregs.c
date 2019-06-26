/* Low-level debug register code for NetBSD x86 (i386 and x86-64).

   Copyright (C) 1999-2019 Free Software Foundation, Inc.

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
#include "nat/gdb_ptrace.h"
#include "target/waitstatus.h"
#include "nat/x86-netbsd.h"
#include "nat/x86-dregs.h"
#include "nat/x86-netbsd-dregs.h"

/* Get debug register REGNUM value from the LWP specified by PTID.  */

static unsigned long
x86_netbsd_dr_get (ptid_t ptid, int regnum)
{
  struct dbreg dbr;
  lwpid_t tid;

  pid = ptid.pid ();
  tid = ptid.lwp ();

  if (ptrace (PT_GETDBREGS, pid, &dbr, tid) == -1)
    perror_with_name (_("Couldn't read debug register"));

  return dbr.dr[regnum];
}

/* Set debug register REGNUM to VALUE in the LWP specified by PTID.  */

static void
x86_netbsd_dr_set (ptid_t ptid, int regnum, unsigned long value)
{
  struct dbreg dbr;
  lwpid_t tid;

  pid = ptid.pid ();
  tid = ptid.lwp ();

  if (ptrace (PT_GETDBREGS, pid, &dbr, tid) == -1)
    perror_with_name (_("Couldn't read debug register"));

  dbr.dr[regnum] = value;

  if (ptrace (PT_SETDBREGS, pid, &dbr, tid) == -1)
    perror_with_name (_("Couldn't write debug register"));
}

/* Callback for iterate_over_lwps.  Mark that our local mirror of
   LWP's debug registers has been changed, and cause LWP to stop if
   it isn't already.  Values are written from our local mirror to
   the actual debug registers immediately prior to LWP resuming.  */

static int
update_debug_registers_callback (struct lwp_info *lwp)
{
  lwp_set_debug_registers_changed (lwp, 1);

  if (!lwp_is_stopped (lwp))
    netbsd_stop_lwp (lwp);

  /* Continue the iteration.  */
  return 0;
}

/* See nat/x86-netbsd-dregs.h.  */

CORE_ADDR
x86_netbsd_dr_get_addr (int regnum)
{
  gdb_assert (DR_FIRSTADDR <= regnum && regnum <= DR_LASTADDR);

  return x86_netbsd_dr_get (current_lwp_ptid (), regnum);
}

/* See nat/x86-netbsd-dregs.h.  */

void
x86_netbsd_dr_set_addr (int regnum, CORE_ADDR addr)
{
  ptid_t pid_ptid = ptid_t (current_lwp_ptid ().pid ());

  gdb_assert (DR_FIRSTADDR <= regnum && regnum <= DR_LASTADDR);

  iterate_over_lwps (pid_ptid, update_debug_registers_callback);
}

/* See nat/x86-netbsd-dregs.h.  */

unsigned long
x86_netbsd_dr_get_control (void)
{
  return x86_netbsd_dr_get (current_lwp_ptid (), DR_CONTROL);
}

/* See nat/x86-netbsd-dregs.h.  */

void
x86_netbsd_dr_set_control (unsigned long control)
{
  ptid_t pid_ptid = ptid_t (current_lwp_ptid ().pid ());

  iterate_over_lwps (pid_ptid, update_debug_registers_callback);
}

/* See nat/x86-netbsd-dregs.h.  */

unsigned long
x86_netbsd_dr_get_status (void)
{
  return x86_netbsd_dr_get (current_lwp_ptid (), DR_STATUS);
}

/* See nat/x86-netbsd-dregs.h.  */

void
x86_netbsd_update_debug_registers (struct lwp_info *lwp)
{
  ptid_t ptid = ptid_of_lwp (lwp);
  int clear_status = 0;

  gdb_assert (lwp_is_stopped (lwp));

  if (lwp_debug_registers_changed (lwp))
    {
      struct x86_debug_reg_state *state
	= x86_debug_reg_state (ptid.pid ());
      int i;

      ALL_DEBUG_ADDRESS_REGISTERS (i)
	if (state->dr_ref_count[i] > 0)
	  {
	    x86_netbsd_dr_set (ptid, i, state->dr_mirror[i]);

	    /* If we're setting a watchpoint, any change the inferior
	       has made to its debug registers needs to be discarded
	       to avoid x86_stopped_data_address getting confused.  */
	    clear_status = 1;
	  }

      /* If DR_CONTROL is supposed to be zero then it's already set.  */
      if (state->dr_control_mirror != 0)
	x86_netbsd_dr_set (ptid, DR_CONTROL, state->dr_control_mirror);

      lwp_set_debug_registers_changed (lwp, 0);
    }

  if (clear_status
      || lwp_stop_reason (lwp) == TARGET_STOPPED_BY_WATCHPOINT)
    x86_netbsd_dr_set (ptid, DR_STATUS, 0);
}
