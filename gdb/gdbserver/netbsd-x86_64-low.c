/* Copyright (C) 2010-2019 Free Software Foundation, Inc.

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
#include <limits.h>
#include <sys/ptrace.h>
#include "gdbsupport/x86-xstate.h"
#include "arch/amd64.h"
#include "x86-tdesc.h"


/* The index of various registers inside the regcache.  */

enum netbsd_x86_64_gdb_regnum
{
  I386_EAX_REGNUM,
  I386_ECX_REGNUM,
  I386_EDX_REGNUM,
  I386_EBX_REGNUM,
  I386_ESP_REGNUM,
  I386_EBP_REGNUM,
  I386_ESI_REGNUM,
  I386_EDI_REGNUM,
  I386_EIP_REGNUM,
  I386_EFLAGS_REGNUM,
  I386_CS_REGNUM,
  I386_SS_REGNUM,
  I386_DS_REGNUM,
  I386_ES_REGNUM,
  I386_FS_REGNUM,
  I386_GS_REGNUM,
  I386_ST0_REGNUM,
  I386_FCTRL_REGNUM = I386_ST0_REGNUM + 8,
  I386_FSTAT_REGNUM,
  I386_FTAG_REGNUM,
  I386_FISEG_REGNUM,
  I386_FIOFF_REGNUM,
  I386_FOSEG_REGNUM,
  I386_FOOFF_REGNUM,
  I386_FOP_REGNUM,
  I386_XMM0_REGNUM = 32,
  I386_MXCSR_REGNUM = I386_XMM0_REGNUM + 8,
  I386_SENTINEL_REGUM
};

/* The fill_function for the general-purpose register set.  */

static void
netbsd_x86_64_fill_gregset (struct regcache *regcache, char *buf)
{
#define netbsd_x86_64_collect_gp(regnum, fld) \
  collect_register (regcache, regnum, \
                    buf + offsetof (usr_econtext_t, uec_##fld))

  netbsd_x86_64_collect_gp (I386_EAX_REGNUM, eax);
  netbsd_x86_64_collect_gp (I386_ECX_REGNUM, ecx);
  netbsd_x86_64_collect_gp (I386_EDX_REGNUM, edx);
  netbsd_x86_64_collect_gp (I386_EBX_REGNUM, ebx);
  netbsd_x86_64_collect_gp (I386_ESP_REGNUM, esp);
  netbsd_x86_64_collect_gp (I386_EBP_REGNUM, ebp);
  netbsd_x86_64_collect_gp (I386_ESI_REGNUM, esi);
  netbsd_x86_64_collect_gp (I386_EDI_REGNUM, edi);
  netbsd_x86_64_collect_gp (I386_EIP_REGNUM, eip);
  netbsd_x86_64_collect_gp (I386_EFLAGS_REGNUM, eflags);
  netbsd_x86_64_collect_gp (I386_CS_REGNUM, cs);
  netbsd_x86_64_collect_gp (I386_SS_REGNUM, ss);
  netbsd_x86_64_collect_gp (I386_DS_REGNUM, ds);
  netbsd_x86_64_collect_gp (I386_ES_REGNUM, es);
  netbsd_x86_64_collect_gp (I386_FS_REGNUM, fs);
  netbsd_x86_64_collect_gp (I386_GS_REGNUM, gs);
}

/* The store_function for the general-purpose register set.  */

static void
netbsd_x86_64_store_gregset (struct regcache *regcache, const char *buf)
{
#define netbsd_x86_64_supply_gp(regnum, fld) \
  supply_register (regcache, regnum, \
                   buf + offsetof (usr_econtext_t, uec_##fld))

  netbsd_x86_64_supply_gp (I386_EAX_REGNUM, eax);
  netbsd_x86_64_supply_gp (I386_ECX_REGNUM, ecx);
  netbsd_x86_64_supply_gp (I386_EDX_REGNUM, edx);
  netbsd_x86_64_supply_gp (I386_EBX_REGNUM, ebx);
  netbsd_x86_64_supply_gp (I386_ESP_REGNUM, esp);
  netbsd_x86_64_supply_gp (I386_EBP_REGNUM, ebp);
  netbsd_x86_64_supply_gp (I386_ESI_REGNUM, esi);
  netbsd_x86_64_supply_gp (I386_EDI_REGNUM, edi);
  netbsd_x86_64_supply_gp (I386_EIP_REGNUM, eip);
  netbsd_x86_64_supply_gp (I386_EFLAGS_REGNUM, eflags);
  netbsd_x86_64_supply_gp (I386_CS_REGNUM, cs);
  netbsd_x86_64_supply_gp (I386_SS_REGNUM, ss);
  netbsd_x86_64_supply_gp (I386_DS_REGNUM, ds);
  netbsd_x86_64_supply_gp (I386_ES_REGNUM, es);
  netbsd_x86_64_supply_gp (I386_FS_REGNUM, fs);
  netbsd_x86_64_supply_gp (I386_GS_REGNUM, gs);
}

#if 0
/* Extract the first 16 bits of register REGNUM in the REGCACHE,
   and store these 2 bytes at DEST.

   This is useful to collect certain 16bit registers which are known
   by GDBserver as 32bit registers (such as the Control Register
   for instance).  */

static void
collect_16bit_register (struct regcache *regcache, int regnum, char *dest)
{
  gdb_byte word[4];

  collect_register (regcache, regnum, word);
  memcpy (dest, word, 2);
}
#endif

#if 0
/* The fill_function for the floating-point register set.  */

static void
netbsd_x86_64_fill_fpregset (struct regcache *regcache, char *buf)
{
  int i;

  /* Collect %st0 .. %st7.  */
  for (i = 0; i < 8; i++)
    collect_register (regcache, I386_ST0_REGNUM + i,
                      buf + offsetof (usr_fcontext_t, ufc_reg)
		      + i * sizeof (struct ufp387_real));

  /* Collect the other FPU registers.  */
  collect_16bit_register (regcache, x86_64_FCTRL_REGNUM,
                          buf + offsetof (usr_fcontext_t, ufc_control));
  collect_16bit_register (regcache, I386_FSTAT_REGNUM,
                          buf + offsetof (usr_fcontext_t, ufc_status));
  collect_16bit_register (regcache, I386_FTAG_REGNUM,
                          buf + offsetof (usr_fcontext_t, ufc_tag));
  collect_register (regcache, I386_FISEG_REGNUM,
                    buf + offsetof (usr_fcontext_t, ufc_inst_sel));
  collect_register (regcache, I386_FIOFF_REGNUM,
                    buf + offsetof (usr_fcontext_t, ufc_inst_off));
  collect_register (regcache, I386_FOSEG_REGNUM,
                    buf + offsetof (usr_fcontext_t, ufc_data_sel));
  collect_register (regcache, I386_FOOFF_REGNUM,
                    buf + offsetof (usr_fcontext_t, ufc_data_off));
#if !defined(netbsdOS_178)
  collect_16bit_register (regcache, I386_FOP_REGNUM,
                          buf + offsetof (usr_fcontext_t, ufc_opcode));

  /* Collect the XMM registers.  */
  for (i = 0; i < 8; i++)
    collect_register (regcache, I386_XMM0_REGNUM + i,
                      buf + offsetof (usr_fcontext_t, uxmm_reg)
		      + i * sizeof (struct uxmm_register));
  collect_register (regcache, I386_MXCSR_REGNUM,
                    buf + offsetof (usr_fcontext_t, usse_mxcsr));
#endif
}
#endif

#if 0
/* This is the supply counterpart for collect_16bit_register:
   It extracts a 2byte value from BUF, and uses that value to
   set REGNUM's value in the regcache.

   This is useful to supply the value of certain 16bit registers
   which are known by GDBserver as 32bit registers (such as the Control
   Register for instance).  */

static void
supply_16bit_register (struct regcache *regcache, int regnum, const char *buf)
{
  gdb_byte word[4];

  memcpy (word, buf, 2);
  memset (word + 2, 0, 2);
  supply_register (regcache, regnum, word);
}
#endif

#if 0
/* The store_function for the floating-point register set.  */

static void
netbsd_x86_64_store_fpregset (struct regcache *regcache, const char *buf)
{
  int i;

  /* Store the %st0 .. %st7 registers.  */
  for (i = 0; i < 8; i++)
    supply_register (regcache, I386_ST0_REGNUM + i,
                     buf + offsetof (usr_fcontext_t, ufc_reg)
		     + i * sizeof (struct ufp387_real));

  /* Store the other FPU registers.  */
  supply_16bit_register (regcache, I386_FCTRL_REGNUM,
                         buf + offsetof (usr_fcontext_t, ufc_control));
  supply_16bit_register (regcache, I386_FSTAT_REGNUM,
                         buf + offsetof (usr_fcontext_t, ufc_status));
  supply_16bit_register (regcache, I386_FTAG_REGNUM,
                         buf + offsetof (usr_fcontext_t, ufc_tag));
  supply_register (regcache, I386_FISEG_REGNUM,
                   buf + offsetof (usr_fcontext_t, ufc_inst_sel));
  supply_register (regcache, I386_FIOFF_REGNUM,
                   buf + offsetof (usr_fcontext_t, ufc_inst_off));
  supply_register (regcache, I386_FOSEG_REGNUM,
                   buf + offsetof (usr_fcontext_t, ufc_data_sel));
  supply_register (regcache, I386_FOOFF_REGNUM,
                   buf + offsetof (usr_fcontext_t, ufc_data_off));
#if !defined(LYNXOS_178)
  supply_16bit_register (regcache, I386_FOP_REGNUM,
                         buf + offsetof (usr_fcontext_t, ufc_opcode));

  /* Store the XMM registers.  */
  for (i = 0; i < 8; i++)
    supply_register (regcache, I386_XMM0_REGNUM + i,
                     buf + offsetof (usr_fcontext_t, uxmm_reg)
		     + i * sizeof (struct uxmm_register));
  supply_register (regcache, I386_MXCSR_REGNUM,
                   buf + offsetof (usr_fcontext_t, usse_mxcsr));
#endif
}
#endif

/* Implements the netbsd_target_ops.arch_setup routine.  */

static void
netbsd_x86_64_arch_setup (void)
{
  struct target_desc *tdesc
    = x86_64_create_target_description (X86_XSTATE_SSE_MASK, false, false);

  init_target_desc (tdesc, x86_64_expedite_regs);

  netbsd_tdesc = tdesc;
}

/* Description of all the x86-netbsd register sets.  */

struct netbsd_regset_info netbsd_target_regsets[] = {
  /* General Purpose Registers.  */
  {PT_GETREGS, PT_SETREGS, sizeof(struct reg),
   netbsd_x86_64_fill_gregset, netbsd_x86_64_store_gregset},
  /* Floating Point Registers.  */
#if 0
  { PTRACE_GETFPREGS, PTRACE_SETFPREGS, sizeof(usr_fcontext_t),
    netbsd_x86_64_fill_fpregset, netbsd_x86_64_store_fpregset },
#endif
  /* End of list marker.  */
  {0, 0, -1, NULL, NULL }
};

/* The netbsd_target_ops vector for x86-netbsd.  */

struct netbsd_target_ops the_low_target = {
  netbsd_x86_64_arch_setup,
};
