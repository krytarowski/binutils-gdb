/* GNU/Linux/x86-64 specific target description, for the remote server
   for GDB.
   Copyright (C) 2017-2019 Free Software Foundation, Inc.

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
#include "tdesc.h"
#include "netbsd-x86-tdesc.h"
#include "arch/i386.h"
#include "common/x86-xstate.h"
#ifdef __x86_64__
#include "arch/amd64.h"
#endif
#include "x86-tdesc.h"

/* Return the right x86_netbsd_tdesc index for a given XCR0.  Return
   X86_TDESC_LAST if can't find a match.  */

static enum x86_netbsd_tdesc
xcr0_to_tdesc_idx (uint64_t xcr0)
{
  if (xcr0 & X86_XSTATE_PKRU)
    {
	return X86_TDESC_AVX_MPX_AVX512_PKU;
    }
  else if (xcr0 & X86_XSTATE_AVX512)
    return X86_TDESC_AVX_AVX512;
  else if ((xcr0 & X86_XSTATE_AVX_MPX_MASK) == X86_XSTATE_AVX_MPX_MASK)
    {
	return X86_TDESC_AVX_MPX;
    }
  else if (xcr0 & X86_XSTATE_MPX)
    {
	return X86_TDESC_MPX;
    }
  else if (xcr0 & X86_XSTATE_AVX)
    return X86_TDESC_AVX;
  else if (xcr0 & X86_XSTATE_SSE)
    return X86_TDESC_SSE;
  else if (xcr0 & X86_XSTATE_X87)
    return X86_TDESC_MMX;
  else
    return X86_TDESC_LAST;
}

#if defined __i386__ || !defined IN_PROCESS_AGENT

static struct target_desc *i386_tdescs[X86_TDESC_LAST] = { };

/* Return the target description according to XCR0.  */

const struct target_desc *
i386_netbsd_read_description (uint64_t xcr0)
{
  enum x86_netbsd_tdesc idx = xcr0_to_tdesc_idx (xcr0);

  if (idx == X86_TDESC_LAST)
    return NULL;

  struct target_desc **tdesc = &i386_tdescs[idx];

  if (*tdesc == NULL)
    {
      *tdesc = i386_create_target_description (xcr0, true, false);

      init_target_desc (*tdesc, i386_expedite_regs);
    }

  return *tdesc;;
}
#endif

#ifdef __x86_64__

static target_desc *amd64_tdescs[X86_TDESC_LAST] = { };

const struct target_desc *
amd64_netbsd_read_description (uint64_t xcr0)
{
  enum x86_netbsd_tdesc idx = xcr0_to_tdesc_idx (xcr0);

  if (idx == X86_TDESC_LAST)
    return NULL;

  struct target_desc **tdesc = NULL;

  tdesc = &amd64_tdescs[idx];

  if (*tdesc == NULL)
    {
      *tdesc = amd64_create_target_description (xcr0, false, true, true);

      init_target_desc (*tdesc, amd64_expedite_regs);
    }
  return *tdesc;
}

#endif
