/* Low level support for x86 (i386 and x86-64), for gdbserver.

   Copyright (C) 2016-2019 Free Software Foundation, Inc.

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

#ifndef GDBSERVER_NETBSD_X86_TDESC_H
#define GDBSERVER_NETBSD_X86_TDESC_H

/* Note: since IPA obviously knows what ABI it's running on (i386 vs x86_64
   vs x32), it's sufficient to pass only the register set here.  This,
   together with the ABI known at IPA compile time, maps to a tdesc.  */

enum x86_netbsd_tdesc {
  X86_TDESC_MMX = 0,
  X86_TDESC_SSE = 1,
  X86_TDESC_AVX = 2,
  X86_TDESC_MPX = 3,
  X86_TDESC_AVX_MPX = 4,
  X86_TDESC_AVX_AVX512 = 5,
  X86_TDESC_AVX_MPX_AVX512_PKU = 6,
  X86_TDESC_LAST = 7,
};

#ifdef __x86_64__
const struct target_desc *amd64_netbsd_read_description (uint64_t xcr0);
#endif

const struct target_desc *i386_netbsd_read_description (uint64_t xcr0);

void initialize_low_tdesc ();

#endif /* GDBSERVER_NETBSD_X86_TDESC_H */
