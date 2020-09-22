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

#ifndef GDBSERVER_NETBSD_LOW_H
#define GDBSERVER_NETBSD_LOW_H

struct regcache;
struct target_desc;

/*  Some information relative to a given register set.   */

struct netbsd_regset_info
{
  /* The ptrace request needed to get/set registers of this set.  */
  int get_request, set_request;
  /* The size of the register set.  */
  int size;
  /* Fill the buffer BUF from the contents of the given REGCACHE.  */
  void (*fill_function) (struct regcache *regcache, char *buf);
  /* Store the register value in BUF in the given REGCACHE.  */
  void (*store_function) (struct regcache *regcache, const char *buf);
};

/* Target ops definitions for a NetBSD target.  */

class netbsd_process_target : public process_stratum_target
{
public:

  int create_inferior (const char *program,
		       const std::vector<char *> &program_args) override;

  void post_create_inferior () override;

  int attach (unsigned long pid) override;

  int kill (process_info *proc) override;

  int detach (process_info *proc) override;

  void mourn (process_info *proc) override;

  void join (int pid) override;

  bool thread_alive (ptid_t pid) override;

  void resume (thread_resume *resume_info, size_t n) override;

  ptid_t wait (ptid_t ptid, target_waitstatus *status,
	       int options) override;

  void fetch_registers (regcache *regcache, int regno) override;

  void store_registers (regcache *regcache, int regno) override;

  int read_memory (CORE_ADDR memaddr, unsigned char *myaddr,
		   int len) override;

  int write_memory (CORE_ADDR memaddr, const unsigned char *myaddr,
		    int len) override;

  void request_interrupt () override;

  bool supports_read_auxv () override;

  int read_auxv (CORE_ADDR offset, unsigned char *myaddr,
		 unsigned int len) override;

  bool supports_hardware_single_step () override;

  const gdb_byte *sw_breakpoint_from_kind (int kind, int *size) override;

  bool supports_z_point_type (char z_type) override;

  int insert_point (enum raw_bkpt_type type, CORE_ADDR addr,
		    int size, struct raw_breakpoint *bp) override;

  int remove_point (enum raw_bkpt_type type, CORE_ADDR addr,
		    int size, struct raw_breakpoint *bp) override;

  bool stopped_by_sw_breakpoint () override;

  bool supports_qxfer_siginfo () override;

  int qxfer_siginfo (const char *annex, unsigned char *readbuf,
		     unsigned const char *writebuf, CORE_ADDR offset,
		     int len) override;

  bool supports_stopped_by_sw_breakpoint () override;

  bool supports_non_stop () override;

  bool supports_multi_process () override;

  bool supports_fork_events () override;

  bool supports_vfork_events () override;

  bool supports_exec_events () override;

  bool supports_disable_randomization () override;

  bool supports_qxfer_libraries_svr4 () override;

  int qxfer_libraries_svr4 (const char*, unsigned char*, const unsigned char*,
			    CORE_ADDR, int) override;

  bool supports_pid_to_exec_file () override;

  char *pid_to_exec_file (int pid) override;

  const char *thread_name (ptid_t thread) override;

  bool supports_catch_syscall () override;

protected:

  /* Call add_process with the given parameters, and initialize
     the process' private data.  */
  void netbsd_add_process (int pid, int attached);

  /* Callback used by fork_inferior to start tracing the inferior.  */
  void netbsd_ptrace_fun ();
  
  /* Read one pointer from MEMADDR in the inferior.  */

  int read_one_ptr (CORE_ADDR memaddr, CORE_ADDR *ptr, int ptr_size);

  /* Return true if FILE is a 64-bit ELF file,
     false if the file is not a 64-bit ELF file,
     and error if the file is not accessible or doesn't exist.  */
  bool elf_64_file_p (const char *file);

  /* Returns true if GDB is interested in any child syscalls.  */
  bool gdb_catching_syscalls_p (pid_t pid);

  /* Returns true if GDB is interested in the reported SYSNO syscall.  */
  bool netbsd_catch_this_syscall (int sysno);

  /* Helper function for child_wait and the derivatives of child_wait.                                                                              
   HOSTSTATUS is the waitstatus from wait() or the equivalent; store our                                                                          
   translation of that in OURSTATUS.  */
  void netbsd_store_waitstatus (struct target_waitstatus *ourstatus, int hoststatus);

  /* Implement a safe wrapper around waitpid().  */
  pid_t netbsd_waitpid (ptid_t ptid, struct target_waitstatus *ourstatus, int options);

  /* Implement the wait target_ops method.                                                                                                          
     
     Wait for the child specified by PTID to do something.  Return the                                                                              
     process ID of the child, or MINUS_ONE_PTID in case of error; store                                                                             
     the status in *OURSTATUS.  */
  ptid_t netbsd_wait (ptid_t ptid, struct target_waitstatus *ourstatus,
		      int target_options);
  
  /* Read the AUX Vector for the specified PID, wrapping the ptrace(2) call                                                                         
     with the PIOD_READ_AUXV operation and using the PT_IO standard input                                                                           
     and output arguments.  */
  size_t netbsd_read_auxv(pid_t pid, void *offs, void *addr, size_t len);

  /* Extract &phdr and num_phdr in the inferior.  Return 0 on success.  */
  int get_phdr_phnum_from_proc_auxv (const pid_t pid,
				     CORE_ADDR *phdr_memaddr,
				     int *num_phdr);

  /* Return &_DYNAMIC (via PT_DYNAMIC) in the inferior, or 0 if not present.  */
  CORE_ADDR get_dynamic (const pid_t pid);

  /* Return &_r_debug in the inferior, or -1 if not present.  Return value                                                                          
     can be 0 if the inferior does not yet have the library list initialized.                                                                       
     We look for DT_MIPS_RLD_MAP first.  MIPS executables use this instead of                                                                       
     DT_DEBUG, although they sometimes contain an unused DT_DEBUG entry too.  */

  CORE_ADDR get_r_debug (const pid_t pid);

  /* **************************************************************************/
  
  /* The architecture-specific "low" methods are listed below.  */

  /* Return the information to access registers.  This has public
     visibility because proc-service uses it.  */
  virtual const netbsd_regset_info *get_regs_info () = 0;
    
  /* Architecture-specific setup for the current thread.  */
  virtual void low_arch_setup () = 0;
};

extern netbsd_process_target *the_netbsd_target;

#endif /* GDBSERVER_NETBSD_LOW_H */
