/* Machine-dependent details of interruptible RPC messaging.  i386 version.
Copyright (C) 1995, 1996 Free Software Foundation, Inc.
This file is part of the GNU C Library.

The GNU C Library is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

The GNU C Library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.

You should have received a copy of the GNU Library General Public
License along with the GNU C Library; see the file COPYING.LIB.  If
not, write to the Free Software Foundation, Inc., 675 Mass Ave,
Cambridge, MA 02139, USA.  */


#define INTR_MSG_TRAP(msg, option, send_size, rcv_size, rcv_name, timeout, notify) \
({									      \
  error_t err;								      \
  asm (".globl _hurd_intr_rpc_msg_do_trap\n" 				      \
       ".globl _hurd_intr_rpc_msg_in_trap\n"				      \
       ".globl _hurd_intr_rpc_msg_cx_sp\n"				      \
       ".globl _hurd_intr_rpc_msg_sp_restored\n"			      \
       "				movl %%esp, %%ecx\n"		      \
       "				leal %1, %%esp\n"		      \
       "_hurd_intr_rpc_msg_cx_sp:	movl $-25, %%eax\n"		      \
       "_hurd_intr_rpc_msg_do_trap:	lcall $7, $0 # status in %0\n"	      \
       "_hurd_intr_rpc_msg_in_trap:	movl %%ecx, %%esp\n"		      \
       "_hurd_intr_rpc_msg_sp_restored:"				      \
       : "=a" (err) : "m" ((&msg)[-1]) : "%ecx");			      \
  err;									      \
})


static void inline
INTR_MSG_BACK_OUT (struct i386_thread_state *state)
{
  extern const void _hurd_intr_rpc_msg_cx_sp;
  if (state->eip >= (natural_t) &_hurd_intr_rpc_msg_cx_sp)
    state->uesp = state->ecx;
  else
    state->ecx = state->uesp;
}

#include "hurdfault.h"

static inline int
SYSCALL_EXAMINE (struct i386_thread_state *state, int *callno)
{
  struct { unsigned int c[2]; } *p = (void *) (state->eip - 7);
  int result;
  if (_hurdsig_catch_memory_fault (p))
    return 0;
  if (result = p->c[0] == 0x0000009a && (p->c[1] & 0x00ffffff) == 0x00000700)
    /* The PC is just after an `lcall $7,$0' instruction.
       This is a system call in progress; %eax holds the call number.  */
    *callno = state->eax;
  _hurdsig_end_catch_fault ();
  return result;
}


struct mach_msg_trap_args
  {
    void *retaddr;		/* Address mach_msg_trap will return to.  */
    /* This is the order of arguments to mach_msg_trap.  */
    mach_msg_header_t *msg;
    mach_msg_option_t option;
    mach_msg_size_t send_size;
    mach_msg_size_t rcv_size;
    mach_port_t rcv_name;
    mach_msg_timeout_t timeout;
    mach_port_t notify;
  };


static inline mach_port_t
MSG_EXAMINE (struct i386_thread_state *state, int *msgid)
{
  const struct mach_msg_trap_args *args = (const void *) state->uesp;
  mach_msg_header_t *msg;
  mach_port_t send_port;

  if (_hurdsig_catch_memory_fault (args))
    return MACH_PORT_NULL;
  msg = args->msg;
  _hurdsig_end_catch_fault ();

  if (_hurdsig_catch_memory_fault (msg))
    return MACH_PORT_NULL;
  send_port = msg->msgh_remote_port;
  *msgid = msg->msgh_id;
  _hurdsig_end_catch_fault ();

  return send_port;
}
