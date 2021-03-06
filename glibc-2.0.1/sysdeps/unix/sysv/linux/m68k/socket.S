/* Copyright (C) 1996 Free Software Foundation, Inc.
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

#include <sysdep.h>
#include <sys/socketcall.h>

#define P(a, b) P2(a, b)
#define P2(a, b) a##b

	.text
/* The socket-oriented system calls are handled unusally in Linux.
   They are all gated through the single `socketcall' system call number.
   `socketcall' takes two arguments: the first is the subcode, specifying
   which socket function is being called; and the second is a pointer to
   the arguments to the specific function.

   The .S files for the other calls just #define socket and #include this.  */

.globl P(__,socket)
ENTRY (P(__,socket))

	/* Save registers.  */
	move.l %d2, %a0

	move.l #SYS_ify (socketcall), %d0 /* System call number in %d0.  */

	/* Use ## so `socket' is a separate token that might be #define'd.  */
	move.l #P (SOCKOP_,socket), %d1	/* Subcode is first arg to syscall.  */
	lea 4(%sp), %a1			/* Address of args is 2nd arg.  */
	move.l %a1, %d2

        /* Do the system call trap.  */
	trap #0

	/* Restore registers.  */
	move.l %a0, %d2

	/* %d0 is < 0 if there was an error.  */
	tst.l %d0
	jmi syscall_error

	/* Successful; return the syscall's value.  */
	rts
PSEUDO_END (P(__,socket))

weak_alias (P(__,socket), socket)
