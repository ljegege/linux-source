/* Copyright (C) 1996, 1997 Free Software Foundation, Inc.
   Contributed by Andreas Schwab (schwab@issan.informatik.uni-dortmund.de)

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* clone is even more special than fork as it mucks with stacks
   and invokes a function in the right context after its all over.  */

#include <sysdep.h>
#define _ERRNO_H	1
#include <errnos.h>

/* int clone(int (*fn)(void *arg), void *child_stack, int flags, void *arg); */

        .text
ENTRY (__clone)

	/* Sanity check arguments.  */
	movel	#-EINVAL, %d0
	movel	4(%sp), %a0		/* no NULL function pointers */
	tstl	%a0
	jeq	syscall_error
	movel	8(%sp), %a1		/* no NULL stack pointers */
	tstl	%a1
	jeq	syscall_error

	/* Allocate space and copy the argument onto the new stack.  */
	movel	16(%sp), -(%a1)

	/* Do the system call */
	exg	%d2, %a1		/* save %d2 and get stack pointer */
	movel	12(%sp), %d1		/* get flags */
	movel	#SYS_ify (clone), %d0
	trap	#0
	exg	%d2, %a1		/* restore %d2 */

	tstl	%d0
	jmi	syscall_error
	jeq	thread_start

	rts

thread_start:
	subl	%fp, %fp	/* terminate the stack frame */
	jsr	(%a0)
	movel	%d0, -(%sp)
	jbsr	JUMPTARGET (_exit)

PSEUDO_END (__clone)

weak_alias (__clone, clone)
