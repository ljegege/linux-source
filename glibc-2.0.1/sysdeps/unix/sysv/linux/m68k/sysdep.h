/* Copyright (C) 1996 Free Software Foundation, Inc.
This file is part of the GNU C Library.
Written by Andreas Schwab, <schwab@issan.informatik.uni-dortmund.de>,
December 1995.

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

#include <sysdeps/unix/sysdep.h>

/* For Linux we can use the system call table in the header file
	/usr/include/asm/unistd.h
   of the kernel.  But these symbols do not follow the SYS_* syntax
   so we have to redefine the `SYS_ify' macro here.  */
#undef SYS_ify
#ifdef __STDC__
# define SYS_ify(syscall_name)	__NR_##syscall_name
#else
# define SYS_ify(syscall_name)	__NR_/**/syscall_name
#endif

#ifdef ASSEMBLER

/* Define an entry point visible from C.  */
#define	ENTRY(name)							      \
  .globl name;								      \
  .type name, @function;						      \
  .align 4;								      \
  C_LABEL(name)								      \
  CALL_MCOUNT

#undef END
#define END(name) .size name, . - name

/* If compiled for profiling, call `_mcount' at the start of each function.  */
#ifdef	PROF
/* The mcount code relies on a normal frame pointer being on the stack
   to locate our caller, so push one just for its benefit.  */
#define CALL_MCOUNT \
  move.l %fp, -(%sp); move.l %sp, %fp;					      \
  jbsr JUMPTARGET (_mcount);						      \
  move.l (%sp)+, %fp;
#else
#define CALL_MCOUNT		/* Do nothing.  */
#endif

#ifdef PIC
#define JUMPTARGET(name)	name##@PLTPC
#else
#define JUMPTARGET(name)	name
#endif

/* Since C identifiers are not normally prefixed with an underscore
   on this system, the asm identifier `syscall_error' intrudes on the
   C name space.  Make sure we use an innocuous name.  */
#define	syscall_error	__syscall_error

/* Linux uses a negative return value to indicate syscall errors, unlike
   most Unices, which use the condition codes' carry flag.

   Since version 2.1 the return value of a system call might be negative
   even if the call succeeded.  E.g., the `lseek' system call might return
   a large offset.  Therefore we must not anymore test for < 0, but test
   for a real error by making sure the value in %d0 is a real error
   number.  Linus said he will make sure the no syscall returns a value
   in -1 .. -4095 as a valid result so we can savely test with -4095.  */
#define	PSEUDO(name, syscall_name, args)				      \
  .text;								      \
  ENTRY (name)								      \
    DO_CALL (&SYS_ify (syscall_name), args);				      \
    cmp.l &-4095, %d0;							      \
    jcc syscall_error

#undef PSEUDO_END
#define PSEUDO_END(name)						      \
  SYSCALL_ERROR_HANDLER;						      \
  END (name)

#ifdef PIC
/* Store (- %d0) into errno through the GOT.  */
#ifdef _LIBC_REENTRANT
#define SYSCALL_ERROR_HANDLER						      \
syscall_error:								      \
    move.l (errno@GOTPC, %pc), %a0;					      \
    neg.l %d0;								      \
    move.l %d0, (%a0);							      \
    move.l %d0, -(%sp);							      \
    jbsr __errno_location@PLTPC;					      \
    move.l (%sp)+, (%a0);						      \
    move.l &-1, %d0;							      \
    /* Copy return value to %a0 for syscalls that are declared to return      \
       a pointer (e.g., mmap).  */					      \
    move.l %d0, %a0;							      \
    rts;
#else
#define SYSCALL_ERROR_HANDLER						      \
syscall_error:								      \
    move.l (errno@GOTPC, %pc), %a0;					      \
    neg.l %d0;								      \
    move.l %d0, (%a0);							      \
    move.l &-1, %d0;							      \
    /* Copy return value to %a0 for syscalls that are declared to return      \
       a pointer (e.g., mmap).  */					      \
    move.l %d0, %a0;							      \
    rts;
#endif /* _LIBC_REENTRANT */
#else
#define SYSCALL_ERROR_HANDLER	/* Nothing here; code in sysdep.S is used.  */
#endif /* PIC */

/* Linux takes system call arguments in registers:

	syscall number	%d0	     call-clobbered
	arg 1		%d1	     call-clobbered
	arg 2		%d2	     call-saved
	arg 3		%d3	     call-saved
	arg 4		%d4	     call-saved
	arg 5		%d5	     call-saved

   The stack layout upon entering the function is:

	20(%sp)		Arg# 5
	16(%sp)		Arg# 4
	12(%sp)		Arg# 3
	 8(%sp)		Arg# 2
	 4(%sp)		Arg# 1
	  (%sp)		Return address

   (Of course a function with say 3 arguments does not have entries for
   arguments 4 and 5.)

   Separate move's are faster than movem, but need more space.  Since
   speed is more important, we don't use movem.  Since %a0 and %a1 are
   scratch registers, we can use them for saving as well.  */

#define DO_CALL(syscall, args)				      		      \
    move.l syscall, %d0;						      \
    DOARGS_##args							      \
    trap &0;								      \
    UNDOARGS_##args

#define	DOARGS_0	/* No arguments to frob.  */
#define	UNDOARGS_0	/* No arguments to unfrob.  */
#define	_DOARGS_0(n)	/* No arguments to frob.  */

#define	DOARGS_1	_DOARGS_1 (4)
#define	_DOARGS_1(n)	move.l n(%sp), %d1; _DOARGS_0 (n)
#define	UNDOARGS_1	UNDOARGS_0

#define	DOARGS_2	_DOARGS_2 (8)
#define	_DOARGS_2(n)	move.l %d2, %a0; move.l n(%sp), %d2; _DOARGS_1 (n-4)
#define	UNDOARGS_2	UNDOARGS_1; move.l %a0, %d2

#define DOARGS_3	_DOARGS_3 (12)
#define _DOARGS_3(n)	move.l %d3, %a1; move.l n(%sp), %d3; _DOARGS_2 (n-4)
#define UNDOARGS_3	UNDOARGS_2; move.l %a1, %d3

#define DOARGS_4	_DOARGS_4 (16)
#define _DOARGS_4(n)	move.l %d4, -(%sp); move.l n+4(%sp), %d4; _DOARGS_3 (n)
#define UNDOARGS_4	UNDOARGS_3; move.l (%sp)+, %d4

#define DOARGS_5	_DOARGS_5 (20)
#define _DOARGS_5(n)	move.l %d5, -(%sp); move.l n+4(%sp), %d5; _DOARGS_4 (n)
#define UNDOARGS_5	UNDOARGS_4; move.l (%sp)+, %d5


#define	ret	rts
#if 0 /* Not used by Linux */
#define	r0	%d0
#define	r1	%d1
#define	MOVE(x,y)	movel x , y
#endif

#endif	/* ASSEMBLER */
