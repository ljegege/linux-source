/* Copyright (C) 1994 Free Software Foundation, Inc.
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

#define MOVE(x,y)	mov x, y

#define LOSE asm volatile ("call_pal 0") /* halt */

#define START_MACHDEP \
  asm ("_start:	mov	$30, $16\n" /* Put initial SP in a0.  */	      \
       "	br	$27, 1f\n" /* Load GP from PC.  */		      \
       "1:	ldgp	$29, 0($27)\n"					      \
       "	jmp	$26, _start0");	/* Jump to _start0; don't return.  */
#define START_ARGS	char **sparg
#define SNARF_ARGS(argc, argv, envp) \
  (envp = &(argv = &sparg[1])[(argc = *(int *) sparg) + 1])

#define CALL_WITH_SP(fn, sp) \
  ({ register long int __fn = (long int) fn, __sp = (long int) sp; \
     asm volatile ("mov %0,$30; jmp $31, (%1); ldgp $29, 0(%1)" \
		   : : "r" (__sp), "r" (__fn)); })

#define ENTRY(name) LEAF(name, ***loser no arg count***)

#define STACK_GROWTH_DOWN

#include_next <sysdep.h>
