/* Copyright (C) 1991, 1992, 1994 Free Software Foundation, Inc.
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

#include <setjmp.h>

/* Save the current program position in ENV and return 0.  */
int
__sigsetjmp (jmp_buf env, int savemask)
{
  /* Save data registers D1 through D7.  */
  asm volatile ("movem%.l %/d1-%/d7, %0"
		: : "m" (env[0].__jmpbuf[0].__dregs[0]));

  /* Save return address in place of register A0.  */
  env[0].__jmpbuf[0].__aregs[0] = ((void **) &env)[-1];

  /* Save address registers A1 through A5.  */
  asm volatile ("movem%.l %/a1-%/a5, %0"
		: : "m" (env[0].__jmpbuf[0].__aregs[1]));

  /* Save caller's FP, not our own.  */
  env[0].__jmpbuf[0].__fp = ((void **) &env)[-2];

  /* Save caller's SP, not our own.  */
  env[0].__jmpbuf[0].__sp = (void *) &env;

#if	defined(__HAVE_68881__) || defined(__HAVE_FPU__)
  /* Save floating-point (68881) registers FP0 through FP7.  */
  asm volatile ("fmovem%.x %/fp0-%/fp7, %0"
		: : "m" (env[0].__jmpbuf[0].__fpregs[0]));
#endif

  /* Save the signal mask if requested.  */
  return __sigjmp_save (env, savemask);
}
