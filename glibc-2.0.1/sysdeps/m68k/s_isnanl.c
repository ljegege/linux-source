/* Copyright (C) 1991, 1992, 1995 Free Software Foundation, Inc.
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

#include <math.h>
#include "ieee754.h"

#undef __isnanl
#undef isnanl


/* Return nonzero if VALUE is not a number.  */
int
__isnanl (long double value)
{
  union ieee854_long_double u;

  u.d = value;

  /* IEEE 854 NaN's have the maximum possible
     exponent and a nonzero mantissa.  In Motorola's
     interpretation the integer bit is ignored.  */
  return ((u.ieee.exponent & 0x7fff) == 0x7fff &&
	  ((u.ieee.mantissa0 & 0x7fffffff) != 0 || u.ieee.mantissa1 != 0));
}

weak_alias (__isnanl, isnanl);
