/* Copyright (C) 1995 Free Software Foundation, Inc.
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

#include "gmp.h"
#include "gmp-impl.h"
#include <float.h>

/* Convert a multi-precision integer of the needed number of bits and an
   integral power of two to a `long double'.  */

long double
__mpn_construct_long_double (mp_srcptr frac_ptr, int expt, int negative)
{
#error "__mpn_construct_long_double not implemented for floating point format"
}

