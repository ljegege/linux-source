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

#define __NO_M81_MATH_INLINES
#include <math.h>
#include "math_private.h"

#ifndef FUNC
#define FUNC tan
#endif
#ifndef float_type
#define float_type double
#endif

#define __CONCATX(a,b) __CONCAT(a,b)

float_type
__CONCATX(__kernel_,FUNC) (x, y, iy)
     float_type x;
     float_type y;
     int iy;
{
  float_type tan_x, tan_y;
  tan_x = __m81_u(__CONCATX(__,FUNC)) (x);
  tan_y = __m81_u(__CONCATX(__,FUNC)) (y);
  if (iy > 0)
    return (tan_x + tan_y) / (1 - tan_x * tan_y);
  else
    return (tan_x * tan_y - 1) / (tan_x + tan_y);
}
