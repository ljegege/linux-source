/* Compatibility functions for floating point formatting.
   Copyright (C) 1995, 1996, 1997 Free Software Foundation, Inc.
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
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#include <stdio.h>
#include <stdlib.h>
#include <float.h>

#ifndef FLOAT_TYPE
#define FLOAT_TYPE double
#define FUNC_PREFIX
#define FLOAT_FMT_FLAG
#define MAXDIG (DBL_DIG + DBL_MAX_10_EXP)
#endif

#define APPEND(a, b) APPEND2 (a, b)
#define APPEND2(a, b) a##b


char *
APPEND (FUNC_PREFIX, fcvt) (value, ndigit, decpt, sign)
     FLOAT_TYPE value;
     int ndigit, *decpt, *sign;
{
  static char buf[MAXDIG];

  (void) fcvt_r (value, ndigit, decpt, sign, buf, sizeof buf);

  return buf;
}

char *
APPEND (FUNC_PREFIX, ecvt) (value, ndigit, decpt, sign)
     FLOAT_TYPE value;
     int ndigit, *decpt, *sign;
{
  static char buf[MAXDIG];

  (void) ecvt_r (value, ndigit, decpt, sign, buf, sizeof buf);

  return buf;
}

char *
APPEND (FUNC_PREFIX, gcvt) (value, ndigit, buf)
     FLOAT_TYPE value;
     int ndigit;
     char *buf;
{
  sprintf (buf, "%.*" FLOAT_FMT_FLAG "g", ndigit, value);
  return buf;
}
