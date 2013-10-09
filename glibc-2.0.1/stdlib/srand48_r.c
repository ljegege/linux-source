/* Copyright (C) 1995, 1996 Free Software Foundation, Inc.
This file is part of the GNU C Library.
Contributed by Ulrich Drepper <drepper@gnu.ai.mit.edu>, August 1995.

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
not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.  */

#include <stdlib.h>
#include <limits.h>

int
srand48_r (seedval, buffer)
     long seedval;
     struct drand48_data *buffer;
{
  /* The standards say we only have 32 bits.  */
  if (sizeof (long) > 4)
    seedval &= 0xffffffffl;

#if (USHRT_MAX == 0xffffU)
  buffer->X[2] = seedval >> 16;
  buffer->X[1] = seedval & 0xffffl;
  buffer->X[0] = 0x330e;
#else
  buffer->X[2] = seedval;
  buffer->X[1] = 0x330e0000UL;
  buffer->X[0] = 0;
#endif

  return 0;
}
