/* Copyright (C) 1991, 1995, 1996 Free Software Foundation, Inc.
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

#include <errno.h>

/* Extend the process's data space by INCREMENT.
   If INCREMENT is negative, shrink data space by - INCREMENT.
   Return the address of the start of data space, or -1 for errors.  */
void *
__sbrk (increment)
     int increment;
{
  __set_errno (ENOSYS);
  return (void *) -1;
}
stub_warning (sbrk)

weak_alias (__sbrk, sbrk)
