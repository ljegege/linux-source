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

#include "libioP.h"
#include "stdio.h"

#undef _IO_putc

int
_IO_putc (c, fp)
     int c;
     _IO_FILE *fp;
{
  int result;
  CHECK_FILE (fp, EOF);
  __libc_cleanup_region_start ((void (*) __P ((void *))) _IO_funlockfile, fp);
  _IO_flockfile (fp);
  result = _IO_putc_unlocked (c, fp);
  __libc_cleanup_region_end (1);
  return result;
}
#undef putc
weak_alias (_IO_putc, putc)

#ifdef _IO_MTSAFE_IO
# undef putc_locked

weak_alias (putc, putc_locked)
#endif
