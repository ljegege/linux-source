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
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>

/* Open FILE with access OFLAG.  If OFLAG includes O_CREAT,
   a third argument is the file protection.  */
int
__open (file, oflag)
     const char *file;
     int oflag;
{
  int mode;

  if (file == NULL)
    {
      __set_errno (EINVAL);
      return -1;
    }

  if (oflag & O_CREAT)
    {
      va_list arg;
      va_start(arg, oflag);
      mode = va_arg(arg, int);
      va_end(arg);
    }

  __set_errno (ENOSYS);
  return -1;
}
stub_warning (open)

weak_alias (__open, open)
