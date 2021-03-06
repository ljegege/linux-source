/* ANSI C `remove' function to delete a file or directory.  POSIX.1 version.
Copyright (C) 1995, 1996 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <unistd.h>

int
remove (file)
     const char *file;
{
  int save;

  save = errno;
  if (__rmdir (file) == 0)
    return 0;
  else if (errno == ENOTDIR && __unlink (file) == 0)
    {
      __set_errno (save);
      return 0;
    }

  return -1;
}
