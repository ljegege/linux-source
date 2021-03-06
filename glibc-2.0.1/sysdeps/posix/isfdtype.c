/* isfdtype - Determine whether descriptor has given property.
Copyright (C) 1996 Free Software Foundation, Inc.
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
not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.  */

#include <errno.h>
#include <sys/stat.h>
#include <sys/socket.h>

int
isfdtype (int fildes, int fdtype)
{
  struct stat st;
  int result;

  {
    int save_error = errno;
    result = fstat (fildes, &st);
    __set_errno (save_error);
  }

  return result ?: (st.st_mode & S_IFMT) == fdtype;
}
