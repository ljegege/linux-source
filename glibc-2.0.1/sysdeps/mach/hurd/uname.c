/* Copyright (C) 1992, 1993, 1994, 1996 Free Software Foundation, Inc.
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

#include <unistd.h>
#include <sys/utsname.h>
#include <hurd.h>
#include <hurd/startup.h>

int
uname (struct utsname *uname)
{
  error_t err;

  if (err = __USEPORT (PROC, __proc_uname (port, uname)))
    return __hurd_fail (err);

  /* Fill in the hostname, which the proc server doesn't know.  */
  err = errno;
  if (__gethostname (uname->nodename, sizeof uname->nodename) < 0)
    {
      if (errno == ENAMETOOLONG)
	/* Ignore the error of the buffer being too small.
	   It is of fixed size, nothing to do about it.  */
	errno = err;
      else
	return -1;
    }

  return 0;
}
