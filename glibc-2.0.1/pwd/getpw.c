/* Copyright (C) 1991, 1992, 1996 Free Software Foundation, Inc.
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

#include <alloca.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>


/* Re-construct the password-file line for the given uid
   in the given buffer.  This knows the format that the caller
   will expect, but this need not be the format of the password file.  */

int __getpw __P ((__uid_t uid, char *buf));

int
__getpw (uid, buf)
     __uid_t uid;
     char *buf;
{
  size_t buflen;
  char *tmpbuf;
  struct passwd resbuf, *p;

  if (buf == NULL)
    {
      __set_errno (EINVAL);
      return -1;
    }

  buflen = __sysconf (_SC_GETPW_R_SIZE_MAX);
  tmpbuf = alloca (buflen);

  if (getpwuid_r (uid, &resbuf, tmpbuf, buflen, &p) < 0)
    return -1;

  if (sprintf (buf, "%s:%s:%u:%u:%s:%s:%s", p->pw_name, p->pw_passwd,
	       p->pw_uid, p->pw_gid, p->pw_gecos, p->pw_dir, p->pw_shell) < 0)
    return -1;

  return 0;
}
weak_alias (__getpw, getpw)
