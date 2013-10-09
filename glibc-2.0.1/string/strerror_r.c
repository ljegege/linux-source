/* Copyright (C) 1991, 1993, 1994, 1995, 1996 Free Software Foundation, Inc.
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
#include <string.h>

extern char *_strerror_internal __P ((int, char *, size_t));

/* Return a string describing the errno code in ERRNUM.  At most BUFLEN
   characters of the result will be placed in STRERRBUF.  */
char *
__strerror_r (int errnum, char *buf, size_t buflen)
{
  return _strerror_internal (errnum, buf, buflen);
}
weak_alias (__strerror_r, strerror_r)
