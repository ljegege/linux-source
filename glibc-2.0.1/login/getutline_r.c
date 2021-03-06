/* Copyright (C) 1996 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>
   and Paul Janzen <pcj@primenet.com>, 1996.

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

#include <errno.h>
#include <libc-lock.h>
#include <string.h>
#include <unistd.h>
#include <utmp.h>

#include "utmp-private.h"


/* We have to use the lock in getutent_r.c.  */
__libc_lock_define (extern, __libc_utmp_lock)

/* The jump table is also in getutent_r.c.  */
extern struct utfuncs *__libc_utmp_jump_table;


int
__getutline_r (const struct utmp *line, struct utmp *buffer,
	       struct utmp **result)
{
  int retval = -1;

  __libc_lock_lock (__libc_utmp_lock);

  /* Not yet initialized.  */
  if ((*__libc_utmp_jump_table->setutent) (0))
    retval = (*__libc_utmp_jump_table->getutline_r) (line, buffer, result);
  else
    *result = NULL;

  __libc_lock_unlock (__libc_utmp_lock);

  return retval;
}
weak_alias (__getutline_r, getutline_r)
