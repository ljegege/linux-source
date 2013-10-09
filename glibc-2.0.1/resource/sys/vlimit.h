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

#ifndef _SYS_VLIMIT_H

#define _SYS_VLIMIT_H	1
#include <features.h>

__BEGIN_DECLS

/* This interface is obsolete, and is superseded by <sys/resource.h>.  */

/* Kinds of resource limit.  */
enum __vlimit_resource
{
  /* Setting this non-zero makes it impossible to raise limits.
     Only the super-use can set it to zero.

     This is not implemented in recent versions of BSD, nor by
     the GNU C library.  */
  LIM_NORAISE,

  /* CPU time available for each process (seconds).  */
  LIM_CPU,

  /* Largest file which can be created (bytes).  */
  LIM_FSIZE,

  /* Maximum size of the data segment (bytes).  */
  LIM_DATA,

  /* Maximum size of the stack segment (bytes).  */
  LIM_STACK,

  /* Largest core file that will be created (bytes).  */
  LIM_CORE,

  /* Resident set size (bytes).  */
  LIM_MAXRSS
};

/* This means no limit.  */
#define INFINITY 0x7fffffff


/* Set the soft limit for RESOURCE to be VALUE.
   Returns 0 for success, -1 for failure.  */
extern int vlimit __P ((enum __vlimit_resource __resource, int __value));


__END_DECLS

#endif /* vlimit.h  */