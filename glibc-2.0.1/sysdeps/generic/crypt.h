/*
 * UFC-crypt: ultra fast crypt(3) implementation
 *
 * Copyright (C) 1991, 1992, 1993, 1996, 1997 Free Software Foundation, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with the GNU C Library; see the file COPYING.LIB.  If not,
 * write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * @(#)crypt.h	1.3 16 Sep 1996
 *
 */

#ifndef _CRYPT_H

#define _CRYPT_H	1
#include <features.h>

__BEGIN_DECLS

struct crypt_data
{
  char keysched[(16 * 8) / sizeof (char)];
  char sb0[32768 / sizeof (char)];
  char sb1[32768 / sizeof (char)];
  char sb2[32768 / sizeof (char)];
  char sb3[32768 / sizeof (char)];
  /* end-of-alignment-critical-data */
  char crypt_3_buf[14];
  char current_salt[2];
  long current_saltbits;
  int  direction, initialized;
};

/* Encrypt at most 8 characters from KEY using salt to perturb DES.  */
extern char *crypt __P ((__const char *__key, __const char *__salt));


/* Reentrant versions of the functions above.  The additional argument
   points to a structure where the results are placed in.  */
extern char *crypt_r __P ((__const char *__key, __const char *__salt,
			   struct crypt_data *__data));

__END_DECLS

#endif	/* crypt.h */
