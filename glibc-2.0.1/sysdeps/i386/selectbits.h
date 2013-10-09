/* Copyright (C) 1997 Free Software Foundation, Inc.
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

#ifndef _SELECTBITS_H
#define _SELECTBITS_H	1

#if defined __GNUC__ && __GNUC__ >= 2

#define __FD_ZERO(fdsetp) \
  __asm__ __volatile__ ("cld ; rep ; stosl"				      \
			: "=m" (*(__fd_set *) (fdsetp))			      \
			: "a" (0), "c" (sizeof (__fd_set)		      \
					/ sizeof (__fd_mask)),		      \
			  "D" ((__fd_set *) (fdsetp))			      \
			:"cx","di")
#define __FD_SET(fd, fdsetp) \
  __asm__ __volatile__ ("btsl %1,%0"					      \
			: "=m" (*(__fd_set *) (fdsetp))			      \
			: "r" ((int) (fd)))
#define __FD_CLR(fd, fdsetp) \
  __asm__ __volatile__ ("btrl %1,%0"					      \
			: "=m" (*(__fd_set *) (fdsetp))			      \
			: "r" ((int) (fd)))
#define __FD_ISSET(fd, fdsetp) \
  (__extension__							      \
   ({unsigned char __result;						      \
     __asm__ __volatile__ ("btl %1,%2 ; setb %0"			      \
			   : "=q" (__result)				      \
			   : "r" ((int) (fd)), "m" (*(__fd_set *) (fdsetp))); \
     __result; }))

#else	/* ! GNU CC */

#define __FD_ZERO(set)  \
  ((void) memset ((__ptr_t) (set), 0, sizeof (fd_set)))
#define __FD_SET(d, set)	((set)->fds_bits[__FDELT(d)] |= __FDMASK(d))
#define __FD_CLR(d, set)	((set)->fds_bits[__FDELT(d)] &= ~__FDMASK(d))
#define __FD_ISSET(d, set)	((set)->fds_bits[__FDELT(d)] & __FDMASK(d))

#endif	/* GNU CC */

#endif /* selectbits.h */
