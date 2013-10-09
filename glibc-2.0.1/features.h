/* Copyright (C) 1991, 92, 93, 95, 96, 97 Free Software Foundation, Inc.
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

#ifndef	_FEATURES_H

#define	_FEATURES_H	1

/* These are defined by the user (or the compiler)
   to specify the desired environment:

   __STRICT_ANSI__	ISO Standard C.
   _POSIX_SOURCE	IEEE Std 1003.1.
   _POSIX_C_SOURCE	If ==1, like _POSIX_SOURCE; if >=2 add IEEE Std 1003.2;
			if >=199309L, add IEEE Std 1003.1b-1993
   _XOPEN_SOURCE	Includes POSIX and XPG things.
   _XOPEN_SOURCE_EXTENDED XPG things and X/Open Unix extensions.
   _BSD_SOURCE		ISO C, POSIX, and 4.3BSD things.
   _SVID_SOURCE		ISO C, POSIX, and SVID things.
   _GNU_SOURCE		All of the above, plus GNU extensions.
   _REENTRANT		Select additionally reentrant object.
   _THREAD_SAFE		Same as _REENTRANT, often used by other systems.

   The `-ansi' switch to the GNU C compiler defines __STRICT_ANSI__.
   If none of these are defined, the default is all but _GNU_SOURCE.
   If more than one of these are defined, they accumulate.
   For example __STRICT_ANSI__, _POSIX_SOURCE and _POSIX_C_SOURCE
   together give you ISO C, 1003.1, and 1003.2, but nothing else.

   These are defined by this file and are used by the
   header files to decide what to declare or define:

   __USE_POSIX		Define IEEE Std 1003.1 things.
   __USE_POSIX2		Define IEEE Std 1003.2 things.
   __USE_POSIX199309	Define IEEE Std 1003.1b things.
   __USE_XOPEN		Define XPG things.
   __USE_XOPEN_EXTENDED	Define X/Open Unix things.
   __USE_BSD		Define 4.3BSD things.
   __USE_SVID		Define SVID things.
   __USE_MISC		Define things common to BSD and System V Unix.
   __USE_GNU		Define GNU extensions.
   __USE_REENTRANT	Define reentrant/thread-safe *_r functions.
   __FAVOR_BSD		Favor 4.3BSD things in cases of conflict.

   The macros `__GNU_LIBRARY__', `__GLIBC__', and `__GLIBC_MINOR__' are
   defined by this file unconditionally.  `__GNU_LIBRARY__' is provided
   only for compatibility.  All new code should use the other symbols
   to test for features.

   All macros listed above as possibly being defined by this file are
   explicitly undefined if they are not explicitly defined.
   Feature-test macros that are not defined by the user or compiler
   but are implied by the other feature-test macros defined (or by the
   lack of any definitions) are defined by the file.  */


/* Undefine everything, so we get a clean slate.  */
#undef	__USE_POSIX
#undef	__USE_POSIX2
#undef	__USE_POSIX199309
#undef	__USE_XOPEN
#undef	__USE_XOPEN_EXTENDED
#undef	__USE_BSD
#undef	__USE_SVID
#undef	__USE_MISC
#undef	__USE_GNU
#undef	__USE_REENTRANT
#undef	__FAVOR_BSD
#undef	__KERNEL_STRICT_NAMES

/* Suppress kernel-name space pollution unless user expressedly asks
   for it.  */
#ifndef _LOOSE_KERNEL_NAMES
# define __KERNEL_STRICT_NAMES
#endif

/* Always use ISO C things.  */
#define	__USE_ANSI	1


/* If _BSD_SOURCE was defined by the user, favor BSD over POSIX.  */
#if defined _BSD_SOURCE && \
    !(defined _POSIX_SOURCE || defined _POSIX_C_SOURCE || \
      defined _XOPEN_SOURCE || defined _XOPEN_SOURCE_EXTENDED || \
      defined _GNU_SOURCE || defined _SVID_SOURCE)
# define __FAVOR_BSD	1
#endif

/* If _GNU_SOURCE was defined by the user, turn on all the other features.  */
#ifdef _GNU_SOURCE
#undef	_POSIX_SOURCE
#define	_POSIX_SOURCE	1
#undef	_POSIX_C_SOURCE
#define	_POSIX_C_SOURCE	199309L
#undef	_XOPEN_SOURCE
#define	_XOPEN_SOURCE	1
#undef	_XOPEN_SOURCE_EXTENDED
#define	_XOPEN_SOURCE_EXTENDED	1
#undef	_BSD_SOURCE
#define	_BSD_SOURCE	1
#undef	_SVID_SOURCE
#define	_SVID_SOURCE	1
#endif

/* If nothing (other than _GNU_SOURCE) is defined,
   define _BSD_SOURCE and _SVID_SOURCE.  */
#if (!defined __STRICT_ANSI__ && !defined _POSIX_SOURCE && \
     !defined _POSIX_C_SOURCE && !defined _XOPEN_SOURCE && \
     !defined _XOPEN_SOURCE_EXTENDED && !defined _BSD_SOURCE && \
     !defined _SVID_SOURCE)
#define	_BSD_SOURCE	1
#define	_SVID_SOURCE	1
#endif

/* If none of the ANSI/POSIX macros are defined, use POSIX.1 and POSIX.2
   (and IEEE Std 1003.1b-1993 unless _XOPEN_SOURCE is defined).  */
#if (!defined __STRICT_ANSI__ && !defined _POSIX_SOURCE && \
     !defined _POSIX_C_SOURCE)
#define	_POSIX_SOURCE	1
#ifdef _XOPEN_SOURCE
#define	_POSIX_C_SOURCE	2
#else
#define	_POSIX_C_SOURCE	199309L
#endif
#endif

#if defined _POSIX_SOURCE || _POSIX_C_SOURCE >= 1 || defined _XOPEN_SOURCE
#define	__USE_POSIX	1
#endif

#if defined _POSIX_C_SOURCE && _POSIX_C_SOURCE >= 2 || defined _XOPEN_SOURCE
#define	__USE_POSIX2	1
#endif

#if defined _POSIX_C_SOURCE && _POSIX_C_SOURCE >= 199309L
#define	__USE_POSIX199309	1
#endif

#ifdef	_XOPEN_SOURCE
#define	__USE_XOPEN	1
#ifdef	_XOPEN_SOURCE_EXTENDED
#define	__USE_XOPEN_EXTENDED	1
#endif
#endif

#if defined _BSD_SOURCE || defined _SVID_SOURCE
#define	__USE_MISC	1
#endif

#ifdef	_BSD_SOURCE
#define	__USE_BSD	1
#endif

#ifdef	_SVID_SOURCE
#define	__USE_SVID	1
#endif

#ifdef	_GNU_SOURCE
#define	__USE_GNU	1
#endif

#if defined _REENTRANT || defined _THREAD_SAFE
#define __USE_REENTRANT	1
#endif


/* This macro indicates that the installed library is the GNU C Library.
   For historic reasons the value now is 6 and this will stay from now
   on.  The use of this variable is deprecated.  Use __GLIBC__ and
   __GLIBC_MINOR__ now (see below) when you want to test for a specific
   GNU C library version and use the values in <gnu/lib-names.h> to get
   the sonames of the shared libraries.  */
#undef  __GNU_LIBRARY__
#define __GNU_LIBRARY__ 6

/* Major and minor version number of the GNU C library package.  Use
   these macros to test for features in specific releases.  */
#define	__GLIBC__	2
#define	__GLIBC_MINOR__	0


#if !defined __GNUC__ || __GNUC__ < 2
/* In GCC version 2, (__extension__ EXPR) will not complain
   about GCC extensions used in EXPR under -ansi or -pedantic.  */
#define	__extension__
#endif


/* This is here only because every header file already includes this one.  */
#ifndef __ASSEMBLER__
#include <sys/cdefs.h>
#endif

/* This is here only because every header file already includes this one.  */
#ifndef _LIBC
/* Get the definitions of all the appropriate `__stub_FUNCTION' symbols.
   <gnu/stubs.h> contains `#define __stub_FUNCTION' when FUNCTION is a stub
   which will always return failure (and set errno to ENOSYS).

   We avoid including <gnu/stubs.h> when compiling the C library itself to
   avoid a dependency loop.  stubs.h depends on every object file.  If
   this #include were done for the library source code, then every object
   file would depend on stubs.h.  */

#include <gnu/stubs.h>
#endif

#endif	/* features.h  */
