# Copyright (C) 1991, 92, 93, 94, 95, 96, 97 Free Software Foundation, Inc.
# This file is part of the GNU C Library.

# The GNU C Library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Library General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.

# The GNU C Library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Library General Public License for more details.

# You should have received a copy of the GNU Library General Public
# License along with the GNU C Library; see the file COPYING.LIB.  If not,
# write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA.

#
#	Sub-makefile for string portion of library.
#
subdir	:= string

headers	:= string.h strings.h memory.h endian.h bytesex.h \
	   argz.h envz.h

routines	:= strcat strchr strcmp strcoll strcpy strcspn		\
		   strdup strndup	\
		   strerror _strerror strerror_r strlen strnlen		\
		   strncat strncmp strncpy				\
		   strrchr strpbrk strsignal strspn strstr strtok	\
		   strtok_r strxfrm memchr memcmp memmove memset	\
		   bcopy bzero ffs stpcpy stpncpy			\
		   strcasecmp strncase					\
		   memccpy memcpy wordcopy strsep			\
		   swab strfry memfrob memmem				\
		   $(addprefix argz-,append count create ctsep next	\
			             delete extract insert stringify	\
				     addsep)				\
		   envz basename

tests		:= tester testcopy test-ffs tst-strlen stratcliff
distribute	:= memcopy.h pagecopy.h


include ../Rules

tester-ENV = LANGUAGE=C
CFLAGS-tester.c = -fno-builtin
CFLAGS-tst-strlen.c = -fno-builtin
CFLAGS-stratcliff.c = -fno-builtin
