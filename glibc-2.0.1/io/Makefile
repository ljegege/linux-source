# Copyright (C) 1992, 93, 94, 95, 96, 97 Free Software Foundation, Inc.
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
#	Sub-makefile for I/O portion of the library.
#
subdir	:= io

headers := sys/stat.h statbuf.h sys/statfs.h statfsbuf.h sys/vfs.h \
	   fcntl.h sys/fcntl.h fcntlbits.h \
	   poll.h sys/poll.h \
	   utime.h ftw.h fts.h

routines :=							      \
	utime							      \
	mkfifo							      \
	stat fstat lstat mknod					      \
	xstat fxstat lxstat xmknod				      \
	statfs fstatfs						      \
	umask chmod fchmod mkdir				      \
	open close read write lseek access euidaccess		      \
	fcntl flock lockf					      \
	dup dup2 pipe						      \
	creat							      \
	chdir fchdir						      \
	getcwd getwd getdirname					      \
	chown fchown lchown					      \
	ttyname ttyname_r isatty				      \
	link symlink readlink					      \
	unlink rmdir						      \
	ftw fts poll

# These routines will be omitted from the libc shared object.
# Instead the static object files will be included in a special archive
# linked against when the shared library will be used.
static-only-routines = stat fstat lstat mknod

others		:= pwd
tests		:= test-utime

include ../Rules

CFLAGS-fts.c = -Wno-uninitialized
CFLAGS-ftw.c = -Wno-uninitialized
