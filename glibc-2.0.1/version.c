/* Copyright (C) 1991, 92, 93, 94, 95, 96, 97 Free Software Foundation, Inc.
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

#include "version.h"
const char __libc_release[] = RELEASE;
const char __libc_version[] = VERSION;

static const char banner[] =
"GNU C Library "RELEASE" release version "VERSION", by Roland McGrath et al.\n\
Compiled by GNU CC version "__VERSION__".\n\
Copyright (C) 1992, 93, 94, 95, 96, 97 Free Software Foundation, Inc.\n\
This is free software; see the source for copying conditions.\n\
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A\n\
PARTICULAR PURPOSE.\n"
#include "version-info.h"
"Report bugs using the `glibcbug' script to <bugs@gnu.ai.mit.edu>.\n";

#include <unistd.h>

void
__libc_print_version (void)
{
  __write (STDOUT_FILENO, banner, sizeof banner - 1);
}

#ifdef HAVE_ELF
/* This function is the entry point for the shared object.
   Running the library as a program will get here.  */

void
__libc_main (void)
{
  __libc_print_version ();
  _exit (0);
}
#endif

/*
   Local Variables:
   version-control: never
   End:
*/
