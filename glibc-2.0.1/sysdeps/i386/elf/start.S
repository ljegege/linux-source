/* Startup code compliant to the ELF i386 ABI.
   Copyright (C) 1995, 1996, 1997 Free Software Foundation, Inc.
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

/* This is the canonical entry point, usually the first thing in the text
   segment.  The SVR4/i386 ABI (pages 3-31, 3-32) says that when the entry
   point runs, most registers' values are unspecified, except for:

   %edx		Contains a function pointer to be registered with `atexit'.
   		This is how the dynamic linker arranges to have DT_FINI
		functions called for shared libraries that have been loaded
		before this code runs.

   %esp		The stack contains the arguments and environment:
   		0(%esp)			argc
		4(%esp)			argv[0]
		...
		(4*argc)(%esp)		NULL
		(4*(argc+1))(%esp)	envp[0]
		...
					NULL
*/

	.text
	.globl _start
_start:
	/* Clear the frame pointer.  The ABI suggests this be done, to mark
	   the outermost frame obviously.  */
	xorl %ebp, %ebp

	/* %edx contains the address of the shared library termination
	   function, which we will register with `atexit' to be called by
	   `exit'.  I suspect that on some systems, and when statically
	   linked, this will not be set by anything to any function
	   pointer; hopefully it will be zero so we don't try to call
	   random pointers.  */
	testl %edx,%edx
	jz nofini
	pushl %edx
	call atexit
	popl %eax		/* Pop value to unused register to remove
				   argument from stack.  */
nofini:

	/* Do essential libc initialization.  In statically linked
	   programs under the GNU Hurd, this is what sets up the
	   arguments on the stack for the code below.  */
	call __libc_init_first

	/* Extract the arguments and environment as encoded on the stack
	   and set up the arguments for `main': argc, argv, envp.  */
	popl %esi		/* Pop the argument count.  */
	leal 4(%esp,%esi,4), %eax /* envp = &argv[argc + 1] */
	movl %eax, _environ	/* Store it in the global variable.  */
	movl %esp, %edx		/* argv starts just at the current stack top.*/

	/* Before pushing the arguments align the stack to a double word
	   boundary to avoid penalties from misaligned accesses.  Thanks
	   to Edward Seidl <seidl@janed.com> for pointing this out.  */
	andl $0xfffffff8, %esp

	pushl %eax		/* Push third argument: envp.  */
	pushl %edx		/* Push second argument: argv.  */
	pushl %esi		/* Push first argument: argc.  */

	/* Call `_init', which is the entry point to our own `.init'
	   section; and register with `atexit' to have `exit' call
	   `_fini', which is the entry point to our own `.fini' section.  */
	call _init
	pushl $_fini
	call atexit
	popl %eax

	/* Call the user's main function, and exit with its value.  */
	call main
	pushl %eax
	call exit
	hlt			/* Crash if somehow `exit' does return.  */

/* Define a symbol for the first piece of initialized data.  */
	.data
	.globl __data_start
__data_start:
	.long 0
	.weak data_start
	data_start = __data_start
