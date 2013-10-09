/* Assembler macros for i386.
   Copyright (C) 1991, 92, 93, 95, 96 Free Software Foundation, Inc.
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

#include <sysdeps/generic/sysdep.h>

#ifdef	ASSEMBLER

/* Syntactic details of assembler.  */

#ifdef HAVE_ELF

/* ELF uses byte-counts for .align, most others use log2 of count of bytes.  */
#define ALIGNARG(log2) 1<<log2
/* For ELF we need the `.type' directive to make shared libs work right.  */
#define ASM_TYPE_DIRECTIVE(name,typearg) .type name,typearg;
#define ASM_SIZE_DIRECTIVE(name) .size name,.-name

/* In ELF C symbols are asm symbols.  */
#undef	NO_UNDERSCORES
#define NO_UNDERSCORES

#else

#define ALIGNARG(log2) log2
#define ASM_TYPE_DIRECTIVE(name,type)	/* Nothing is specified.  */
#define ASM_SIZE_DIRECTIVE(name)	/* Nothing is specified.  */

#endif


/* Define an entry point visible from C.  */
#define	ENTRY(name)							      \
  ASM_GLOBAL_DIRECTIVE C_SYMBOL_NAME(name);				      \
  ASM_TYPE_DIRECTIVE (C_SYMBOL_NAME(name),@function)			      \
  .align ALIGNARG(4);							      \
  C_LABEL(name)								      \
  CALL_MCOUNT

#undef	END
#define END(name)							      \
  ASM_SIZE_DIRECTIVE(name)

/* If compiled for profiling, call `mcount' at the start of each function.  */
#ifdef	PROF
/* The mcount code relies on a normal frame pointer being on the stack
   to locate our caller, so push one just for its benefit.  */
#define CALL_MCOUNT \
  pushl %ebp; movl %esp, %ebp; call JUMPTARGET(mcount); popl %ebp;
#else
#define CALL_MCOUNT		/* Do nothing.  */
#endif

#ifdef	NO_UNDERSCORES
/* Since C identifiers are not normally prefixed with an underscore
   on this system, the asm identifier `syscall_error' intrudes on the
   C name space.  Make sure we use an innocuous name.  */
#define	syscall_error	__syscall_error
#define mcount		_mcount
#endif

#define	PSEUDO(name, syscall_name, args)				      \
lose: SYSCALL_PIC_SETUP							      \
  jmp JUMPTARGET(syscall_error)						      \
  .globl syscall_error;							      \
  ENTRY (name)								      \
  DO_CALL (syscall_name, args);						      \
  jb lose

#undef	PSEUDO_END
#define	PSEUDO_END(name)						      \
  END (name)

#ifdef PIC
#define JUMPTARGET(name)	name##@PLT
#define SYSCALL_PIC_SETUP \
    pushl %ebx;								      \
    call 0f;								      \
0:  popl %ebx;								      \
    addl $_GLOBAL_OFFSET_TABLE+[.-0b], %ebx;
#else
#define JUMPTARGET(name)	name
#define SYSCALL_PIC_SETUP	/* Nothing.  */
#endif

#endif	/* ASSEMBLER */
