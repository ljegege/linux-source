/* Machine-dependent ELF dynamic relocation inline functions.  m68k version.
   Copyright (C) 1996 Free Software Foundation, Inc.
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
   License along with the GNU C Library; see the file COPYING.LIB.  If
   not, write to the Free Software Foundation, Inc.,
   59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#ifndef dl_machine_h
#define dl_machine_h

#define ELF_MACHINE_NAME "m68k"

#include <assert.h>

/* Return nonzero iff E_MACHINE is compatible with the running host.  */
static inline int
elf_machine_matches_host (Elf32_Half e_machine)
{
  switch (e_machine)
    {
    case EM_68K:
      return 1;
    default:
      return 0;
    }
}


/* Return the link-time address of _DYNAMIC.  Conveniently, this is the
   first element of the GOT.  This must be inlined in a function which
   uses global data.  */
static inline Elf32_Addr
elf_machine_dynamic (void)
{
  register Elf32_Addr *got asm ("%a5");
  return *got;
}


/* Return the run-time load address of the shared object.  */
static inline Elf32_Addr
elf_machine_load_address (void)
{
  Elf32_Addr addr;
  asm ("here:	lea here(%%pc), %0\n"
       "	sub.l %#here, %0"
       : "=a" (addr));
  return addr;
}

/* The `subl' insn above will contain an R_68K_RELATIVE relocation
   entry intended to insert the run-time address of the label `here'.
   This will be the first relocation in the text of the dynamic
   linker; we skip it to avoid trying to modify read-only text in this
   early stage.  */
#define ELF_MACHINE_BEFORE_RTLD_RELOC(dynamic_info) \
  ((dynamic_info)[DT_RELA]->d_un.d_ptr += sizeof (Elf32_Rela), \
   (dynamic_info)[DT_RELASZ]->d_un.d_val -= sizeof (Elf32_Rela))


/* Set up the loaded object described by L so its unrelocated PLT
   entries will jump to the on-demand fixup code in dl-runtime.c.  */

static inline void
elf_machine_runtime_setup (struct link_map *l, int lazy)
{
  Elf32_Addr *got;
  extern void _dl_runtime_resolve (Elf32_Word);

  if (l->l_info[DT_JMPREL] && lazy)
    {
      /* The GOT entries for functions in the PLT have not yet been
	 filled in.  Their initial contents will arrange when called
	 to push an offset into the .rela.plt section, push
	 _GLOBAL_OFFSET_TABLE_[1], and then jump to
	 _GLOBAL_OFFSET_TABLE_[2].  */
      got = (Elf32_Addr *) (l->l_addr + l->l_info[DT_PLTGOT]->d_un.d_ptr);
      got[1] = (Elf32_Addr) l;	/* Identify this shared object.  */
      /* This function will get called to fix up the GOT entry
	 indicated by the offset on the stack, and then jump to the
	 resolved address.  */
      got[2] = (Elf32_Addr) &_dl_runtime_resolve;
    }

  /* This code is used in dl-runtime.c to call the `fixup' function
     and then redirect to the address it returns.  */
#define ELF_MACHINE_RUNTIME_TRAMPOLINE asm ("\
| Trampoline for _dl_runtime_resolver
	.globl _dl_runtime_resolve
	.type _dl_runtime_resolve, @function
_dl_runtime_resolve:
	| Save %a0 (struct return address) and %a1.
	move.l %a0, -(%sp)
	move.l %a1, -(%sp)
	| Call the real address resolver.
	jbsr fixup
	| Restore register %a0 and %a1.
	move.l (%sp)+, %a1
	move.l (%sp)+, %a0
	| Pop parameters
	addq.l #8, %sp
	| Call real function.
	jmp (%d0)
	.size _dl_runtime_resolve, . - _dl_runtime_resolve
");
#define ELF_MACHINE_RUNTIME_FIXUP_ARGS long int save_a0, long int save_a1
/* The PLT uses Elf32_Rela relocs.  */
#define elf_machine_relplt elf_machine_rela
}


/* Mask identifying addresses reserved for the user program,
   where the dynamic linker should not map anything.  */
#define ELF_MACHINE_USER_ADDRESS_MASK	0x80000000UL

/* Initial entry point code for the dynamic linker.
   The C function `_dl_start' is the real entry point;
   its return value is the user program's entry point.  */

#define RTLD_START asm ("\
.text
.globl _start
.globl _dl_start_user
_start:
	move.l %sp, -(%sp)
	jbsr _dl_start
	addq.l #4, %sp
_dl_start_user:
	| Save the user entry point address in %a4.
	move.l %d0, %a4
	| Point %a5 at the GOT.
	lea _GLOBAL_OFFSET_TABLE_@GOTPC(%pc), %a5
	| See if we were run as a command with the executable file
	| name as an extra leading argument.
	move.l ([_dl_skip_args@GOT, %a5]), %d0
	jeq 0f
	| Pop the original argument count
	move.l (%sp)+, %d1
	| Subtract _dl_skip_args from it.
	sub.l %d0, %d1
	| Adjust the stack pointer to skip _dl_skip_args words.
	lea (%sp, %d0*4), %sp
	| Push back the modified argument count.
	move.l %d1, -(%sp)
0:	| Push _dl_default_scope[2] as argument in _dl_init_next call below.
	move.l ([_dl_default_scope@GOT, %a5], 8), %d2
0:	move.l %d2, -(%sp)
	| Call _dl_init_next to return the address of an initializer
	| function to run.
	bsr.l _dl_init_next@PLTPC
	add.l #4, %sp | Pop argument.
	| Check for zero return, when out of initializers.
	tst.l %d0
	jeq 1f
	| Call the shared object initializer function.
	| NOTE: We depend only on the registers (%d2, %a4 and %a5)
	| and the return address pushed by this call;
	| the initializer is called with the stack just
	| as it appears on entry, and it is free to move
	| the stack around, as long as it winds up jumping to
	| the return address on the top of the stack.
	move.l %d0, %a0
	jsr (%a0)
	| Loop to call _dl_init_next for the next initializer.
	jra 0b
1:	| Clear the startup flag.
	clr.l _dl_starting_up@GOT(%a5)
	| Pass our finalizer function to the user in %a1.
	move.l _dl_fini@GOT(%a5), %a1
	| Initialize %fp with the stack pointer.
	move.l %sp, %fp
	| Jump to the user's entry point.
	jmp (%a4)");

/* Nonzero iff TYPE describes relocation of a PLT entry, so
   PLT entries should not be allowed to define the value.  */
#define elf_machine_pltrel_p(type) ((type) == R_68K_JMP_SLOT)

/* The m68k never uses Elf32_Rel relocations.  */
#define ELF_MACHINE_NO_REL 1

#endif /* !dl_machine_h */

#ifdef RESOLVE

/* Perform the relocation specified by RELOC and SYM (which is fully resolved).
   MAP is the object containing the reloc.  */

static inline void
elf_machine_rela (struct link_map *map,
		  const Elf32_Rela *reloc, const Elf32_Sym *sym)
{
  Elf32_Addr *const reloc_addr = (void *) (map->l_addr + reloc->r_offset);
  Elf32_Addr loadbase;

  switch (ELF32_R_TYPE (reloc->r_info))
    {
    case R_68K_COPY:
      loadbase = RESOLVE (&sym, DL_LOOKUP_NOEXEC);
      memcpy (reloc_addr, (void *) (loadbase + sym->st_value), sym->st_size);
      break;
    case R_68K_GLOB_DAT:
      loadbase = RESOLVE (&sym, 0);
      *reloc_addr = sym ? (loadbase + sym->st_value) : 0;
      break;
    case R_68K_JMP_SLOT:
      loadbase = RESOLVE (&sym, DL_LOOKUP_NOPLT);
      *reloc_addr = sym ? (loadbase + sym->st_value) : 0;
      break;
    case R_68K_8:
      loadbase = RESOLVE (&sym, 0);
      *(char *) reloc_addr = ((sym ? (loadbase + sym->st_value) : 0)
			      + reloc->r_addend);
      break;
    case R_68K_16:
      loadbase = RESOLVE (&sym, 0);
      *(short *) reloc_addr = ((sym ? (loadbase + sym->st_value) : 0)
			       + reloc->r_addend);
      break;
    case R_68K_32:
      loadbase = RESOLVE (&sym, 0);
      *reloc_addr = ((sym ? (loadbase + sym->st_value) : 0)
		     + reloc->r_addend);
      break;
    case R_68K_RELATIVE:
      *reloc_addr = map->l_addr + reloc->r_addend;
      break;
    case R_68K_PC8:
      loadbase = RESOLVE (&sym, 0);
      *(char *) reloc_addr = ((sym ? (loadbase + sym->st_value) : 0)
			      + reloc->r_addend - (Elf32_Addr) reloc_addr);
      break;
    case R_68K_PC16:
      loadbase = RESOLVE (&sym, 0);
      *(short *) reloc_addr = ((sym ? (loadbase + sym->st_value) : 0)
			       + reloc->r_addend - (Elf32_Addr) reloc_addr);
      break;
    case R_68K_PC32:
      loadbase = RESOLVE (&sym, 0);
      *reloc_addr = ((sym ? (loadbase + sym->st_value) : 0)
		     + reloc->r_addend - (Elf32_Addr) reloc_addr);
      break;
    case R_68K_NONE:		/* Alright, Wilbur.  */
      break;
    default:
      assert (! "unexpected dynamic reloc type");
      break;
    }
}

static inline void
elf_machine_lazy_rel (struct link_map *map, const Elf32_Rela *reloc)
{
  Elf32_Addr *const reloc_addr = (void *) (map->l_addr + reloc->r_offset);
  switch (ELF32_R_TYPE (reloc->r_info))
    {
    case R_68K_JMP_SLOT:
      *reloc_addr += map->l_addr;
      break;
    default:
      assert (! "unexpected PLT reloc type");
      break;
    }
}

#endif /* RESOLVE */
