/* Do relocations for ELF dynamic linking.
   Copyright (C) 1995, 1996 Free Software Foundation, Inc.
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

/* This file may be included twice, to define both
   `elf_dynamic_do_rel' and `elf_dynamic_do_rela'.  */

#ifdef DO_RELA
#define elf_dynamic_do_rel	elf_dynamic_do_rela
#define	Rel			Rela
#define elf_machine_rel		elf_machine_rela
#endif


/* Perform the relocations in MAP on the running program image as specified
   by RELTAG, SZTAG.  If LAZY is nonzero, this is the first pass on PLT
   relocations; they should be set up to call _dl_runtime_resolve, rather
   than fully resolved now.  */

static inline void
elf_dynamic_do_rel (struct link_map *map,
		    int reltag, int sztag,
		    int lazy)
{
  const ElfW(Sym) *const symtab
    = (const ElfW(Sym) *) (map->l_addr + map->l_info[DT_SYMTAB]->d_un.d_ptr);
  const ElfW(Rel) *r
    = (const ElfW(Rel) *) (map->l_addr + map->l_info[reltag]->d_un.d_ptr);
  const ElfW(Rel) *end = &r[map->l_info[sztag]->d_un.d_val / sizeof *r];

  if (lazy)
    /* Doing lazy PLT relocations; they need very little info.  */
    for (; r < end; ++r)
      elf_machine_lazy_rel (map, r);
  else
    for (; r < end; ++r)
      elf_machine_rel (map, r, &symtab[ELFW(R_SYM) (r->r_info)]);
}

#undef elf_dynamic_do_rel
#undef Rel
#undef elf_machine_rel
