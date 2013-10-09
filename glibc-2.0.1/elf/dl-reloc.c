/* Relocate a shared object and resolve its references to other loaded objects.
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

#include <link.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include "dynamic-link.h"

void
_dl_relocate_object (struct link_map *l, struct link_map *scope[], int lazy)
{
  if (l->l_relocated)
    return;

  if (l->l_info[DT_TEXTREL])
    {
      /* Bletch.  We must make read-only segments writable
	 long enough to relocate them.  */
      const ElfW(Phdr) *ph;
      for (ph = l->l_phdr; ph < &l->l_phdr[l->l_phnum]; ++ph)
	if (ph->p_type == PT_LOAD && (ph->p_flags & PF_W) == 0)
	  {
	    caddr_t mapstart = ((caddr_t) l->l_addr +
				(ph->p_vaddr & ~(_dl_pagesize - 1)));
	    caddr_t mapend = ((caddr_t) l->l_addr +
			      ((ph->p_vaddr + ph->p_memsz + _dl_pagesize - 1)
			       & ~(_dl_pagesize - 1)));
	    if (__mprotect (mapstart, mapend - mapstart,
			    PROT_READ|PROT_WRITE) < 0)
	      _dl_signal_error (errno, l->l_name,
				"cannot make segment writable for relocation");
	  }
    }

  {
    /* Do the actual relocation of the object's GOT and other data.  */

    const char *strtab		/* String table object symbols.  */
      = ((void *) l->l_addr + l->l_info[DT_STRTAB]->d_un.d_ptr);

    /* This macro is used as a callback from the ELF_DYNAMIC_RELOCATE code.  */
#define RESOLVE(ref, flags) \
    (_dl_lookup_symbol (strtab + (*ref)->st_name, ref, scope, \
			l->l_name, flags))

#include "dynamic-link.h"
    ELF_DYNAMIC_RELOCATE (l, lazy);
  }

  /* Set up the PLT so its unrelocated entries will jump to
     _dl_runtime_resolve (dl-runtime.c), which will relocate them.  */
  elf_machine_runtime_setup (l, lazy);

  /* Mark the object so we know ths work has been done.  */
  l->l_relocated = 1;

  if (l->l_info[DT_TEXTREL])
    {
      /* Undo the protection change we made before relocating.  */
      const ElfW(Phdr) *ph;
      for (ph = l->l_phdr; ph < &l->l_phdr[l->l_phnum]; ++ph)
	if (ph->p_type == PT_LOAD && (ph->p_flags & PF_W) == 0)
	  {
	    caddr_t mapstart = ((caddr_t) l->l_addr +
				(ph->p_vaddr & ~(_dl_pagesize - 1)));
	    caddr_t mapend = ((caddr_t) l->l_addr +
			      ((ph->p_vaddr + ph->p_memsz + _dl_pagesize - 1)
			       & ~(_dl_pagesize - 1)));
	    int prot = 0;
	    if (ph->p_flags & PF_R)
	      prot |= PROT_READ;
	    if (ph->p_flags & PF_X)
	      prot |= PROT_EXEC;
	    if (__mprotect (mapstart, mapend - mapstart, prot) < 0)
	      _dl_signal_error (errno, l->l_name,
				"can't restore segment prot after reloc");
	  }
    }
}
