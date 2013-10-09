/* Run time dynamic linker.
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

#include <link.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>		/* Check if MAP_ANON is defined.  */
#include "../stdio-common/_itoa.h"
#include <assert.h>
#include "dynamic-link.h"


/* System-specific function to do initial startup for the dynamic linker.
   After this, file access calls and getenv must work.  This is responsible
   for setting __libc_enable_secure if we need to be secure (e.g. setuid),
   and for setting _dl_argc and _dl_argv, and then calling _dl_main.  */
extern ElfW(Addr) _dl_sysdep_start (void **start_argptr,
				    void (*dl_main) (const ElfW(Phdr) *phdr,
						     ElfW(Half) phent,
						     ElfW(Addr) *user_entry));
extern void _dl_sysdep_start_cleanup (void);

/* System-dependent function to read a file's whole contents
   in the most convenient manner available.  */
extern void *_dl_sysdep_read_whole_file (const char *filename,
					 size_t *filesize_ptr,
					 int mmap_prot);

/* Helper function to handle errors while resolving symbols.  */
static void print_unresolved (const char *errstring, const char *objname);


int _dl_argc;
char **_dl_argv;
const char *_dl_rpath;

/* Set nonzero during loading and initialization of executable and
   libraries, cleared before the executable's entry point runs.  This
   must not be initialized to nonzero, because the unused dynamic
   linker loaded in for libc.so's "ld.so.1" dep will provide the
   definition seen by libc.so's initializer; that value must be zero,
   and will be since that dynamic linker's _dl_start and dl_main will
   never be called.  */
int _dl_starting_up;

static void dl_main (const ElfW(Phdr) *phdr,
		     ElfW(Half) phent,
		     ElfW(Addr) *user_entry);

struct link_map _dl_rtld_map;

#ifdef RTLD_START
RTLD_START
#else
#error "sysdeps/MACHINE/dl-machine.h fails to define RTLD_START"
#endif

ElfW(Addr)
_dl_start (void *arg)
{
  struct link_map bootstrap_map;

  /* This #define produces dynamic linking inline functions for
     bootstrap relocation instead of general-purpose relocation.  */
#define RTLD_BOOTSTRAP
#define RESOLVE(sym, flags) bootstrap_map.l_addr
#include "dynamic-link.h"

  /* Figure out the run-time load address of the dynamic linker itself.  */
  bootstrap_map.l_addr = elf_machine_load_address ();

  /* Read our own dynamic section and fill in the info array.  */
  bootstrap_map.l_ld = (void *) bootstrap_map.l_addr + elf_machine_dynamic ();
  elf_get_dynamic_info (bootstrap_map.l_ld, bootstrap_map.l_info);

#ifdef ELF_MACHINE_BEFORE_RTLD_RELOC
  ELF_MACHINE_BEFORE_RTLD_RELOC (bootstrap_map.l_info);
#endif

  /* Relocate ourselves so we can do normal function calls and
     data access using the global offset table.  */

  ELF_DYNAMIC_RELOCATE (&bootstrap_map, 0);


  /* Now life is sane; we can call functions and access global data.
     Set up to use the operating system facilities, and find out from
     the operating system's program loader where to find the program
     header table in core.  */


  /* Transfer data about ourselves to the permanent link_map structure.  */
  _dl_rtld_map.l_addr = bootstrap_map.l_addr;
  _dl_rtld_map.l_ld = bootstrap_map.l_ld;
  memcpy (_dl_rtld_map.l_info, bootstrap_map.l_info,
	  sizeof _dl_rtld_map.l_info);
  _dl_setup_hash (&_dl_rtld_map);

  /* Cache the DT_RPATH stored in ld.so itself; this will be
     the default search path.  */
  _dl_rpath = (void *) (_dl_rtld_map.l_addr +
			_dl_rtld_map.l_info[DT_STRTAB]->d_un.d_ptr +
			_dl_rtld_map.l_info[DT_RPATH]->d_un.d_val);

  /* Call the OS-dependent function to set up life so we can do things like
     file access.  It will call `dl_main' (below) to do all the real work
     of the dynamic linker, and then unwind our frame and run the user
     entry point on the same stack we entered on.  */
  return _dl_sysdep_start (arg, &dl_main);
}


/* Now life is peachy; we can do all normal operations.
   On to the real work.  */

void _start (void);

unsigned int _dl_skip_args;	/* Nonzero if we were run directly.  */

static void
dl_main (const ElfW(Phdr) *phdr,
	 ElfW(Half) phent,
	 ElfW(Addr) *user_entry)
{
  const ElfW(Phdr) *ph;
  struct link_map *l;
  int lazy;
  enum { normal, list, verify, trace } mode;
  struct link_map **preloads;
  unsigned int npreloads;
  const char *preloadlist;
  size_t file_size;
  char *file;

  mode = getenv ("LD_TRACE_LOADED_OBJECTS") != NULL ? trace : normal;

  /* LAZY is determined by the parameters --datadeps and --function-deps
     if we trace the binary.  */
  if (mode == trace)
    lazy = -1;
  else
    lazy = !__libc_enable_secure && *(getenv ("LD_BIND_NOW") ?: "") == '\0';

  /* Set up a flag which tells we are just starting.  */
  _dl_starting_up = 1;

  if (*user_entry == (ElfW(Addr)) &_start)
    {
      /* Ho ho.  We are not the program interpreter!  We are the program
	 itself!  This means someone ran ld.so as a command.  Well, that
	 might be convenient to do sometimes.  We support it by
	 interpreting the args like this:

	 ld.so PROGRAM ARGS...

	 The first argument is the name of a file containing an ELF
	 executable we will load and run with the following arguments.
	 To simplify life here, PROGRAM is searched for using the
	 normal rules for shared objects, rather than $PATH or anything
	 like that.  We just load it and use its entry point; we don't
	 pay attention to its PT_INTERP command (we are the interpreter
	 ourselves).  This is an easy way to test a new ld.so before
	 installing it.  */
      if (_dl_argc < 2)
	_dl_sysdep_fatal ("\
Usage: ld.so [--list|--verify] EXECUTABLE-FILE [ARGS-FOR-PROGRAM...]\n\
You have invoked `ld.so', the helper program for shared library executables.\n\
This program usually lives in the file `/lib/ld.so', and special directives\n\
in executable files using ELF shared libraries tell the system's program\n\
loader to load the helper program from this file.  This helper program loads\n\
the shared libraries needed by the program executable, prepares the program\n\
to run, and runs it.  You may invoke this helper program directly from the\n\
command line to load and run an ELF executable file; this is like executing\n\
that file itself, but always uses this helper program from the file you\n\
specified, instead of the helper program file specified in the executable\n\
file you run.  This is mostly of use for maintainers to test new versions\n\
of this helper program; chances are you did not intend to run this program.\n",
			  NULL);

      /* Note the place where the dynamic linker actually came from.  */
      _dl_rtld_map.l_name = _dl_argv[0];

      while (_dl_argc > 1)
	if (! strcmp (_dl_argv[1], "--list"))
	  {
	    mode = list;
	    lazy = -1;	/* This means do no dependency analysis.  */

	    ++_dl_skip_args;
	    --_dl_argc;
	    ++_dl_argv;
	  }
	else if (! strcmp (_dl_argv[1], "--verify"))
	  {
	    mode = verify;

	    ++_dl_skip_args;
	    --_dl_argc;
	    ++_dl_argv;
	  }
	else if (! strcmp (_dl_argv[1], "--data-relocs"))
	  {
	    mode = trace;
	    lazy = 1;	/* This means do only data relocation analysis.  */

	    ++_dl_skip_args;
	    --_dl_argc;
	    ++_dl_argv;
	  }
	else if (! strcmp (_dl_argv[1], "--function-relocs"))
	  {
	    mode = trace;
	    lazy = 0;	/* This means do also function relocation analysis.  */

	    ++_dl_skip_args;
	    --_dl_argc;
	    ++_dl_argv;
	  }
	else
	  break;

      ++_dl_skip_args;
      --_dl_argc;
      ++_dl_argv;

      if (mode == verify)
	{
	  void doit (void)
	    {
	      l = _dl_map_object (NULL, _dl_argv[0], lt_library, 0);
	    }
	  char *err_str = NULL;
	  const char *obj_name __attribute__ ((unused));

	  (void) _dl_catch_error (&err_str, &obj_name, doit);
	  if (err_str != NULL)
	    {
	      free (err_str);
	      _exit (EXIT_FAILURE);
	    }
	}
      else
	l = _dl_map_object (NULL, _dl_argv[0], lt_library, 0);

      phdr = l->l_phdr;
      phent = l->l_phnum;
      l->l_name = (char *) "";
      *user_entry = l->l_entry;
    }
  else
    {
      /* Create a link_map for the executable itself.
	 This will be what dlopen on "" returns.  */
      l = _dl_new_object ((char *) "", "", lt_executable);
      if (l == NULL)
	_dl_sysdep_fatal ("cannot allocate memory for link map", NULL);
      l->l_phdr = phdr;
      l->l_phnum = phent;
      l->l_entry = *user_entry;
    }

  if (l != _dl_loaded)
    {
      /* GDB assumes that the first element on the chain is the
	 link_map for the executable itself, and always skips it.
	 Make sure the first one is indeed that one.  */
      l->l_prev->l_next = l->l_next;
      if (l->l_next)
	l->l_next->l_prev = l->l_prev;
      l->l_prev = NULL;
      l->l_next = _dl_loaded;
      _dl_loaded->l_prev = l;
      _dl_loaded = l;
    }

  /* Scan the program header table for the dynamic section.  */
  for (ph = phdr; ph < &phdr[phent]; ++ph)
    switch (ph->p_type)
      {
      case PT_DYNAMIC:
	/* This tells us where to find the dynamic section,
	   which tells us everything we need to do.  */
	l->l_ld = (void *) l->l_addr + ph->p_vaddr;
	break;
      case PT_INTERP:
	/* This "interpreter segment" was used by the program loader to
	   find the program interpreter, which is this program itself, the
	   dynamic linker.  We note what name finds us, so that a future
	   dlopen call or DT_NEEDED entry, for something that wants to link
	   against the dynamic linker as a shared library, will know that
	   the shared object is already loaded.  */
	_dl_rtld_map.l_libname = (const char *) l->l_addr + ph->p_vaddr;
	break;
      }
  if (! _dl_rtld_map.l_libname && _dl_rtld_map.l_name)
    /* We were invoked directly, so the program might not have a PT_INTERP.  */
    _dl_rtld_map.l_libname = _dl_rtld_map.l_name;
  else
    assert (_dl_rtld_map.l_libname); /* How else did we get here?  */

  if (mode == verify)
    /* We were called just to verify that this is a dynamic executable
       using us as the program interpreter.  */
    _exit (l->l_ld == NULL ? EXIT_FAILURE : EXIT_SUCCESS);

  /* Extract the contents of the dynamic section for easy access.  */
  elf_get_dynamic_info (l->l_ld, l->l_info);
  if (l->l_info[DT_HASH])
    /* Set up our cache of pointers into the hash table.  */
    _dl_setup_hash (l);

  /* Put the link_map for ourselves on the chain so it can be found by
     name.  */
  if (! _dl_rtld_map.l_name)
    /* If not invoked directly, the dynamic linker shared object file was
       found by the PT_INTERP name.  */
    _dl_rtld_map.l_name = (char *) _dl_rtld_map.l_libname;
  _dl_rtld_map.l_type = lt_library;
  while (l->l_next)
    l = l->l_next;
  l->l_next = &_dl_rtld_map;
  _dl_rtld_map.l_prev = l;

  /* We have two ways to specify objects to preload: via environment
     variable and via the file /etc/ld.so.preload.  The later can also
     be used when security is enabled.  */
  preloads = NULL;
  npreloads = 0;

  preloadlist = getenv ("LD_PRELOAD");
  if (preloadlist)
    {
      /* The LD_PRELOAD environment variable gives a white space
	 separated list of libraries that are loaded before the
	 executable's dependencies and prepended to the global scope
	 list.  If the binary is running setuid all elements
	 containing a '/' are ignored since it is insecure.  */
      char *list = strdupa (preloadlist);
      char *p;
      while ((p = strsep (&list, " ")) != NULL)
	if (! __libc_enable_secure || strchr (p, '/') == NULL)
	  {
	    (void) _dl_map_object (NULL, p, lt_library, 0);
	    ++npreloads;
	  }
    }

  /* Read the contents of the file.  */
  file = _dl_sysdep_read_whole_file ("/etc/ld.so.preload", &file_size,
				     PROT_READ | PROT_WRITE);
  if (file)
    {
      /* Parse the file.  It contains names of libraries to be loaded,
	 separated by white spaces or `:'.  It may also contain
	 comments introduced by `#'.  */
      char *problem;
      char *runp;
      size_t rest;

      /* Eliminate comments.  */
      runp = file;
      rest = file_size;
      while (rest > 0)
	{
	  char *comment = memchr (runp, '#', rest);
	  if (comment == NULL)
	    break;

	  rest -= comment - runp;
	  do
	    *comment = ' ';
	  while (--rest > 0 && *++comment != '\n');
	}

      /* We have one problematic case: if we have a name at the end of
	 the file without a trailing terminating characters, we cannot
	 place the \0.  Handle the case separately.  */
      if (file[file_size - 1] != ' ' && file[file_size] != '\t'
	  && file[file_size] != '\n')
	{
	  problem = &file[file_size];
	  while (problem > file && problem[-1] != ' ' && problem[-1] != '\t'
		 && problem[-1] != '\n')
	    --problem;

	  if (problem > file)
	    problem[-1] = '\0';
	}
      else
	problem = NULL;

      if (file != problem)
	{
	  char *p;
	  runp = file;
	  while ((p = strsep (&runp, ": \t\n")) != NULL)
	    {
	      (void) _dl_map_object (NULL, p, lt_library, 0);
	      ++npreloads;
	    }
	}

      if (problem != NULL)
	{
	  char *p = strndupa (problem, file_size - (problem - file));
	  (void) _dl_map_object (NULL, p, lt_library, 0);
	}

      /* We don't need the file anymore.  */
      __munmap (file, file_size);
    }

  if (npreloads != 0)
    {
      /* Set up PRELOADS with a vector of the preloaded libraries.  */
      struct link_map *l;
      unsigned int i;
      preloads = __alloca (npreloads * sizeof preloads[0]);
      l = _dl_rtld_map.l_next; /* End of the chain before preloads.  */
      i = 0;
      do
	{
	  preloads[i++] = l;
	  l = l->l_next;
	} while (l);
      assert (i == npreloads);
    }

  /* Load all the libraries specified by DT_NEEDED entries.  If LD_PRELOAD
     specified some libraries to load, these are inserted before the actual
     dependencies in the executable's searchlist for symbol resolution.  */
  _dl_map_object_deps (l, preloads, npreloads, mode == trace);

#ifndef MAP_ANON
  /* We are done mapping things, so close the zero-fill descriptor.  */
  __close (_dl_zerofd);
  _dl_zerofd = -1;
#endif

  /* Remove _dl_rtld_map from the chain.  */
  _dl_rtld_map.l_prev->l_next = _dl_rtld_map.l_next;
  if (_dl_rtld_map.l_next)
    _dl_rtld_map.l_next->l_prev = _dl_rtld_map.l_prev;

  if (_dl_rtld_map.l_opencount)
    {
      /* Some DT_NEEDED entry referred to the interpreter object itself, so
	 put it back in the list of visible objects.  We insert it into the
	 chain in symbol search order because gdb uses the chain's order as
	 its symbol search order.  */
      unsigned int i = 1;
      while (l->l_searchlist[i] != &_dl_rtld_map)
	++i;
      _dl_rtld_map.l_prev = l->l_searchlist[i - 1];
      _dl_rtld_map.l_next = (i + 1 < l->l_nsearchlist ?
			     l->l_searchlist[i + 1] : NULL);
      assert (_dl_rtld_map.l_prev->l_next == _dl_rtld_map.l_next);
      _dl_rtld_map.l_prev->l_next = &_dl_rtld_map;
      if (_dl_rtld_map.l_next)
	{
	  assert (_dl_rtld_map.l_next->l_prev == _dl_rtld_map.l_prev);
	  _dl_rtld_map.l_next->l_prev = &_dl_rtld_map;
	}
    }

  if (mode != normal)
    {
      /* We were run just to list the shared libraries.  It is
	 important that we do this before real relocation, because the
	 functions we call below for output may no longer work properly
	 after relocation.  */

      int i;

      if (! _dl_loaded->l_info[DT_NEEDED])
	_dl_sysdep_message ("\t", "statically linked\n", NULL);
      else
	for (l = _dl_loaded->l_next; l; l = l->l_next)
	  if (l->l_opencount == 0)
	    /* The library was not found.  */
	    _dl_sysdep_message ("\t", l->l_libname, " => not found\n", NULL);
	  else
	    {
	      char buf[20], *bp;
	      buf[sizeof buf - 1] = '\0';
	      bp = _itoa (l->l_addr, &buf[sizeof buf - 1], 16, 0);
	      while ((size_t) (&buf[sizeof buf - 1] - bp)
		     < sizeof l->l_addr * 2)
		*--bp = '0';
	      _dl_sysdep_message ("\t", l->l_libname, " => ", l->l_name,
				  " (0x", bp, ")\n", NULL);
	    }

      if (mode != trace)
	for (i = 1; i < _dl_argc; ++i)
	  {
	    const ElfW(Sym) *ref = NULL;
	    ElfW(Addr) loadbase = _dl_lookup_symbol (_dl_argv[i], &ref,
						     &_dl_default_scope[2],
						     "argument",
						     DL_LOOKUP_NOPLT);
	    char buf[20], *bp;
	    buf[sizeof buf - 1] = '\0';
	    bp = _itoa (ref->st_value, &buf[sizeof buf - 1], 16, 0);
	    while ((size_t) (&buf[sizeof buf - 1] - bp) < sizeof loadbase * 2)
	      *--bp = '0';
	    _dl_sysdep_message (_dl_argv[i], " found at 0x", bp, NULL);
	    buf[sizeof buf - 1] = '\0';
	    bp = _itoa (loadbase, &buf[sizeof buf - 1], 16, 0);
	    while ((size_t) (&buf[sizeof buf - 1] - bp) < sizeof loadbase * 2)
	      *--bp = '0';
	    _dl_sysdep_message (" in object at 0x", bp, "\n", NULL);
	  }
      else if (lazy >= 0)
	{
	  /* We have to do symbol dependency testing.  */
	  void doit (void)
	    {
	      _dl_relocate_object (l, _dl_object_relocation_scope (l), lazy);
	    }

	  l = _dl_loaded;
	  while (l->l_next)
	    l = l->l_next;
	  do
	    {
	      if (l != &_dl_rtld_map && l->l_opencount > 0)
		{
		  _dl_receive_error (print_unresolved, doit);
		  *_dl_global_scope_end = NULL;
		}
	      l = l->l_prev;
	    } while (l);
	}

      _exit (0);
    }

  {
    /* Now we have all the objects loaded.  Relocate them all except for
       the dynamic linker itself.  We do this in reverse order so that copy
       relocs of earlier objects overwrite the data written by later
       objects.  We do not re-relocate the dynamic linker itself in this
       loop because that could result in the GOT entries for functions we
       call being changed, and that would break us.  It is safe to relocate
       the dynamic linker out of order because it has no copy relocs (we
       know that because it is self-contained).  */

    l = _dl_loaded;
    while (l->l_next)
      l = l->l_next;
    do
      {
	if (l != &_dl_rtld_map)
	  {
	    _dl_relocate_object (l, _dl_object_relocation_scope (l), lazy);
	    *_dl_global_scope_end = NULL;
	  }
	l = l->l_prev;
      } while (l);

    /* Do any necessary cleanups for the startup OS interface code.
       We do these now so that no calls are made after rtld re-relocation
       which might be resolved to different functions than we expect.
       We cannot do this before relocating the other objects because
       _dl_relocate_object might need to call `mprotect' for DT_TEXTREL.  */
    _dl_sysdep_start_cleanup ();

    if (_dl_rtld_map.l_opencount > 0)
      /* There was an explicit ref to the dynamic linker as a shared lib.
	 Re-relocate ourselves with user-controlled symbol definitions.  */
      _dl_relocate_object (&_dl_rtld_map, &_dl_default_scope[2], 0);
  }

  {
    /* Initialize _r_debug.  */
    struct r_debug *r = _dl_debug_initialize (_dl_rtld_map.l_addr);

    l = _dl_loaded;

#ifdef ELF_MACHINE_DEBUG_SETUP

    /* Some machines (e.g. MIPS) don't use DT_DEBUG in this way.  */

    ELF_MACHINE_DEBUG_SETUP (l, r);
    ELF_MACHINE_DEBUG_SETUP (&_dl_rtld_map, r);

#else

    if (l->l_info[DT_DEBUG])
      /* There is a DT_DEBUG entry in the dynamic section.  Fill it in
	 with the run-time address of the r_debug structure  */
      l->l_info[DT_DEBUG]->d_un.d_ptr = (ElfW(Addr)) r;

    /* Fill in the pointer in the dynamic linker's own dynamic section, in
       case you run gdb on the dynamic linker directly.  */
    if (_dl_rtld_map.l_info[DT_DEBUG])
      _dl_rtld_map.l_info[DT_DEBUG]->d_un.d_ptr = (ElfW(Addr)) r;

#endif

    /* Notify the debugger that all objects are now mapped in.  */
    r->r_state = RT_ADD;
    _dl_debug_state ();
  }

  /* Once we return, _dl_sysdep_start will invoke
     the DT_INIT functions and then *USER_ENTRY.  */
}

/* This is a little helper function for resolving symbols while
   tracing the binary.  */
static void
print_unresolved (const char *errstring, const char *objname)
{
  _dl_sysdep_error (errstring, "	(", objname, ")\n", NULL);
}
