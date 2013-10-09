/* Operating system support for run-time dynamic linker.  Hurd version.
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

#include <hurd.h>
#include <link.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <assert.h>
#include <sysdep.h>
#include <mach/mig_support.h>
#include "hurdstartup.h"
#include <mach/host_info.h>
#include "../stdio-common/_itoa.h"
#include <hurd/auth.h>
#include <hurd/term.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/stat.h>

#include "dl-machine.h"

extern void __mach_init (void);

extern int _dl_argc;
extern char **_dl_argv;
extern char **_environ;

int __libc_enable_secure;

struct hurd_startup_data *_dl_hurd_data;

unsigned int __hurd_threadvar_max = _HURD_THREADVAR_MAX;
static unsigned long int threadvars[_HURD_THREADVAR_MAX];
unsigned long int __hurd_threadvar_stack_offset
  = (unsigned long int) &threadvars;
unsigned long int __hurd_sigthread_stack_base;
unsigned long int __hurd_sigthread_stack_end;
unsigned long int *__hurd_sigthread_variables;
unsigned long int __hurd_threadvar_stack_mask;


/* XXX loser kludge for vm_map kernel bug */
static vm_address_t fmha;
static vm_size_t fmhs;
static void unfmh(void){
__vm_deallocate(__mach_task_self(),fmha,fmhs);}
static void fmh(void) {
    error_t err;int x;mach_port_t p;
    vm_address_t a=0x08000000U,max=VM_MAX_ADDRESS;
    while (!(err=__vm_region(__mach_task_self(),&a,&fmhs,&x,&x,&x,&x,&p,&x))){
      __mach_port_deallocate(__mach_task_self(),p);
      if (a+fmhs>=0x80000000U){
	max=a; break;}
      fmha=a+=fmhs;}
    if (err) assert(err==KERN_NO_SPACE);
    if (!fmha)fmhs=0;else{
    fmhs=max-fmha;
    err = __vm_map (__mach_task_self (),
		    &fmha, fmhs, 0, 0, MACH_PORT_NULL, 0, 1,
		    VM_PROT_NONE, VM_PROT_NONE, VM_INHERIT_COPY);
    assert_perror(err);}
  }
/* XXX loser kludge for vm_map kernel bug */



Elf32_Addr
_dl_sysdep_start (void **start_argptr,
		  void (*dl_main) (const Elf32_Phdr *phdr, Elf32_Word phent,
				   Elf32_Addr *user_entry))
{
  extern void _start ();

  void go (int *argdata)
    {
      extern unsigned int _dl_skip_args; /* rtld.c */
      char **p;

      /* Cache the information in various global variables.  */
      _dl_argc = *argdata;
      _dl_argv = 1 + (char **) argdata;
      _environ = &_dl_argv[_dl_argc + 1];
      for (p = _environ; *p++;); /* Skip environ pointers and terminator.  */

      if ((void *) p == _dl_argv[0])
	{
	  static struct hurd_startup_data nodata;
	  _dl_hurd_data = &nodata;
	  nodata.user_entry = (vm_address_t) &_start;
	}
      else
	_dl_hurd_data = (void *) p;

      __libc_enable_secure = _dl_hurd_data->flags & EXEC_SECURE;

      if (_dl_hurd_data->flags & EXEC_STACK_ARGS &&
	  _dl_hurd_data->user_entry == 0)
	_dl_hurd_data->user_entry = (vm_address_t) &_start;

unfmh();			/* XXX */

      if (_dl_hurd_data->user_entry == (vm_address_t) &_start)
	/* We were invoked as a command, not as the program interpreter.
	   The generic ld.so code supports this: it will parse the args
	   as "ld.so PROGRAM [ARGS...]".  For booting the Hurd, we
	   support an additional special syntax:
	     ld.so [-LIBS...] PROGRAM [ARGS...]
	   Each LIBS word consists of "FILENAME=MEMOBJ";
	   for example "-/lib/libc.so=123" says that the contents of
	   /lib/libc.so are found in a memory object whose port name
	   in our task is 123.  */
	while (_dl_argc > 2 && _dl_argv[1][0] == '-' && _dl_argv[1][1] != '-')
	  {
	    char *lastslash, *memobjname, *p;
	    struct link_map *l;
	    mach_port_t memobj;
	    error_t err;

	    ++_dl_skip_args;
	    --_dl_argc;
	    p = _dl_argv++[1] + 1;

	    memobjname = strchr (p, '=');
	    if (! memobjname)
	      _dl_sysdep_fatal ("Bogus library spec: ", p, "\n", NULL);
	    *memobjname++ = '\0';
	    memobj = 0;
	    while (*memobjname != '\0')
	      memobj = (memobj * 10) + (*memobjname++ - '0');

	    /* Add a user reference on the memory object port, so we will
	       still have one after _dl_map_object_from_fd calls our
	       `close'.  */
	    err = __mach_port_mod_refs (__mach_task_self (), memobj,
					MACH_PORT_RIGHT_SEND, +1);
	    assert_perror (err);

	    lastslash = strrchr (p, '/');
	    l = _dl_map_object_from_fd (lastslash ? lastslash + 1 : p,
					memobj, strdup (p));

	    /* Squirrel away the memory object port where it
	       can be retrieved by the program later.  */
	    l->l_info[DT_NULL] = (void *) memobj;
	  }

      /* Call elf/rtld.c's main program.  It will set everything
	 up and leave us to transfer control to USER_ENTRY.  */
      (*dl_main) ((const Elf32_Phdr *) _dl_hurd_data->phdr,
		  _dl_hurd_data->phdrsz / sizeof (Elf32_Phdr),
		  &_dl_hurd_data->user_entry);

      if (_dl_skip_args && _dl_argv[-_dl_skip_args] == (char *) p)
	{
	  /* We are ignoring the first few arguments, but we have no Hurd
	     startup data.  It is magical convention that ARGV[0] == P in
	     this case.  The startup code in init-first.c will get confused
	     if this is not the case, so we must rearrange things to make
	     it so.  Overwrite the original ARGV[0] at P with
	     ARGV[_dl_skip_args].  */
	  assert ((char *) p < _dl_argv[0]);
	  _dl_argv[0] = strcpy ((char *) p, _dl_argv[0]);
	}

      {
	extern void _dl_start_user (void);
	/* Unwind the stack to ARGDATA and simulate a return from _dl_start
	   to the RTLD_START code which will run the user's entry point.  */
	RETURN_TO (argdata, &_dl_start_user, _dl_hurd_data->user_entry);
      }
    }

  /* Set up so we can do RPCs.  */
  __mach_init ();

fmh();				/* XXX */

  /* See hurd/hurdstartup.c; this deals with getting information
     from the exec server and slicing up the arguments.
     Then it will call `go', above.  */
  _hurd_startup (start_argptr, &go);

  LOSE;
  abort ();
}

void
_dl_sysdep_start_cleanup (void)
{
  /* Deallocate the reply port and task port rights acquired by
     __mach_init.  We are done with them now, and the user will
     reacquire them for himself when he wants them.  */
  __mig_dealloc_reply_port (MACH_PORT_NULL);
  __mach_port_deallocate (__mach_task_self (), __mach_task_self_);
}

void
_dl_sysdep_fatal (const char *msg, ...)
{
  va_list ap;

  va_start (ap, msg);
  do
    {
      size_t len = strlen (msg);
      mach_msg_type_number_t nwrote;
      do
	{
	  if (__io_write (_hurd_init_dtable[2], msg, len, -1, &nwrote))
	    break;
	  len -= nwrote;
	  msg += nwrote;
	} while (nwrote > 0);
      msg = va_arg (ap, const char *);
    } while (msg);
  va_end (ap);

  _exit (127);
}


void
_dl_sysdep_error (const char *msg, ...)
{
  va_list ap;

  va_start (ap, msg);
  do
    {
      size_t len = strlen (msg);
      mach_msg_type_number_t nwrote;
      do
	{
	  if (__io_write (_hurd_init_dtable[2], msg, len, -1, &nwrote))
	    break;
	  len -= nwrote;
	  msg += nwrote;
	} while (nwrote > 0);
      msg = va_arg (ap, const char *);
    } while (msg);
  va_end (ap);
}


void
_dl_sysdep_message (const char *msg, ...)
{
  va_list ap;

  va_start (ap, msg);
  do
    {
      size_t len = strlen (msg);
      mach_msg_type_number_t nwrote;
      do
	{
	  if (__io_write (_hurd_init_dtable[1], msg, len, -1, &nwrote))
	    break;
	  len -= nwrote;
	  msg += nwrote;
	} while (nwrote > 0);
      msg = va_arg (ap, const char *);
    } while (msg);
  va_end (ap);
}

/* Minimal open/close/mmap implementation sufficient for initial loading of
   shared libraries.  These are weak definitions so that when the
   dynamic linker re-relocates itself to be user-visible (for -ldl),
   it will get the user's definition (i.e. usually libc's).  */

/* Open FILE_NAME and return a read-mmappable port in MEMOBJ_RD for it, or
   return an error.  If STAT is non-zero, stat the file into that stat buffer.  */
static error_t
open_file (const char *file_name, int mode,
	   mach_port_t *memobj_rd, struct stat *stat)
{
  enum retry_type doretry;
  char retryname[1024];		/* XXX string_t LOSES! */
  file_t startdir, newpt, fileport;
  int dealloc_dir;
  int nloops;
  error_t err;

  assert (mode == O_RDONLY);

  startdir = _dl_hurd_data->portarray[file_name[0] == '/' ?
				      INIT_PORT_CRDIR : INIT_PORT_CWDIR];

  while (file_name[0] == '/')
    file_name++;

  if (err = __dir_lookup (startdir, (char *)file_name, mode, 0,
			  &doretry, retryname, &fileport))
    return err;

  dealloc_dir = 0;
  nloops = 0;

  while (1)
    {
      if (dealloc_dir)
	__mach_port_deallocate (__mach_task_self (), startdir);
      if (err)
	return err;

      switch (doretry)
	{
	case FS_RETRY_REAUTH:
	  {
	    mach_port_t ref = __mach_reply_port ();
	    err = __io_reauthenticate (fileport, ref, MACH_MSG_TYPE_MAKE_SEND);
	    if (! err)
	      err = __auth_user_authenticate
		(_dl_hurd_data->portarray[INIT_PORT_AUTH],
		 ref, MACH_MSG_TYPE_MAKE_SEND,
		 &newpt);
	    __mach_port_destroy (__mach_task_self (), ref);
	  }
	  __mach_port_deallocate (__mach_task_self (), fileport);
	  if (err)
	    return err;
	  fileport = newpt;
	  /* Fall through.  */

	case FS_RETRY_NORMAL:
#ifdef SYMLOOP_MAX
	  if (nloops++ >= SYMLOOP_MAX)
	    return ELOOP;
#endif

	  /* An empty RETRYNAME indicates we have the final port.  */
	  if (retryname[0] == '\0')
	    {
	      mach_port_t memobj_wr;

	      dealloc_dir = 1;

	    opened:
	      /* We have the file open.  Now map it.  */

	      if (stat)
		err = __io_stat (fileport, stat);
	      if (! err)
		err = __io_map (fileport, memobj_rd, &memobj_wr);

	      if (dealloc_dir)
		__mach_port_deallocate (__mach_task_self (), fileport);
	      if (err)
		return err;

	      if (memobj_wr != MACH_PORT_NULL)
		__mach_port_deallocate (__mach_task_self (), memobj_wr);

	      return 0;
	    }

	  startdir = fileport;
	  dealloc_dir = 1;
	  file_name = retryname;
	  break;

	case FS_RETRY_MAGICAL:
	  switch (retryname[0])
	    {
	    case '/':
	      startdir = _dl_hurd_data->portarray[INIT_PORT_CRDIR];
	      dealloc_dir = 0;
	      if (fileport != MACH_PORT_NULL)
		__mach_port_deallocate (__mach_task_self (), fileport);
	      file_name = &retryname[1];
	      break;

	    case 'f':
	      if (retryname[1] == 'd' && retryname[2] == '/' &&
		  isdigit (retryname[3]))
		{
		  /* We can't use strtol for the decoding here
		     because it brings in hairy locale bloat.  */
		  char *p;
		  int fd = 0;
		  for (p = &retryname[3]; isdigit (*p); ++p)
		    fd = (fd * 10) + (*p - '0');
		  /* Check for excess text after the number.  A slash is
		     valid; it ends the component.  Anything else does not
		     name a numeric file descriptor.  */
		  if (*p != '/' && *p != '\0')
		    return ENOENT;
		  if (fd < 0 || fd >= _dl_hurd_data->dtablesize ||
		      _dl_hurd_data->dtable[fd] == MACH_PORT_NULL)
		    /* If the name was a proper number, but the file
		       descriptor does not exist, we return EBADF instead
		       of ENOENT.  */
		    return EBADF;
		  fileport = _dl_hurd_data->dtable[fd];
		  if (*p == '\0')
		    {
		      /* This descriptor is the file port we want.  */
		      dealloc_dir = 0;
		      goto opened;
		    }
		  else
		    {
		      /* Do a normal retry on the remaining components.  */
		      startdir = fileport;
		      dealloc_dir = 1;
		      file_name = p + 1; /* Skip the slash.  */
		      break;
		    }
		}
	      else
		goto bad_magic;
	      break;

	    case 'm':
	      if (retryname[1] == 'a' && retryname[2] == 'c' &&
		  retryname[3] == 'h' && retryname[4] == 't' &&
		  retryname[5] == 'y' && retryname[6] == 'p' &&
		  retryname[7] == 'e')
		{
		  error_t err;
		  struct host_basic_info hostinfo;
		  mach_msg_type_number_t hostinfocnt = HOST_BASIC_INFO_COUNT;
		  char *p;
		  if (err = __host_info (__mach_host_self (), HOST_BASIC_INFO,
					 (natural_t *) &hostinfo,
					 &hostinfocnt))
		    return err;
		  if (hostinfocnt != HOST_BASIC_INFO_COUNT)
		    return EGRATUITOUS;
		  p = _itoa (hostinfo.cpu_subtype, &retryname[8], 10, 0);
		  *--p = '/';
		  p = _itoa (hostinfo.cpu_type, &retryname[8], 10, 0);
		  if (p < retryname)
		    abort ();	/* XXX write this right if this ever happens */
		  if (p > retryname)
		    strcpy (retryname, p);
		  startdir = fileport;
		  dealloc_dir = 1;
		}
	      else
		goto bad_magic;
	      break;

	    case 't':
	      if (retryname[1] == 't' && retryname[2] == 'y')
		switch (retryname[3])
		  {
		    error_t opentty (file_t *result)
		      {
			error_t err;
			file_t unauth;
			err = __termctty_open_terminal
			  (_dl_hurd_data->portarray[INIT_PORT_CTTYID],
			   mode, &unauth);
			if (! err)
			  {
			    mach_port_t ref = __mach_reply_port ();
			    err = __io_reauthenticate
			      (unauth, ref, MACH_MSG_TYPE_MAKE_SEND);
			    if (! err)
			      err = __auth_user_authenticate
				(_dl_hurd_data->portarray[INIT_PORT_AUTH],
				 ref, MACH_MSG_TYPE_MAKE_SEND,
				 result);
			    __mach_port_deallocate (__mach_task_self (),
						    unauth);
			    __mach_port_destroy (__mach_task_self (), ref);
			  }
			return err;
		      }

		  case '\0':
		    if (err = opentty (&fileport))
		      return err;
		    dealloc_dir = 1;
		    goto opened;
		  case '/':
		    if (err = opentty (&startdir))
		      return err;
		    dealloc_dir = 1;
		    strcpy (retryname, &retryname[4]);
		    break;
		  default:
		    goto bad_magic;
		  }
	      else
		goto bad_magic;
	      break;

	    default:
	    bad_magic:
	      return EGRATUITOUS;
	    }
	  break;

	default:
	  return EGRATUITOUS;
	}

      err = __dir_lookup (startdir, (char *)file_name, mode, 0,
			  &doretry, retryname, &fileport);
    }
}

int weak_function
__open (const char *file_name, int mode, ...)
{
  mach_port_t memobj_rd;
  error_t err = open_file (file_name, mode, &memobj_rd, 0);
  if (err)
    return __hurd_fail (err);
  else
    return (int)memobj_rd;
}

int weak_function
__close (int fd)
{
  if (fd != (int) MACH_PORT_NULL)
    __mach_port_deallocate (__mach_task_self (), (mach_port_t) fd);
  return 0;
}

caddr_t weak_function
__mmap (caddr_t addr, size_t len, int prot, int flags, int fd, off_t offset)
{
  error_t err;
  vm_prot_t vmprot;
  vm_address_t mapaddr;

  vmprot = VM_PROT_NONE;
  if (prot & PROT_READ)
    vmprot |= VM_PROT_READ;
  if (prot & PROT_WRITE)
    vmprot |= VM_PROT_WRITE;
  if (prot & PROT_EXEC)
    vmprot |= VM_PROT_EXECUTE;

  mapaddr = (vm_address_t) addr;
  err = __vm_map (__mach_task_self (),
		  &mapaddr, (vm_size_t) len, 0 /*ELF_MACHINE_USER_ADDRESS_MASK*/,
		  !(flags & MAP_FIXED),
		  (flags & MAP_ANON) ? MACH_PORT_NULL : (mach_port_t) fd,
		  (vm_offset_t) offset,
		  flags & (MAP_COPY|MAP_PRIVATE),
		  vmprot, VM_PROT_ALL,
		  (flags & MAP_SHARED) ? VM_INHERIT_SHARE : VM_INHERIT_COPY);
  if (err == KERN_NO_SPACE && (flags & MAP_FIXED))
    {
      /* XXX this is not atomic as it is in unix! */
      /* The region is already allocated; deallocate it first.  */
      err = __vm_deallocate (__mach_task_self (), mapaddr, len);
      if (! err)
	err = __vm_map (__mach_task_self (),
			&mapaddr, (vm_size_t) len, 0 /*ELF_MACHINE_USER_ADDRESS_MASK*/,
			!(flags & MAP_FIXED),
			(mach_port_t) fd, (vm_offset_t) offset,
			flags & (MAP_COPY|MAP_PRIVATE),
			vmprot, VM_PROT_ALL,
			(flags & MAP_SHARED)
			? VM_INHERIT_SHARE : VM_INHERIT_COPY);
    }

  return err ? (caddr_t) __hurd_fail (err) : (caddr_t) mapaddr;
}

void weak_function
_exit (int status)
{
  __proc_mark_exit (_dl_hurd_data->portarray[INIT_PORT_PROC],
		    W_EXITCODE (status, 0), 0);
  while (__task_terminate (__mach_task_self ()))
    __mach_task_self_ = (__mach_task_self) ();
}

/* Read the whole contents of FILE into new mmap'd space with given
   protections.  The size of the file is returned in SIZE.  */
void *
_dl_sysdep_read_whole_file (const char *file, size_t *size, int prot)
{
  struct stat stat;
  mach_port_t memobj_rd;
  void *contents;
  error_t err = open_file (file, O_RDONLY, &memobj_rd, &stat);

  if (! err)
    {
      /* Map a copy of the file contents.  */
      contents = __mmap (0, stat.st_size, prot, MAP_COPY, memobj_rd, 0);
      if (contents == (void *)-1)
	contents = 0;
      else
	*size = stat.st_size;

      __mach_port_deallocate (__mach_task_self (), memobj_rd);
    }
  else
    {
      __hurd_fail (err);
      contents = 0;
    }

  return contents;
}

/* This function is called by interruptible RPC stubs.  For initial
   dynamic linking, just use the normal mach_msg.  Since this defn is
   weak, the real defn in libc.so will override it if we are linked into
   the user program (-ldl).  */

error_t weak_function
_hurd_intr_rpc_mach_msg (mach_msg_header_t *msg,
			 mach_msg_option_t option,
			 mach_msg_size_t send_size,
			 mach_msg_size_t rcv_size,
			 mach_port_t rcv_name,
			 mach_msg_timeout_t timeout,
			 mach_port_t notify)
{
  return __mach_msg (msg, option, send_size, rcv_size, rcv_name,
		     timeout, notify);
}
