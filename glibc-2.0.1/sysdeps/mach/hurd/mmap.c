/* Copyright (C) 1994, 1995, 1996 Free Software Foundation, Inc.
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
not, write to the Free Software Foundation, Inc., 675 Mass Ave,
Cambridge, MA 02139, USA.  */

#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <hurd.h>
#include <hurd/fd.h>

/* Map addresses starting near ADDR and extending for LEN bytes.  from
   OFFSET into the file FD describes according to PROT and FLAGS.  If ADDR
   is nonzero, it is the desired mapping address.  If the MAP_FIXED bit is
   set in FLAGS, the mapping will be at ADDR exactly (which must be
   page-aligned); otherwise the system chooses a convenient nearby address.
   The return value is the actual mapping address chosen or (caddr_t) -1
   for errors (in which case `errno' is set).  A successful `mmap' call
   deallocates any previous mapping for the affected region.  */

caddr_t
__mmap (caddr_t addr, size_t len, int prot, int flags, int fd, off_t offset)
{
  error_t err;
  vm_prot_t vmprot;
  memory_object_t memobj;
  vm_address_t mapaddr;
  vm_size_t pageoff;

  pageoff = offset & (vm_page_size - 1);
  offset &= ~(vm_page_size - 1);

  mapaddr = (vm_address_t) addr;
  if (flags & MAP_FIXED)
    {
      /* A specific address is requested.  It need not be page-aligned;
	 it just needs to be congruent with the object offset.  */
      if ((mapaddr & (vm_page_size - 1)) != pageoff)
	return (caddr_t) (long int) __hurd_fail (EINVAL);
      else
	/* We will add back PAGEOFF after mapping.  */
	mapaddr -= pageoff;
    }

  vmprot = VM_PROT_NONE;
  if (prot & PROT_READ)
    vmprot |= VM_PROT_READ;
  if (prot & PROT_WRITE)
    vmprot |= VM_PROT_WRITE;
  if (prot & PROT_EXEC)
    vmprot |= VM_PROT_EXECUTE;

  switch (flags & MAP_TYPE)
    {
    default:
      return (caddr_t) (long int) __hurd_fail (EINVAL);

    case MAP_ANON:
      memobj = MACH_PORT_NULL;
      break;

    case MAP_FILE:
    case 0:			/* Allow, e.g., just MAP_SHARED.  */
      {
	mach_port_t robj, wobj;
	if (err = HURD_DPORT_USE (fd, __io_map (port, &robj, &wobj)))
	  return (caddr_t) (long int) __hurd_dfail (fd, err);
	switch (prot & (PROT_READ|PROT_WRITE))
	  {
	  case PROT_READ:
	    memobj = robj;
	    if (wobj != MACH_PORT_NULL)
	      __mach_port_deallocate (__mach_task_self (), wobj);
	    break;
	  case PROT_WRITE:
	    memobj = wobj;
	    if (robj != MACH_PORT_NULL)
	      __mach_port_deallocate (__mach_task_self (), robj);
	    break;
	  case PROT_READ|PROT_WRITE:
	    if (robj == wobj)
	      {
		memobj = wobj;
		/* Remove extra reference.  */
		__mach_port_deallocate (__mach_task_self (), memobj);
	      }
	    else if (wobj == MACH_PORT_NULL && /* Not writable by mapping.  */
		     (flags & (MAP_COPY|MAP_PRIVATE)))
	      /* The file can only be mapped for reading.  Since we are
		 making a private mapping, we will never try to write the
		 object anyway, so we don't care.  */
	      memobj = robj;
	    else
	      {
		__mach_port_deallocate (__mach_task_self (), wobj);
		return ((caddr_t) (long int)
			__hurd_fail (EGRATUITOUS)); /* XXX */
	      }
	    break;
	  }
	break;
	/* XXX handle MAP_NOEXTEND */
      }
    }

  /* XXX handle MAP_INHERIT */

  err = __vm_map (__mach_task_self (),
		  &mapaddr, (vm_size_t) len, (vm_address_t) 0,
		  ! (flags & MAP_FIXED),
		  memobj, (vm_offset_t) offset,
		  ! (flags & MAP_SHARED),
		  vmprot, VM_PROT_ALL,
		  (flags & MAP_SHARED) ? VM_INHERIT_SHARE : VM_INHERIT_COPY);

  if (err == KERN_NO_SPACE && (flags & MAP_FIXED))
    {
      /* XXX this is not atomic as it is in unix! */
      /* The region is already allocated; deallocate it first.  */
      err = __vm_deallocate (__mach_task_self (), mapaddr, len);
      if (! err)
	err = __vm_map (__mach_task_self (),
			&mapaddr, (vm_size_t) len, (vm_address_t) 0,
			0, memobj, (vm_offset_t) offset,
			! (flags & MAP_SHARED),
			vmprot, VM_PROT_ALL,
			(flags & MAP_SHARED) ? VM_INHERIT_SHARE
			: VM_INHERIT_COPY);
    }

  if (memobj != MACH_PORT_NULL)
    __mach_port_deallocate (__mach_task_self (), memobj);

  if (err)
    return (caddr_t) (long int) __hurd_fail (err);

  /* Adjust the mapping address for the offset-within-page.  */
  mapaddr += pageoff;

  return (caddr_t) mapaddr;
}

weak_alias (__mmap, mmap)

