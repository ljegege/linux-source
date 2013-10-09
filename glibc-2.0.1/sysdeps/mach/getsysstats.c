/* System dependent pieces of sysconf; Mach version
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
not, write to the Free Software Foundation, Inc., 675 Mass Ave,
Cambridge, MA 02139, USA.  */

#include <errno.h>
#include <mach.h>
#include <hurd.h>
#include <sys/sysinfo.h>


/* Return the number of processors configured on the system. */
int
__get_nprocs_conf ()
{
  struct host_basic_info hbi;
  kern_return_t err;
  mach_msg_type_number_t cnt = HOST_BASIC_INFO_COUNT;

  err = __host_info (__mach_host_self (), HOST_BASIC_INFO, &hbi, &cnt);
  if (err)
    return __hurd_fail (err);
  else if (cnt != HOST_BASIC_INFO_COUNT)
    return __hurd_fail (EIEIO);

  return hbi.max_cpus;
}

/* Return the number of processors currently available on the system. */
int
__get_nprocs ()
{
  struct host_basic_info hbi;
  kern_return_t err;
  mach_msg_type_number_t cnt = HOST_BASIC_INFO_COUNT;

  err = __host_info (__mach_host_self (), HOST_BASIC_INFO, &hbi, &cnt);
  if (err)
    return __hurd_fail (err);
  else if (cnt != HOST_BASIC_INFO_COUNT)
    return __hurd_fail (EIEIO);

  return hbi.avail_cpus;
}

/* Return the number of physical pages on the system. */
int
__get_phys_pages ()
{
  struct host_basic_info hbi;
  kern_return_t err;
  mach_msg_type_number_t cnt = HOST_BASIC_INFO_COUNT;

  err = __host_info (__mach_host_self (), HOST_BASIC_INFO, &hbi, &cnt);
  if (err)
    return __hurd_fail (err);
  else if (cnt != HOST_BASIC_INFO_COUNT)
    return __hurd_fail (EIEIO);

  return hbi.memory_size / __vm_page_size;
}

/* Return the number of available physical pages */
int
__get_avphys_pages ()
{
  vm_statistics_data_t vs;
  kern_return_t err;

  err = __vm_statistics (__mach_task_self (), &vs);
  if (err)
    return __hurd_fail (err);

  return vs.free_count;
}
