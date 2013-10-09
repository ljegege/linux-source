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

#include <errno.h>
#include <sys/socket.h>
#include <hurd.h>
#include <hurd/socket.h>
#include <hurd/fd.h>
#include <sys/un.h>
#include <hurd/ifsock.h>

/* Send N bytes of BUF on socket FD to peer at address ADDR (which is
   ADDR_LEN bytes long).  Returns the number sent, or -1 for errors.  */
int
sendto (int fd,
	const void *buf,
	size_t n,
	int flags,
	const struct sockaddr_un *addr,
	size_t addr_len)
{
  addr_port_t aport;
  error_t err;
  int wrote;

  if (addr->sun_family == AF_LOCAL)
    {
      /* For the local domain, we must look up the name as a file and talk
	 to it with the ifsock protocol.  */
      file_t file = __file_name_lookup (addr->sun_path, 0, 0);
      if (file == MACH_PORT_NULL)
	return -1;
      err = __ifsock_getsockaddr (file, &aport);
      __mach_port_deallocate (__mach_task_self (), file);
      if (err == MIG_BAD_ID || err == EOPNOTSUPP)
	/* The file did not grok the ifsock protocol.  */
	err = ENOTSOCK;
      if (err)
	return __hurd_fail (err);
    }
  else
    err = EIEIO;

  /* Get an address port for the desired destination address.  */
  err = HURD_DPORT_USE (fd,
			({
			  if (err)
			    err = __socket_create_address (port,
							   addr->sun_family,
							   (char *) addr,
							   addr_len,
							   &aport);
			  if (! err)
			    {
			      /* Send the data.  */
			      err = __socket_send (port, aport,
						   flags, buf, n,
						   NULL,
						   MACH_MSG_TYPE_COPY_SEND, 0,
						   NULL, 0, &wrote);
			      __mach_port_deallocate (__mach_task_self (),
						      aport);
			    }
			  err;
			}));

  return err ? __hurd_dfail (fd, err) : wrote;
}
