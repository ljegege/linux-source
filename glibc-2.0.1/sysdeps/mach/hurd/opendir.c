/* Copyright (C) 1993, 1994, 1995, 1996 Free Software Foundation, Inc.
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
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <hurd.h>
#include <hurd/fd.h>
#include "dirstream.h"


/* Open a directory stream on NAME.  */
DIR *
__opendir (const char *name)
{
  DIR *dirp;
  int fd;
  struct hurd_fd *d;

  fd = __open (name, O_RDONLY);
  if (fd < 0)
    return NULL;

  dirp = (DIR *) malloc (sizeof (DIR));
  if (dirp == NULL)
    {
      __close (fd);
      return NULL;
    }

  /* Extract the pointer to the descriptor structure.  */
  __mutex_lock (&_hurd_dtable_lock);
  d = dirp->__fd = _hurd_dtable[fd];
  __mutex_unlock (&_hurd_dtable_lock);

  /* Set the descriptor to close on exec. */
  __spin_lock (&d->port.lock);
  d->flags |= FD_CLOEXEC;
  __spin_unlock (&d->port.lock);

  dirp->__data = dirp->__ptr = NULL;
  dirp->__entry_data = dirp->__entry_ptr = 0;
  dirp->__allocation = 0;
  dirp->__size = 0;

  __libc_lock_init (dirp->__lock);

  return dirp;
}
weak_alias (__opendir, opendir)
