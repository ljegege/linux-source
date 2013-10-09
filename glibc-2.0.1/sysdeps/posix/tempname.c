/* Copyright (C) 1991, 92, 93, 94, 95, 96 Free Software Foundation, Inc.
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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef USE_IN_LIBIO
# include "libioP.h"
# include <libio.h>
#endif

/* Return nonzero if DIR is an existent directory.  */
static int
diraccess (const char *dir)
{
  struct stat buf;
  return __stat (dir, &buf) == 0 && S_ISDIR (buf.st_mode);
}

/* Return nonzero if FILE exists.  */
static int
exists (const char *file)
{
  /* We can stat the file even if we can't read its data.  */
  struct stat st;
  int save = errno;
  if (__stat (file, &st) == 0)
    return 1;
  else
    {
      /* We report that the file exists if stat failed for a reason other
	 than nonexistence.  In this case, it may or may not exist, and we
	 don't know; but reporting that it does exist will never cause any
	 trouble, while reporting that it doesn't exist when it does would
	 violate the interface of __stdio_gen_tempname.  */
      int exists = errno != ENOENT;
      __set_errno (save);
      return exists;
    }
}


/* These are the characters used in temporary filenames.  */
static const char letters[] =
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* Generate a temporary filename and return it (in a static buffer).  If
   STREAMPTR is not NULL, open a stream "w+b" on the file and set
   *STREAMPTR to it.  If DIR_SEARCH is nonzero, DIR and PFX are used as
   described for tempnam.  If not, a temporary filename in P_tmpdir with no
   special prefix is generated.  If LENPTR is not NULL, *LENPTR is set the
   to length (including the terminating '\0') of the resultant filename,
   which is returned.  This goes through a cyclic pattern of all possible
   filenames consisting of five decimal digits of the current pid and three
   of the characters in `letters'.  Data for tempnam and tmpnam is kept
   separate, but when tempnam is using P_tmpdir and no prefix (i.e, it is
   identical to tmpnam), the same data is used.  Each potential filename is
   tested for an already-existing file of the same name, and no name of an
   existing file will be returned.  When the cycle reaches its end
   (12345ZZZ), NULL is returned.  */
char *
__stdio_gen_tempname (char *buf, size_t bufsize, const char *dir,
		      const char *pfx, int dir_search, size_t *lenptr,
		      FILE **streamptr)
{
  int saverrno = errno;
  static const char tmpdir[] = P_tmpdir;
  static size_t indices[2];
  size_t *idx;
#if 0
  static pid_t oldpid = (pid_t) 0;
#endif
  pid_t pid = __getpid();
  register size_t len, plen, dlen;
  int wrapped;

  if (dir_search)
    {
      register const char *d = __secure_getenv ("TMPDIR");
      if (d != NULL && !diraccess (d))
	d = NULL;
      if (d == NULL && dir != NULL && diraccess (dir))
	d = dir;
      if (d == NULL && diraccess (tmpdir))
	d = tmpdir;
      if (d == NULL && diraccess ("/tmp"))
	d = "/tmp";
      if (d == NULL)
	{
	  __set_errno (ENOENT);
	  return NULL;
	}
      dir = d;
    }
  else
    dir = tmpdir;

  dlen = strlen (dir);

 /* Remove trailing slashes from the directory name.  */
  while (dlen > 1 && dir[dlen - 1] == '/')
    --dlen;

  if (pfx != NULL && *pfx != '\0')
    {
      plen = strlen (pfx);
      if (plen > 5)
	plen = 5;
    }
  else
    plen = 0;

  if (dir != tmpdir && !strcmp (dir, tmpdir))
    dir = tmpdir;
  idx = &indices[(plen == 0 && dir == tmpdir) ? 1 : 0];

#if 0
  /* XXX Is this ever useful???  At least when using a thread package
     which uses different PIDs for the threads it is not helpful.  */
  if (pid != oldpid)
    {
      oldpid = pid;
      indices[0] = indices[1] = 0;
    }
#endif

  wrapped = 0; /* We have not yet wrapped around the index counter.  */
  len = dlen + 1 + plen + 5 + 3;
  while (1)
    {
      size_t i;

      if (*idx >= ((sizeof (letters) - 1) * (sizeof (letters) - 1) *
		   (sizeof (letters) - 1)))
	{
	  if (wrapped)
	    /* We really wrapped around this call.  Can't believe it
	       but nevertheless stop the endless loop.  */
	    break;

	  indices[0] = indices[1] = 0;
	  wrapped = 1;
	}

      i = (*idx)++;

      /* Construct a file name and see if it already exists.

	 We use a single counter in *IDX to cycle each of three
	 character positions through each of 62 possible letters.  */

      if (__snprintf (buf, bufsize, "%.*s/%.*s%.5d%c%c%c",
		      (int) dlen, dir, (int) plen,
		      pfx, pid % 100000,
		      letters[i % (sizeof (letters) - 1)],
		      letters[(i / (sizeof (letters) - 1))
			     % (sizeof (letters) - 1)],
		      letters[(i / ((sizeof (letters) - 1) *
				    (sizeof (letters) - 1)))
			     % (sizeof (letters) - 1)]
		    ) != (int) len)
	return NULL;

      if (streamptr != NULL)
	{
	  /* Try to create the file atomically.  */
	  int fd = __open (buf, O_RDWR|O_CREAT|O_EXCL, 0666);
	  if (fd >= 0)
	    {
	      /* We got a new file that did not previously exist.
		 Create a stream for it.  */
#ifdef USE_IN_LIBIO
	      int save;
	      struct locked_FILE
		{
		  struct _IO_FILE_plus fp;
#ifdef _IO_MTSAFE_IO
		  _IO_lock_t lock;
#endif
		} *new_f;
	      struct _IO_FILE_plus *fp;

	      new_f = (struct locked_FILE *)
		malloc (sizeof (struct locked_FILE));
	      if (new_f == NULL)
		{
		  /* We lost trying to create a stream (out of memory?).
		     Nothing to do but remove the file, close the descriptor,
		     and return failure.  */
		  save = errno;
		lose:
		  (void) remove (buf);
		  (void) __close (fd);
		  __set_errno (save);
		  return NULL;
		}
	      fp = &new_f->fp;
#ifdef _IO_MTSAFE_IO
	      fp->file._lock = &new_f->lock;
#endif
	      _IO_init (&fp->file, 0);
	      _IO_JUMPS (&fp->file) = &_IO_file_jumps;
	      _IO_file_init (&fp->file);
# if !_IO_UNIFIED_JUMPTABLES
	      fp->vtable = NULL;
# endif
	      if (_IO_file_attach (&fp->file, fd) == NULL)
		{
		  save = errno;
		  free (fp);
		  goto lose;
		}
	      fp->file._flags &= ~_IO_DELETE_DONT_CLOSE;

	      *streamptr = (FILE *) fp;
#else
	      *streamptr = __newstream ();
	      if (*streamptr == NULL)
		{
		  /* We lost trying to create a stream (out of memory?).
		     Nothing to do but remove the file, close the descriptor,
		     and return failure.  */
		  const int save = errno;
		  (void) remove (buf);
		  (void) __close (fd);
		  __set_errno (save);
		  return NULL;
		}
	      (*streamptr)->__cookie = (__ptr_t) (long int) fd;
	      (*streamptr)->__mode.__write = 1;
	      (*streamptr)->__mode.__read = 1;
	      (*streamptr)->__mode.__binary = 1;
#endif
	    }
#if defined EMFILE || defined ENFILE || defined EINTR
	  else if (0
# ifdef EMFILE
		   || errno == EMFILE
# endif
# ifdef ENFILE
		   || errno == ENFILE
# endif
# ifdef EINTR
		   || errno == EINTR
# endif
		   )
	    /* We cannot open anymore files since all descriptors are
	       used or because we got a signal.  */
	    return NULL;
#endif
	  else
	    continue;
	}
      else if (exists (buf))
	continue;

      /* If the file already existed we have continued the loop above,
	 so we only get here when we have a winning name to return.  */

      __set_errno (saverrno);

      if (lenptr != NULL)
	*lenptr = len + 1;
      return buf;
    }

  /* We got out of the loop because we ran out of combinations to try.  */
  __set_errno (EEXIST);		/* ? */
  return NULL;
}
