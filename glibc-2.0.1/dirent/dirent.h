/* Copyright (C) 1991, 92, 93, 94, 95, 96, 97 Free Software Foundation, Inc.
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

/*
 *	POSIX Standard: 5.1.2 Directory Operations	<dirent.h>
 */

#ifndef	_DIRENT_H

#define	_DIRENT_H	1
#include <features.h>

__BEGIN_DECLS

#include <gnu/types.h>

/* This file defines `struct dirent'.

   It defines the macro `_DIRENT_HAVE_D_NAMLEN' iff there is a `d_namlen'
   member that gives the length of `d_name'.

   It defines the macro `_DIRENT_HAVE_D_RECLEN' iff there is a `d_reclen'
   member that gives the size of the entire directory entry.

   It defines the macro `_DIRENT_HAVE_D_OFF' iff there is a `d_off'
   member that gives the file offset of the next directory entry.

   It defines the macro `_DIRENT_HAVE_D_TYPE' iff there is a `d_type'
   member that gives the type of the file.
 */

#include <direntry.h>

#if (defined __USE_BSD || defined __USE_MISC) && !defined d_fileno
# define d_ino	d_fileno		 /* Backward compatibility.  */
#endif

/* These macros extract size information from a `struct dirent *'.
   They may evaluate their argument multiple times, so it must not
   have side effects.  Each of these may involve a relatively costly
   call to `strlen' on some systems, so these values should be cached.

   _D_EXACT_NAMLEN (DP)	returns the length of DP->d_name, not including
   its terminating null character.

   _D_ALLOC_NAMLEN (DP)	returns a size at least (_D_EXACT_NAMLEN (DP) + 1);
   that is, the allocation size needed to hold the DP->d_name string.
   Use this macro when you don't need the exact length, just an upper bound.
   This macro is less likely to require calling `strlen' than _D_EXACT_NAMLEN.
   */

#ifdef _DIRENT_HAVE_D_NAMLEN
# define _D_EXACT_NAMLEN(d) ((d)->d_namlen)
# define _D_ALLOC_NAMLEN(d) (_D_EXACT_NAMLEN (d) + 1)
#else
# define _D_EXACT_NAMLEN(d) (strlen ((d)->d_name))
# ifdef _DIRENT_HAVE_D_RECLEN
#  define _D_ALLOC_NAMLEN(d) (((char *) (d) + (d)->d_reclen) - &(d)->d_name[0])
# else
#  define _D_ALLOC_NAMLEN(d) (sizeof (d)->d_name > 1 ? sizeof (d)->d_name : \
			      _D_EXACT_NAMLEN (d) + 1)
# endif
#endif


#ifdef __USE_BSD
/* File types for `d_type'.  */
enum
  {
    DT_UNKNOWN = 0,
    DT_FIFO = 1,
    DT_CHR = 2,
    DT_DIR = 4,
    DT_BLK = 6,
    DT_REG = 8,
    DT_LNK = 10,
    DT_SOCK = 12
  };

/* Convert between stat structure types and directory types.  */
# define IFTODT(mode)	(((mode) & 0170000) >> 12)
# define DTTOIF(dirtype)	((dirtype) << 12)
#endif


/* This is the data type of directory stream objects.
   The actual structure is opaque to users.  */
typedef struct __dirstream DIR;

/* Open a directory stream on NAME.
   Return a DIR stream on the directory, or NULL if it could not be opened.  */
extern DIR *__opendir __P ((__const char *__name));
extern DIR *opendir __P ((__const char *__name));

/* Close the directory stream DIRP.
   Return 0 if successful, -1 if not.  */
extern int __closedir __P ((DIR *__dirp));
extern int closedir __P ((DIR *__dirp));

/* Read a directory entry from DIRP.
   Return a pointer to a `struct dirent' describing the entry,
   or NULL for EOF or error.  The storage returned may be overwritten
   by a later readdir call on the same DIR stream.  */
extern struct dirent *__readdir __P ((DIR *__dirp));
extern struct dirent *readdir __P ((DIR *__dirp));

#if defined __USE_POSIX || defined __USE_MISC
/* Reentrant version of `readdir'.  Return in RESULT a pointer to the
   next entry.  */
extern int __readdir_r __P ((DIR *__dirp, struct dirent *__entry,
			     struct dirent **__result));
extern int readdir_r __P ((DIR *__dirp, struct dirent *__entry,
			   struct dirent **__result));
#endif	/* POSIX or misc */

/* Rewind DIRP to the beginning of the directory.  */
extern void rewinddir __P ((DIR *__dirp));

#if defined __USE_BSD || defined __USE_MISC

/* Return the file descriptor used by DIRP.  */
extern int dirfd __P ((DIR *__dirp));

# if defined __OPTIMIZE__ && defined _DIR_dirfd
#  define dirfd(dirp)	_DIR_dirfd (dirp)
# endif

# ifndef MAXNAMLEN
/* Get the definitions of the POSIX.1 limits.  */
#  include <posix1_lim.h>

/* `MAXNAMLEN' is the BSD name for what POSIX calls `NAME_MAX'.  */
#  ifdef NAME_MAX
#   define MAXNAMLEN	NAME_MAX
#  else
#   define MAXNAMLEN	255
#  endif
# endif

# include <gnu/types.h>
# define __need_size_t
# include <stddef.h>

/* Seek to position POS on DIRP.  */
extern void seekdir __P ((DIR *__dirp, __off_t __pos));

/* Return the current position of DIRP.  */
extern __off_t telldir __P ((DIR *__dirp));

/* Scan the directory DIR, calling SELECTOR on each directory entry.
   Entries for which SELECT returns nonzero are individually malloc'd,
   sorted using qsort with CMP, and collected in a malloc'd array in
   *NAMELIST.  Returns the number of entries selected, or -1 on error.  */
extern int scandir __P ((__const char *__dir,
			 struct dirent ***__namelist,
			 int (*__selector) __P ((struct dirent *)),
			 int (*__cmp) __P ((__const __ptr_t,
					    __const __ptr_t))));

/* Function to compare two `struct dirent's alphabetically.  */
extern int alphasort __P ((__const __ptr_t, __const __ptr_t));


/* Read directory entries from FD into BUF, reading at most NBYTES.
   Reading starts at offset *BASEP, and *BASEP is updated with the new
   position after reading.  Returns the number of bytes read; zero when at
   end of directory; or -1 for errors.  */
extern __ssize_t __getdirentries __P ((int __fd, char *__buf,
				       size_t __nbytes, __off_t *__basep));
extern __ssize_t getdirentries __P ((int __fd, char *__buf,
				     size_t __nbytes, __off_t *__basep));


#endif /* Use BSD or misc.  */

__END_DECLS

#endif /* dirent.h  */
