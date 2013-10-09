/* Copyright (C) 1996 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Thorsten Kukuk <kukuk@vt.uni-paderborn.de>, 1996.

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

#include <nss.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <aliases.h>
#include <libc-lock.h>
#include <rpcsvc/yp.h>
#include <rpcsvc/ypclnt.h>

#include "nss-nis.h"

__libc_lock_define_initialized (static, lock)

static bool_t new_start = 1;
static char *oldkey = NULL;
static int oldkeylen = 0;

static int
_nss_nis_parse_aliasent (const char *key, char *alias, struct aliasent *result,
			 char *buffer, size_t buflen)
{
  char *first_unused = buffer + strlen (alias) + 1;
  size_t room_left =
    buflen - (buflen % __alignof__ (char *)) - strlen (alias) - 2;
  char *line;
  char *cp;

  result->alias_members_len = 0;
  *first_unused = '\0';
  first_unused++;
  strcpy (first_unused, key);

  if (first_unused[room_left - 1] != '\0')
    {
      /* The line is too long for our buffer.  */
    no_more_room:
      __set_errno (ERANGE);
      return -1;
    }

  result->alias_name = first_unused;

  /* Terminate the line for any case.  */
  cp = strpbrk (alias, "#\n");
  if (cp != NULL)
    *cp = '\0';

  first_unused += strlen (result->alias_name) + 1;
  /* Adjust the pointer so it is aligned for
     storing pointers.  */
  first_unused += __alignof__ (char *) - 1;
  first_unused -= ((first_unused - (char *) 0) % __alignof__ (char *));
  result->alias_members = (char **) first_unused;

  line = alias;

  while (*line != '\0')
    {
      /* Skip leading blanks.  */
      while (isspace (*line))
	line++;

      if (*line == '\0')
	break;

      if (room_left < sizeof (char *))
	  goto no_more_room;
      room_left -= sizeof (char *);
      result->alias_members[result->alias_members_len] = line;

      while (*line != '\0' && *line != ',')
	line++;

      if (line != result->alias_members[result->alias_members_len])
	{
	  *line = '\0';
	  line++;
	  result->alias_members_len++;
	}
    }
  return result->alias_members_len == 0 ? 0 : 1;
}

enum nss_status
_nss_nis_setaliasent (void)
{
  __libc_lock_lock (lock);

  new_start = 1;
  if (oldkey != NULL)
    {
      free (oldkey);
      oldkey = NULL;
      oldkeylen = 0;
    }

  __libc_lock_unlock (lock);

  return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_nis_endaliasent (void)
{
  __libc_lock_lock (lock);

  new_start = 1;
  if (oldkey != NULL)
    {
      free (oldkey);
      oldkey = NULL;
      oldkeylen = 0;
    }

  __libc_lock_unlock (lock);

  return NSS_STATUS_SUCCESS;
}

static enum nss_status
internal_nis_getaliasent_r (struct aliasent *alias, char *buffer,
			    size_t buflen)
{
  char *domain;
  char *result;
  int len;
  char *outkey;
  int keylen;
  char *p;
  int parse_res;

  if (yp_get_default_domain (&domain))
    return NSS_STATUS_UNAVAIL;

  alias->alias_local = 0;

  /* Get the next entry until we found a correct one. */
  do
    {
      enum nss_status retval;

      if (new_start)
        retval = yperr2nss (yp_first (domain, "mail.aliases",
				      &outkey, &keylen, &result, &len));
      else
        retval = yperr2nss ( yp_next (domain, "mail.aliases", oldkey,
				      oldkeylen, &outkey, &keylen,
				      &result, &len));
      if (retval != NSS_STATUS_SUCCESS)
	{
	  if (retval == NSS_STATUS_TRYAGAIN)
            __set_errno (EAGAIN);
          return retval;
        }

      if ((size_t) (len + 1) > buflen)
        {
	  free (result);
          __set_errno (ERANGE);
          return NSS_STATUS_TRYAGAIN;
        }
      p = strncpy (buffer, result, len);
      buffer[len] = '\0';
      while (isspace (*p))
        ++p;
      free (result);

      parse_res = _nss_nis_parse_aliasent (outkey, p, alias, buffer, buflen);
      if (parse_res == -1)
	{
	  __set_errno (ERANGE);
	  return NSS_STATUS_TRYAGAIN;
	}

      free (oldkey);
      oldkey = outkey;
      oldkeylen = keylen;
      new_start = 0;
    }
  while (!parse_res);

  return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_nis_getaliasent_r (struct aliasent *alias, char *buffer, size_t buflen)
{
  enum nss_status status;

  __libc_lock_lock (lock);

  status = internal_nis_getaliasent_r (alias, buffer, buflen);

  __libc_lock_unlock (lock);

  return status;
}

enum nss_status
_nss_nis_getaliasbyname_r (const char *name, struct aliasent *alias,
			   char *buffer, size_t buflen)
{
  enum nss_status retval;
  int parse_res;
  char *domain;
  char *result;
  int len;
  char *p;

  if (name == NULL)
    {
      __set_errno (EINVAL);
      return NSS_STATUS_UNAVAIL;
    }

  if (yp_get_default_domain (&domain))
    return NSS_STATUS_UNAVAIL;

  retval = yperr2nss (yp_match (domain, "mail.aliases", name, strlen (name),
				&result, &len));
  if (retval != NSS_STATUS_SUCCESS)
    {
      if (retval == NSS_STATUS_TRYAGAIN)
	__set_errno (EAGAIN);
      return retval;
    }

  if ((size_t) (len + 1) > buflen)
    {
      free (result);
      __set_errno (ERANGE);
      return NSS_STATUS_TRYAGAIN;
    }

  p = strncpy (buffer, result, len);
  buffer[len] = '\0';
  while (isspace (*p))
    ++p;
  free (result);

  alias->alias_local = 0;
  parse_res = _nss_nis_parse_aliasent (name, p, alias, buffer, buflen);
  if (parse_res == -1)
    return NSS_STATUS_TRYAGAIN;
  else
    if (parse_res == 0)
      return NSS_STATUS_NOTFOUND;
    else
      return NSS_STATUS_SUCCESS;
}
