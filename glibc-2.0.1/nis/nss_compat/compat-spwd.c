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
#include <errno.h>
#include <ctype.h>
#include <netdb.h>
#include <shadow.h>
#include <string.h>
#include <libc-lock.h>
#include <rpcsvc/yp.h>
#include <rpcsvc/ypclnt.h>

/* Get the declaration of the parser function.  */
#define ENTNAME spent
#define STRUCTURE spwd
#define EXTERN_PARSER
#include "../../nss/nss_files/files-parse.c"

/* Structure for remembering -@netgroup and -user members ... */
#define BLACKLIST_INITIAL_SIZE 512
#define BLACKLIST_INCREMENT 256
struct blacklist_t
  {
    char *data;
    int current;
    int size;
  };

struct ent_t
  {
    bool_t netgroup;
    bool_t nis;
    bool_t first;
    char *oldkey;
    int oldkeylen;
    FILE *stream;
    struct blacklist_t blacklist;
    struct spwd pwd;
  };
typedef struct ent_t ent_t;

static ent_t ext_ent = {0, 0, 0, NULL, 0, NULL,	{NULL, 0, 0},
			{NULL, NULL, 0, 0, 0, 0, 0, 0, 0}};

/* Protect global state against multiple changers.  */
__libc_lock_define_initialized (static, lock)

/* Prototypes for local functions.  */
static void blacklist_store_name (const char *, ent_t *);
static int in_blacklist (const char *, int, ent_t *);

static void
give_spwd_free (struct spwd *pwd)
{
  if (pwd->sp_namp != NULL)
    free (pwd->sp_namp);
  if (pwd->sp_pwdp != NULL)
    free (pwd->sp_pwdp);

  memset (pwd, '\0', sizeof (struct spwd));
}

static int
spwd_need_buflen (struct spwd *pwd)
{
  int len = 0;

  if (pwd->sp_pwdp != NULL)
    len += strlen (pwd->sp_pwdp) + 1;

  return len;
}

static void
copy_spwd_changes (struct spwd *dest, struct spwd *src,
		   char *buffer, size_t buflen)
{
  if (src->sp_pwdp != NULL && strlen (src->sp_pwdp))
    {
      if (buffer == NULL)
	dest->sp_pwdp = strdup (src->sp_pwdp);
      else if (dest->sp_pwdp &&
	       strlen (dest->sp_pwdp) >= strlen (src->sp_pwdp))
	strcpy (dest->sp_pwdp, src->sp_pwdp);
      else
	{
	  dest->sp_pwdp = buffer;
	  strcpy (dest->sp_pwdp, src->sp_pwdp);
	  buffer += strlen (dest->sp_pwdp) + 1;
	  buflen = buflen - (strlen (dest->sp_pwdp) + 1);
	}
    }
  if (src->sp_lstchg != 0)
    dest->sp_lstchg = src->sp_lstchg;
  if (src->sp_min != 0)
    dest->sp_min = src->sp_min;
  if (src->sp_max != 0)
    dest->sp_max = src->sp_max;
  if (src->sp_warn != 0)
    dest->sp_warn = src->sp_warn;
  if (src->sp_inact != 0)
    dest->sp_inact = src->sp_inact;
  if (src->sp_expire != 0)
    dest->sp_expire = src->sp_expire;
  if (src->sp_flag != 0)
    dest->sp_flag = src->sp_flag;
}

static enum nss_status
internal_setspent (ent_t *ent)
{
  enum nss_status status = NSS_STATUS_SUCCESS;

  ent->nis = ent->first = ent->netgroup = 0;

  if (ent->oldkey != NULL)
    {
      free (ent->oldkey);
      ent->oldkey = NULL;
      ent->oldkeylen = 0;
    }

  ent->blacklist.current = 0;
  if (ent->blacklist.data != NULL)
    ent->blacklist.data[0] = '\0';

  if (ent->stream == NULL)
    {
      ent->stream = fopen ("/etc/shadow", "r");

      if (ent->stream == NULL)
	status = errno == EAGAIN ? NSS_STATUS_TRYAGAIN : NSS_STATUS_UNAVAIL;
    }
  else
    rewind (ent->stream);

  give_spwd_free (&ent->pwd);

  return status;
}


enum nss_status
_nss_compat_setspent (void)
{
  enum nss_status result;

  __libc_lock_lock (lock);

  result = internal_setspent (&ext_ent);

  __libc_lock_unlock (lock);

  return result;
}


static enum nss_status
internal_endspent (ent_t *ent)
{
  if (ent->stream != NULL)
    {
      fclose (ent->stream);
      ent->stream = NULL;
    }

  ent->nis = ent->first = ent->netgroup = 0;

  if (ent->oldkey != NULL)
    {
      free (ent->oldkey);
      ent->oldkey = NULL;
      ent->oldkeylen = 0;
    }

  ent->blacklist.current = 0;
  if (ent->blacklist.data != NULL)
    ent->blacklist.data[0] = '\0';

  give_spwd_free (&ent->pwd);

  return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_compat_endspent (void)
{
  enum nss_status result;

  __libc_lock_lock (lock);

  result = internal_endspent (&ext_ent);

  __libc_lock_unlock (lock);

  return result;
}


static enum nss_status
getspent_next_netgr (struct spwd *result, ent_t *ent, char *group,
		     char *buffer, size_t buflen)
{
  struct parser_data *data = (void *) buffer;
  char *ypdomain, *host, *user, *domain, *outval, *p, *p2;
  int status, outvallen;
  size_t p2len;

  if (yp_get_default_domain (&ypdomain) != YPERR_SUCCESS)
    {
      ent->netgroup = 0;
      ent->first = 0;
      give_spwd_free (&ent->pwd);
      return NSS_STATUS_UNAVAIL;
    }

  if (ent->first == TRUE)
    {
      setnetgrent (group);
      ent->first = FALSE;
    }

  while (1)
    {
      if ((status = getnetgrent (&host, &user, &domain)) != 1)
	{
	  endnetgrent ();
	  ent->netgroup = 0;
	  give_spwd_free (&ent->pwd);
	  return NSS_STATUS_RETURN;
	}

      if (user == NULL || user[0] == '-')
	continue;

      if (domain != NULL && strcmp (ypdomain, domain) != 0)
	continue;

      if (yp_match (ypdomain, "shadow.byname", user,
		    strlen (user), &outval, &outvallen)
	  != YPERR_SUCCESS)
	continue;

      p2len = spwd_need_buflen (&ent->pwd);
      if (p2len > buflen)
	{
	  __set_errno (ERANGE);
	  return NSS_STATUS_TRYAGAIN;
	}
      p2 = buffer + (buflen - p2len);
      buflen -= p2len;
      p = strncpy (buffer, outval, buflen);
      while (isspace (*p))
	p++;
      free (outval);
      if (_nss_files_parse_spent (p, result, data, buflen))
	{
	  copy_spwd_changes (result, &ent->pwd, p2, p2len);
	  break;
	}
    }

  return NSS_STATUS_SUCCESS;
}

static enum nss_status
getspent_next_nis (struct spwd *result, ent_t *ent,
		   char *buffer, size_t buflen)
{
  struct parser_data *data = (void *) buffer;
  char *domain, *outkey, *outval, *p, *p2;
  int outkeylen, outvallen;
  size_t p2len;

  if (yp_get_default_domain (&domain) != YPERR_SUCCESS)
    {
      ent->nis = 0;
      give_spwd_free (&ent->pwd);
      return NSS_STATUS_UNAVAIL;
    }

  p2len = spwd_need_buflen (&ent->pwd);
  if (p2len > buflen)
    {
      __set_errno (ERANGE);
      return NSS_STATUS_TRYAGAIN;
    }
  p2 = buffer + (buflen - p2len);
  buflen -= p2len;
  do
    {
      if (ent->first)
	{
	  if (yp_first (domain, "shadow.byname", &outkey, &outkeylen,
			&outval, &outvallen) != YPERR_SUCCESS)
	    {
	      ent->nis = 0;
	      give_spwd_free (&ent->pwd);
	      return NSS_STATUS_UNAVAIL;
	    }

	  ent->oldkey = outkey;
	  ent->oldkeylen = outkeylen;
	  ent->first = FALSE;
	}
      else
	{
	  if (yp_next (domain, "shadow.byname", ent->oldkey, ent->oldkeylen,
		       &outkey, &outkeylen, &outval, &outvallen)
	      != YPERR_SUCCESS)
	    {
	      ent->nis = 0;
	      give_spwd_free (&ent->pwd);
	      return NSS_STATUS_NOTFOUND;
	    }

	  free (ent->oldkey);
	  ent->oldkey = outkey;
	  ent->oldkeylen = outkeylen;
	}

      /* Copy the found data to our buffer  */
      p = strncpy (buffer, outval, buflen);

      /* ...and free the data.  */
      free (outval);

      while (isspace (*p))
	++p;
    }
  while (!_nss_files_parse_spent (p, result, data, buflen));

  copy_spwd_changes (result, &ent->pwd, p2, p2len);

  if (!in_blacklist (result->sp_namp, strlen (result->sp_namp), ent))
    return NSS_STATUS_SUCCESS;
  else
    return NSS_STATUS_NOTFOUND;
}


static enum nss_status
getspent_next_file (struct spwd *result, ent_t *ent,
		    char *buffer, size_t buflen)
{
  struct parser_data *data = (void *) buffer;
  while (1)
    {
      char *p, *p2;
      size_t p2len;

      do
	{
	  p = fgets (buffer, buflen, ent->stream);
	  if (p == NULL)
	    return NSS_STATUS_NOTFOUND;

	  /* Terminate the line for any case.  */
	  buffer[buflen - 1] = '\0';

	  /* Skip leading blanks.  */
	  while (isspace (*p))
	    ++p;
	}
      while (*p == '\0' || *p == '#' ||		/* Ignore empty and comment lines.  */
      /* Parse the line.  If it is invalid, loop to
         get the next line of the file to parse.  */
	     !_nss_files_parse_spent (p, result, data, buflen));

      if (result->sp_namp[0] != '+' && result->sp_namp[0] != '-')
	/* This is a real entry.  */
	break;

      /* -@netgroup */
      if (result->sp_namp[0] == '-' && result->sp_namp[1] == '@'
	  && result->sp_namp[2] != '\0')
	{
	  char *user, *host, *domain;

	  setnetgrent (&result->sp_namp[2]);
	  while (getnetgrent (&host, &user, &domain))
	    {
	      if (user != NULL && user[0] != '-')
		blacklist_store_name (user, ent);
	    }
	  endnetgrent ();
	  continue;
	}

      /* +@netgroup */
      if (result->sp_namp[0] == '+' && result->sp_namp[1] == '@'
	  && result->sp_namp[2] != '\0')
	{
	  int status;

	  ent->netgroup = TRUE;
	  ent->first = TRUE;
	  copy_spwd_changes (&ent->pwd, result, NULL, 0);

	  status = getspent_next_netgr (result, ent, &result->sp_namp[2],
					buffer, buflen);
	  if (status == NSS_STATUS_RETURN)
	    continue;
	  else
	    return status;
	}

      /* -user */
      if (result->sp_namp[0] == '-' && result->sp_namp[1] != '\0'
	  && result->sp_namp[1] != '@')
	{
	  blacklist_store_name (&result->sp_namp[1], ent);
	  continue;
	}

      /* +user */
      if (result->sp_namp[0] == '+' && result->sp_namp[1] != '\0'
	  && result->sp_namp[1] != '@')
	{
	  char *domain;
	  char *outval;
	  int outvallen;
	  struct spwd pwd;

	  memset (&pwd, '\0', sizeof (struct spwd));

	  if (yp_get_default_domain (&domain) != YPERR_SUCCESS)
	    /* XXX Should we regard this as an fatal error?  I don't
	       think so.  Just continue working.  --drepper@gnu  */
	    continue;

	  if (yp_match (domain, "shadow.byname", &result->sp_namp[1],
			strlen (result->sp_namp) - 1, &outval, &outvallen)
	      != YPERR_SUCCESS)
	    continue;

	  copy_spwd_changes (&pwd, result, NULL, 0);

	  p2len = spwd_need_buflen (&pwd);
	  if (p2len > buflen)
	    {
	      __set_errno (ERANGE);
	      return NSS_STATUS_TRYAGAIN;
	    }
	  p2 = buffer + (buflen - p2len);
	  buflen -= p2len;
	  p = strncpy (buffer, outval, buflen);
	  while (isspace (*p))
	    p++;
	  free (outval);
	  if (_nss_files_parse_spent (p, result, data, buflen))
	    {
	      copy_spwd_changes (result, &pwd, p2, p2len);
	      give_spwd_free (&pwd);
	      /* We found the entry.  */
	      break;
	    }
	  else
	    {
	      /* Give buffer the old len back */
	      buflen += p2len;
	      give_spwd_free (&pwd);
	    }
	}

      /* +:... */
      if (result->sp_namp[0] == '+' && result->sp_namp[1] == '\0')
	{
	  ent->nis = TRUE;
	  ent->first = TRUE;
	  copy_spwd_changes (&ent->pwd, result, NULL, 0);

	  return getspent_next_nis (result, ent, buffer, buflen);
	}
    }

  return NSS_STATUS_SUCCESS;
}


static enum nss_status
internal_getspent_r (struct spwd *pw, ent_t *ent,
		     char *buffer, size_t buflen)
{
  if (ent->netgroup)
    {
      int status;

      /* We are searching members in a netgroup */
      /* Since this is not the first call, we don't need the group name */
      status = getspent_next_netgr (pw, ent, NULL, buffer, buflen);
      if (status == NSS_STATUS_RETURN)
	return getspent_next_file (pw, ent, buffer, buflen);
      else
	return status;
    }
  else if (ent->nis)
    return getspent_next_nis (pw, ent, buffer, buflen);
  else
    return getspent_next_file (pw, ent, buffer, buflen);
}

enum nss_status
_nss_compat_getspent_r (struct spwd *pwd, char *buffer, size_t buflen)
{
  enum nss_status status = NSS_STATUS_SUCCESS;

  __libc_lock_lock (lock);

  /* Be prepared that the setspent function was not called before.  */
  if (ext_ent.stream == NULL)
    status = internal_setspent (&ext_ent);

  if (status == NSS_STATUS_SUCCESS)
    status = internal_getspent_r (pwd, &ext_ent, buffer, buflen);

  __libc_lock_unlock (lock);

  return status;
}


enum nss_status
_nss_compat_getspnam_r (const char *name, struct spwd *pwd,
			char *buffer, size_t buflen)
{
  ent_t ent = {0, 0, 0, NULL, 0, NULL, {NULL, 0, 0},
	       {NULL, NULL, 0, 0, 0, 0, 0, 0, 0}};
  enum nss_status status;

  if (name[0] == '-' || name[0] == '+')
    return NSS_STATUS_NOTFOUND;

  status = internal_setspent (&ent);
  if (status != NSS_STATUS_SUCCESS)
    return status;

  while ((status = internal_getspent_r (pwd, &ent, buffer, buflen))
	 == NSS_STATUS_SUCCESS)
    if (strcmp (pwd->sp_namp, name) == 0)
      break;

  internal_endspent (&ent);
  return status;
}

/* Support routines for remembering -@netgroup and -user entries.
   The names are stored in a single string with `|' as separator. */
static void
blacklist_store_name (const char *name, ent_t *ent)
{
  int namelen = strlen (name);
  char *tmp;

  /* first call, setup cache */
  if (ent->blacklist.size == 0)
    {
      ent->blacklist.size = MAX (BLACKLIST_INITIAL_SIZE, 2 * namelen);
      ent->blacklist.data = malloc (ent->blacklist.size);
      if (ent->blacklist.data == NULL)
	return;
      ent->blacklist.data[0] = '|';
      ent->blacklist.data[1] = '\0';
      ent->blacklist.current = 1;
    }
  else
    {
      if (in_blacklist (name, namelen, ent))
	return;			/* no duplicates */

      if (ent->blacklist.current + namelen + 1 >= ent->blacklist.size)
	{
	  ent->blacklist.size += MAX (BLACKLIST_INCREMENT, 2 * namelen);
	  tmp = realloc (ent->blacklist.data, ent->blacklist.size);
	  if (tmp == NULL)
	    {
	      free (ent->blacklist.data);
	      ent->blacklist.size = 0;
	      return;
	    }
	  ent->blacklist.data = tmp;
	}
    }

  tmp = stpcpy (ent->blacklist.data + ent->blacklist.current, name);
  *tmp++ = '|';
  *tmp = '\0';
  ent->blacklist.current += namelen + 1;

  return;
}

/* returns TRUE if ent->blacklist contains name, else FALSE */
static bool_t
in_blacklist (const char *name, int namelen, ent_t *ent)
{
  char buf[namelen + 3];

  if (ent->blacklist.data == NULL)
    return FALSE;

  stpcpy (stpcpy (stpcpy (buf, "|"), name), "|");
  return strstr (ent->blacklist.data, buf) != NULL;
}
