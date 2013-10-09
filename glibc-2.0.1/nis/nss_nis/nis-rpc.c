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
#include <netdb.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <libc-lock.h>
#include <rpcsvc/yp.h>
#include <rpcsvc/ypclnt.h>

#include "nss-nis.h"

/* Get the declaration of the parser function.  */
#define ENTNAME rpcent
#define EXTERN_PARSER
#include "../nss/nss_files/files-parse.c"

__libc_lock_define_initialized (static, lock)

struct intern_t
{
  bool_t new_start;
  char *oldkey;
  int oldkeylen;
};
typedef struct intern_t intern_t;

static intern_t intern = {TRUE, NULL, 0};

static enum nss_status
internal_nis_setrpcent (intern_t *data)
{
  data->new_start = 1;
  if (data->oldkey != NULL)
    {
      free (data->oldkey);
      data->oldkey = NULL;
      data->oldkeylen = 0;
    }
  return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_nis_setrpcent (void)
{
  enum nss_status status;

  __libc_lock_lock (lock);

  status = internal_nis_setrpcent (&intern);

  __libc_lock_unlock (lock);

  return status;
}

static enum nss_status
internal_nis_endrpcent (intern_t *data)
{
  data->new_start = 1;
  if (data->oldkey != NULL)
    {
      free (data->oldkey);
      data->oldkey = NULL;
      data->oldkeylen = 0;
    }
  return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_nis_endrpcent (void)
{
  enum nss_status status;

  __libc_lock_lock (lock);

  status = internal_nis_endrpcent (&intern);

  __libc_lock_unlock (lock);

  return status;
}

static enum nss_status
internal_nis_getrpcent_r (struct rpcent *rpc, char *buffer, size_t buflen,
			  intern_t *data)
{
  struct parser_data *pdata = (void *) buffer;
  char *domain;
  char *result;
  int len, parse_res;
  char *outkey;
  int keylen;
  char *p;

  if (yp_get_default_domain (&domain))
    return NSS_STATUS_UNAVAIL;

  /* Get the next entry until we found a correct one. */
  do
    {
      enum nss_status retval;

      if (data->new_start)
        retval = yperr2nss (yp_first (domain, "rpc.bynumber",
                                      &outkey, &keylen, &result, &len));
      else
        retval = yperr2nss ( yp_next (domain, "rpc.bynumber",
				      data->oldkey, data->oldkeylen,
				      &outkey, &keylen, &result, &len));

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

      parse_res = _nss_files_parse_rpcent (p, rpc, pdata, buflen);
      if (!parse_res && errno == ERANGE)
	return NSS_STATUS_TRYAGAIN;

      free (data->oldkey);
      data->oldkey = outkey;
      data->oldkeylen = keylen;
      data->new_start = 0;
    }
  while (!parse_res);

  return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_nis_getrpcent_r (struct rpcent *rpc, char *buffer, size_t buflen)
{
  enum nss_status status;

  __libc_lock_lock (lock);

  status = internal_nis_getrpcent_r (rpc, buffer, buflen, &intern);

  __libc_lock_unlock (lock);

  return status;
}

enum nss_status
_nss_nis_getrpcbyname_r (const char *name, struct rpcent *rpc,
			 char *buffer, size_t buflen)
{
  intern_t data = {TRUE, NULL, 0};
  enum nss_status status;
  int found;

  if (name == NULL)
    {
      __set_errno (EINVAL);
      return NSS_STATUS_UNAVAIL;
    }

  status = internal_nis_setrpcent (&data);
  if (status != NSS_STATUS_SUCCESS)
    return status;

  found = 0;
  while (!found &&
         ((status = internal_nis_getrpcent_r (rpc, buffer, buflen, &data))
          == NSS_STATUS_SUCCESS))
    {
      if (strcmp (rpc->r_name, name) == 0)
	found = 1;
      else
	{
	  int i = 0;

	  while (rpc->r_aliases[i] != NULL)
	    {
	      if (strcmp (rpc->r_aliases[i], name) == 0)
		{
		  found = 1;
		  break;
		}
	      else
		++i;
	    }
	}
    }

  internal_nis_endrpcent (&data);

  if (!found && status == NSS_STATUS_SUCCESS)
    return NSS_STATUS_NOTFOUND;
  else
    return status;
}

enum nss_status
_nss_nis_getrpcbynumber_r (int number, struct rpcent *rpc,
			   char *buffer, size_t buflen)
{
  struct parser_data *data = (void *) buffer;
  enum nss_status retval;
  char *domain, *result, *p;
  int len, nlen, parse_res;
  char buf[32];

  if (yp_get_default_domain (&domain))
    return NSS_STATUS_UNAVAIL;

  nlen = sprintf (buf, "%d", number);

  retval = yperr2nss (yp_match (domain, "rpc.bynumber", buf,
				 nlen, &result, &len));

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

  parse_res = _nss_files_parse_rpcent (p, rpc, data, buflen);

  if (!parse_res)
    {
      if (errno == ERANGE)
	return NSS_STATUS_TRYAGAIN;
      else
	return NSS_STATUS_NOTFOUND;
    }
  else
    return NSS_STATUS_SUCCESS;
}
