/* Copyright (C) 1996 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1996.

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

#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <string.h>

#include "../nss/nsswitch.h"

/* Because the `ethers' lookup does not fit so well in the scheme so
   we define a dummy struct here which helps us to use the available
   functions.  */
struct etherent
{
  const char *e_name;
  struct ether_addr e_addr;
};


/* Type of the lookup function we need here.  */
typedef int (*lookup_function) (const struct ether_addr *, struct etherent *,
				char *, int);

/* The lookup function for the first entry of this service.  */
extern int __nss_ethers_lookup (service_user **nip, const char *name,
				void **fctp);


int
ether_ntohost (char *hostname, const struct ether_addr *addr)
{
  static service_user *startp = NULL;
  static lookup_function start_fct;
  service_user *nip;
  lookup_function fct;
  int no_more;
  enum nss_status status = NSS_STATUS_UNAVAIL;
  struct etherent etherent;

  if (startp == NULL)
    {
      no_more = __nss_ethers_lookup (&nip, "getntohost_r", (void **) &fct);
      if (no_more)
	startp = (service_user *) -1;
      else
	{
	  startp = nip;
	  start_fct = fct;
	}
    }
  else
    {
      fct = start_fct;
      no_more = (nip = startp) == (service_user *) -1;
    }

  while (no_more == 0)
    {
      char buffer[1024];

      status = (*fct) (addr, &etherent, buffer, sizeof buffer);

      no_more = __nss_next (&nip, "getntohost_r", (void **) &fct, status, 0);
    }

  if (status == NSS_STATUS_SUCCESS)
    /* XXX This is a potential cause of trouble because the size of
       the HOSTNAME buffer is not known but the interface does not
       provide this information.  */
    strcpy (hostname, etherent.e_name);

  return status == NSS_STATUS_SUCCESS ? 0 : -1;
}
