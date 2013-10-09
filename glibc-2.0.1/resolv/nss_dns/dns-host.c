/* Copyright (C) 1996, 1997 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Extended from original form by Ulrich Drepper <drepper@cygnus.com>, 1996.

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

/* Parts of this file are plain copies of the file `gethtnamadr.c' from
   the bind package and it has the following copyright.  */

/*
 * ++Copyright++ 1985, 1988, 1993
 * -
 * Copyright (c) 1985, 1988, 1993
 *    The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 * 	This product includes software developed by the University of
 * 	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * -
 * Portions Copyright (c) 1993 by Digital Equipment Corporation.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies, and that
 * the name of Digital Equipment Corporation not be used in advertising or
 * publicity pertaining to distribution of the document or software without
 * specific, written prior permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND DIGITAL EQUIPMENT CORP. DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.   IN NO EVENT SHALL DIGITAL EQUIPMENT
 * CORPORATION BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 * -
 * --Copyright--
 */

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/syslog.h>

#include "nsswitch.h"

/* Get implementation for some internal functions.  */
#include "../resolv/mapv4v6addr.h"
#include "../resolv/mapv4v6hostent.h"

/* Maximum number of aliases we allow.  */
#define MAX_NR_ALIASES	48
#define MAX_NR_ADDRS	48

#if PACKETSZ > 1024
# define MAXPACKET	PACKETSZ
#else
# define MAXPACKET	1024
#endif

static const char AskedForGot[] = "\
gethostby*.getanswer: asked for \"%s\", got \"%s\"";


/* We need this time later.  */
typedef union querybuf
{
  HEADER hdr;
  u_char buf[MAXPACKET];
} querybuf;


static enum nss_status getanswer_r (const querybuf *answer, int anslen,
				    const char *qname, int qtype,
				    struct hostent *result, char *buffer,
				    size_t buflen, int *h_errnop);

enum nss_status
_nss_dns_gethostbyname2_r (const char *name, int af, struct hostent *result,
			   char *buffer, size_t buflen, int *h_errnop)
{
  querybuf host_buffer;
  int size, type, n;
  const char *cp;

  switch (af) {
  case AF_INET:
    size = INADDRSZ;
    type = T_A;
    break;
  case AF_INET6:
    size = IN6ADDRSZ;
    type = T_AAAA;
    break;
  default:
    *h_errnop = NETDB_INTERNAL;
    __set_errno (EAFNOSUPPORT);
    return NSS_STATUS_UNAVAIL;
  }

  result->h_addrtype = af;
  result->h_length = size;

  /*
   * if there aren't any dots, it could be a user-level alias.
   * this is also done in res_query() since we are not the only
   * function that looks up host names.
   */
  if (strchr (name, '.') == NULL && (cp = __hostalias (name)) != NULL)
    name = cp;

  n = res_search (name, C_IN, type, host_buffer.buf, sizeof (host_buffer));
  if (n < 0)
    return errno == ECONNREFUSED ? NSS_STATUS_UNAVAIL : NSS_STATUS_NOTFOUND;

  return getanswer_r (&host_buffer, n, name, type, result, buffer, buflen,
		      h_errnop);
}


enum nss_status
_nss_dns_gethostbyname_r (const char *name, struct hostent *result,
			  char *buffer, size_t buflen, int *h_errnop)
{
  enum nss_status status = NSS_STATUS_NOTFOUND;

  if (_res.options & RES_USE_INET6)
    status = _nss_dns_gethostbyname2_r (name, AF_INET6, result, buffer,
					buflen, h_errnop);
  if (status == NSS_STATUS_NOTFOUND)
    status = _nss_dns_gethostbyname2_r (name, AF_INET, result, buffer,
					buflen, h_errnop);

  return status;
}


enum nss_status
_nss_dns_gethostbyaddr_r (const char *addr, int len, int af,
			  struct hostent *result, char *buffer, size_t buflen,
			  int *h_errnop)
{
  static const u_char mapped[] = { 0,0, 0,0, 0,0, 0,0, 0,0, 0xff,0xff };
  static const u_char tunnelled[] = { 0,0, 0,0, 0,0, 0,0, 0,0, 0,0 };
  const u_char *uaddr = (const u_char *)addr;
  struct host_data
  {
    char *aliases[MAX_NR_ALIASES];
    unsigned char host_addr[16];	/* IPv4 or IPv6 */
    char *h_addr_ptrs[MAX_NR_ADDRS + 1];
    char linebuffer[0];
  } *host_data = (struct host_data *) buffer;
  querybuf host_buffer;
  char qbuf[MAXDNAME+1], *qp;
  int size, n, status;

  if (af == AF_INET6 && len == IN6ADDRSZ &&
      (bcmp (uaddr, mapped, sizeof mapped) == 0
       || bcmp (uaddr, tunnelled, sizeof tunnelled) == 0))
    {
      /* Unmap. */
      addr += sizeof mapped;
      uaddr += sizeof mapped;
      af = AF_INET;
      len = INADDRSZ;
    }

  switch (af)
    {
    case AF_INET:
      size = INADDRSZ;
      break;
    case AF_INET6:
      size = IN6ADDRSZ;
      break;
    default:
      __set_errno (EAFNOSUPPORT);
      *h_errnop = NETDB_INTERNAL;
      return NSS_STATUS_UNAVAIL;
    }
  if (size != len)
    {
      __set_errno (EAFNOSUPPORT);
      *h_errnop = NETDB_INTERNAL;
      return NSS_STATUS_UNAVAIL;
    }

  switch (af)
    {
    case AF_INET:
      sprintf (qbuf, "%u.%u.%u.%u.in-addr.arpa", (uaddr[3] & 0xff),
	       (uaddr[2] & 0xff), (uaddr[1] & 0xff), (uaddr[0] & 0xff));
      break;
    case AF_INET6:
      qp = qbuf;
      for (n = IN6ADDRSZ - 1; n >= 0; n--)
	qp += sprintf (qp, "%x.%x.", uaddr[n] & 0xf, (uaddr[n] >> 4) & 0xf);
      strcpy(qp, "ip6.int");
      break;
    default:
      /* Cannot happen.  */
    }

  n = res_query (qbuf, C_IN, T_PTR, (u_char *)host_buffer.buf,
		 sizeof host_buffer);
  if (n < 0)
    return errno == ECONNREFUSED ? NSS_STATUS_UNAVAIL : NSS_STATUS_NOTFOUND;

  status = getanswer_r (&host_buffer, n, qbuf, T_PTR, result, buffer, buflen,
			h_errnop);
  if (status != NSS_STATUS_SUCCESS)
    return status;

#ifdef SUNSECURITY
  This is not implemented because it is not possible to use the current
  source from bind in a multi-threaded program.
#endif

  result->h_addrtype = af;
  result->h_length = len;
  bcopy (addr, host_data->host_addr, len);
  host_data->h_addr_ptrs[0] = (char *) host_data->host_addr;
  host_data->h_addr_ptrs[1] = NULL;
  if (af == AF_INET && (_res.options & RES_USE_INET6))
    {
      map_v4v6_address ((char *) host_data->host_addr,
			(char *) host_data->host_addr);
      result->h_addrtype = AF_INET6;
      result->h_length = IN6ADDRSZ;
    }
  *h_errnop = NETDB_SUCCESS;
  return NSS_STATUS_SUCCESS;
}


static enum nss_status
getanswer_r (const querybuf *answer, int anslen, const char *qname, int qtype,
	     struct hostent *result, char *buffer, size_t buflen,
	     int *h_errnop)
{
  struct host_data
  {
    char *aliases[MAX_NR_ALIASES];
    unsigned char host_addr[16];	/* IPv4 or IPv6 */
    char *h_addr_ptrs[MAX_NR_ADDRS + 1];
    char linebuffer[0];
  } *host_data = (struct host_data *) buffer;
  int linebuflen = buflen - offsetof (struct host_data, linebuffer);
  register const HEADER *hp;
  const u_char *end_of_message, *cp;
  int n, ancount, qdcount;
  int haveanswer, had_error;
  char *bp, **ap, **hap;
  char tbuf[MAXDNAME];
  const char *tname;
  int (*name_ok) __P ((const char *));

  tname = qname;
  result->h_name = NULL;
  end_of_message = answer->buf + anslen;
  switch (qtype)
    {
    case T_A:
    case T_AAAA:
      name_ok = res_hnok;
      break;
    case T_PTR:
      name_ok = res_dnok;
      break;
    default:
      return NSS_STATUS_UNAVAIL;  /* XXX should be abort(); */
    }

  /*
   * find first satisfactory answer
   */
  hp = &answer->hdr;
  bp = host_data->linebuffer;
  ancount = ntohs (hp->ancount);
  qdcount = ntohs (hp->qdcount);
  cp = answer->buf + HFIXEDSZ;
  if (qdcount != 1)
    {
      *h_errnop = NO_RECOVERY;
      return NSS_STATUS_UNAVAIL;
    }

  n = dn_expand (answer->buf, end_of_message, cp, bp, linebuflen);
  if (n < 0 || (*name_ok) (bp) == 0)
    {
      *h_errnop = NO_RECOVERY;
      return NSS_STATUS_UNAVAIL;
    }
  cp += n + QFIXEDSZ;

  if (qtype == T_A || qtype == T_AAAA)
    {
      /* res_send() has already verified that the query name is the
       * same as the one we sent; this just gets the expanded name
       * (i.e., with the succeeding search-domain tacked on).
       */
      n = strlen (bp) + 1;             /* for the \0 */
      result->h_name = bp;
      bp += n;
      linebuflen -= n;
      /* The qname can be abbreviated, but h_name is now absolute. */
      qname = result->h_name;
    }

  ap = host_data->aliases;
  *ap = NULL;
  result->h_aliases = host_data->aliases;
  hap = host_data->h_addr_ptrs;
  *hap = NULL;
  result->h_addr_list = host_data->h_addr_ptrs;
  haveanswer = 0;
  had_error = 0;

  while (ancount-- > 0 && cp < end_of_message && had_error == 0)
    {
      int type, class;

      n = dn_expand (answer->buf, end_of_message, cp, bp, linebuflen);
      if (n < 0 || (*name_ok) (bp) == 0)
	{
	  ++had_error;
	  continue;
	}
      cp += n;				/* name */
      type = _getshort (cp);
      cp += INT16SZ;			/* type */
      class = _getshort(cp);
      cp += INT16SZ + INT32SZ;		/* class, TTL */
      n = _getshort(cp);
      cp += INT16SZ;			/* len */
      if (class != C_IN)
	{
	  /* XXX - debug? syslog? */
	  cp += n;
	  continue;			/* XXX - had_error++ ? */
	}

      if ((qtype ==T_A || qtype == T_AAAA) && type == T_CNAME)
	{
	  if (ap >= &host_data->aliases[MAX_NR_ALIASES - 1])
	    continue;
	  n = dn_expand (answer->buf, end_of_message, cp, tbuf, sizeof tbuf);
	  if (n < 0 || (*name_ok) (tbuf) == 0)
	    {
	      ++had_error;
	      continue;
	    }
	  cp += n;
	  /* Store alias.  */
	  *ap++ = bp;
	  n = strlen (bp) + 1;		/* For the \0.  */
	  bp += n;
	  linebuflen -= n;
	  /* Get canonical name.  */
	  n = strlen (tbuf) + 1;	/* For the \0.  */
	  if (n > buflen)
	    {
	      ++had_error;
	      continue;
	    }
	  strcpy (bp, tbuf);		/* Cannot overflow.  */
	  result->h_name = bp;
	  bp += n;
	  linebuflen -= n;
	  continue;
	}

      if (qtype == T_PTR && type == T_CNAME)
	{
	  n = dn_expand (answer->buf, end_of_message, cp, tbuf, sizeof tbuf);
	  if (n < 0 || res_hnok (tbuf) == 0)
	    {
	      ++had_error;
	      continue;
	    }
	  cp += n;
	  /* Get canonical name. */
	  n = strlen (tbuf) + 1;   /* For the \0.  */
	  if (n > buflen)
	    {
	      ++had_error;
	      continue;
	    }
	  strcpy (bp, tbuf);		/* Cannot overflow.  */
	  tname = bp;
	  bp += n;
	  linebuflen -= n;
	  continue;
	}
      if (type != qtype)
	{
	  syslog (LOG_NOTICE | LOG_AUTH,
	       "gethostby*.getanswer: asked for \"%s %s %s\", got type \"%s\"",
		  qname, p_class (C_IN), p_type (qtype), p_type (type));
	  cp += n;
	  continue;			/* XXX - had_error++ ? */
	}

      switch (type)
	{
	case T_PTR:
	  if (strcasecmp (tname, bp) != 0)
	    {
	      syslog (LOG_NOTICE | LOG_AUTH, AskedForGot, qname, bp);
	      cp += n;
	      continue;			/* XXX - had_error++ ? */
	    }
	  n = dn_expand (answer->buf, end_of_message, cp, bp, linebuflen);
	  if (n < 0 || res_hnok (bp) == 0)
	    {
	      ++had_error;
	      break;
	    }
#if MULTI_PTRS_ARE_ALIASES
	  cp += n;
	  if (haveanswer == 0)
	    result->h_name = bp;
	  else if (ap < &host_data->aliases[MAXALIASES-1])
	    *ap++ = bp;
	  else
	    n = -1;
	  if (n != -1)
	    {
	      n = strlen (bp) + 1;	/* for the \0 */
	      bp += n;
	      linebuflen -= n;
	    }
	  break;
#else
	  result->h_name = bp;
	  if (_res.options & RES_USE_INET6)
	    {
	      n = strlen (bp) + 1;	/* for the \0 */
	      bp += n;
	      linebuflen -= n;
	      map_v4v6_hostent (result, &bp, &linebuflen);
	    }
	  *h_errnop = NETDB_SUCCESS;
	  return NSS_STATUS_SUCCESS;
#endif
	case T_A:
	case T_AAAA:
	  if (strcasecmp (result->h_name, bp) != 0)
	    {
	      syslog (LOG_NOTICE | LOG_AUTH, AskedForGot, result->h_name, bp);
	      cp += n;
	      continue;			/* XXX - had_error++ ? */
	    }
	  if (n != result->h_length)
	    {
	      cp += n;
	      continue;
	    }
	  if (!haveanswer)
	    {
	      register int nn;

	      result->h_name = bp;
	      nn = strlen (bp) + 1;	/* for the \0 */
	      bp += nn;
	      linebuflen -= nn;
	    }

	  bp += sizeof (align) - ((u_long) bp % sizeof (align));

	  if (n >= linebuflen)
	    {
	      ++had_error;
	      continue;
	    }
	  if (hap >= &host_data->h_addr_ptrs[MAX_NR_ADDRS-1])
	    {
	      cp += n;
	      continue;
	    }
	  bcopy (cp, *hap++ = bp, n);
	  bp += n;
	  cp += n;
	  linebuflen -= n;
	  break;
	default:
	  abort ();
	}
      if (had_error == 0)
	++haveanswer;
    }

  if (haveanswer > 0)
    {
      *ap = NULL;
      *hap = NULL;
#if defined(RESOLVSORT)
      /*
       * Note: we sort even if host can take only one address
       * in its return structures - should give it the "best"
       * address in that case, not some random one
       */
      if (_res.nsort && haveanswer > 1 && qtype == T_A)
	addrsort (host_data->h_addr_ptrs, haveanswer);
#endif /*RESOLVSORT*/

      if (result->h_name == NULL)
	{
	  n = strlen (qname) + 1;	/* For the \0.  */
	  if (n > linebuflen)
	    goto try_again;
	  strcpy (bp, qname);		/* Cannot overflow.  */
	  result->h_name = bp;
	  bp += n;
	  linebuflen -= n;
	}

      if (_res.options & RES_USE_INET6)
	map_v4v6_hostent (result, &bp, &linebuflen);
      *h_errnop = NETDB_SUCCESS;
      return NSS_STATUS_SUCCESS;
    }
try_again:
  *h_errnop = TRY_AGAIN;
  return NSS_STATUS_TRYAGAIN;
}
