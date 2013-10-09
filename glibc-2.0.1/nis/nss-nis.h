/* Copyright (C) 1996 Free Software Foundation, Inc.
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

#ifndef _NIS_NSS_NIS_H
#define _NIS_NSS_NIS_H	1

#include <rpcsvc/ypclnt.h>

#include "nsswitch.h"


/* Convert YP error number to NSS error number.  */
static enum nss_status yperr2nss_tab[] =
{
  [YPERR_SUCCESS] = NSS_STATUS_SUCCESS,
  [YPERR_BADARGS] = NSS_STATUS_UNAVAIL,
  [YPERR_RPC]     = NSS_STATUS_UNAVAIL,
  [YPERR_DOMAIN]  = NSS_STATUS_UNAVAIL,
  [YPERR_MAP]     = NSS_STATUS_UNAVAIL,
  [YPERR_KEY]     = NSS_STATUS_NOTFOUND,
  [YPERR_YPERR]   = NSS_STATUS_UNAVAIL,
  [YPERR_RESRC]   = NSS_STATUS_TRYAGAIN,
  [YPERR_NOMORE]  = NSS_STATUS_NOTFOUND,
  [YPERR_PMAP]    = NSS_STATUS_UNAVAIL,
  [YPERR_YPBIND]  = NSS_STATUS_UNAVAIL,
  [YPERR_YPSERV]  = NSS_STATUS_UNAVAIL,
  [YPERR_NODOM]   = NSS_STATUS_UNAVAIL,
  [YPERR_BADDB]   = NSS_STATUS_UNAVAIL,
  [YPERR_VERS]    = NSS_STATUS_UNAVAIL,
  [YPERR_ACCESS]  = NSS_STATUS_UNAVAIL,
  [YPERR_BUSY]    = NSS_STATUS_TRYAGAIN
};
#define YPERR_COUNT (sizeof (yperr2nss_tab) / sizeof (yperr2nss_tab[0]))

static inline enum nss_status
yperr2nss (int errval)
{
  if ((unsigned int) errval > YPERR_COUNT)
    return NSS_STATUS_UNAVAIL;
  return yperr2nss_tab[errval];
}

#endif /* nis/nss-nis.h */
