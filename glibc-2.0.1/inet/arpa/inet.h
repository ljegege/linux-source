/*
 * Copyright (c) 1983, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
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
 *
 *	@(#)inet.h	8.1 (Berkeley) 6/2/93
 */

#ifndef _INET_H_
#define	_INET_H_

/* External definitions for functions in inet(3) */

#include <sys/cdefs.h>
#include <sys/types.h>
#include <netinet/in.h>		/* To define `struct in_addr'.  */

__BEGIN_DECLS
u_long		 inet_addr __P((const char *));
int		 inet_aton __P((const char *, struct in_addr *));
u_int32_t	 inet_lnaof __P((struct in_addr));
struct in_addr	 inet_makeaddr __P((u_int32_t , u_int32_t));
char *		 inet_neta __P((u_long, char *, size_t));
u_int32_t	 inet_netof __P((struct in_addr));
u_int32_t	 inet_network __P((const char *));
char		*inet_net_ntop __P((int, const void *, int, char *, size_t));
int		 inet_net_pton __P((int, const char *, void *, size_t));
char		*inet_ntoa __P((struct in_addr));
int		 inet_pton __P((int, const char *, void *));
const char	*inet_ntop __P((int, const void *, char *, size_t));
u_int		 inet_nsap_addr __P((const char *, u_char *, int));
char		*inet_nsap_ntoa __P((int, const u_char *, char *));
__END_DECLS

#endif /* !_INET_H_ */
