/* s_rintl.c -- long double version of s_rint.c.
 * Conversion to long double by Ulrich Drepper,
 * Cygnus Support, drepper@cygnus.com.
 */

/*
 * ====================================================
 * Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.
 *
 * Developed at SunPro, a Sun Microsystems, Inc. business.
 * Permission to use, copy, modify, and distribute this
 * software is freely granted, provided that this notice
 * is preserved.
 * ====================================================
 */

#if defined(LIBM_SCCS) && !defined(lint)
static char rcsid[] = "$NetBSD: $";
#endif

/*
 * rintl(x)
 * Return x rounded to integral value according to the prevailing
 * rounding mode.
 * Method:
 *	Using floating addition.
 * Exception:
 *	Inexact flag raised if x not equal to rintl(x).
 */

#include "math.h"
#include "math_private.h"

#ifdef __STDC__
static const long double
#else
static long double
#endif
TWO64[2]={
  1.844674407370955161600000e+19, /* 0x403F, 0x00000000, 0x00000000 */
 -1.844674407370955161600000e+19, /* 0xC03F, 0x00000000, 0x00000000 */
};

#ifdef __STDC__
	long double __rintl(long double x)
#else
	long double __rintl(x)
	long double x;
#endif
{
	int32_t se,j0,sx;
	u_int32_t i,i0,i1;
	long double w,t;
	GET_LDOUBLE_WORDS(se,i0,i1,x);
	sx = (se>>15)&1;
	j0 = (se&0x7fff)-0x3fff;
	if(j0<32) {
	    if(j0<0) {
		if(((se&0x7fff)|i0|i1)==0) return x;
		i1 |= i0;
		i0 &= 0xe0000000;
		i0 |= (i1|-i1)&0x80000000;
		SET_LDOUBLE_MSW(x,i0);
	        w = TWO64[sx]+x;
	        t = w-TWO64[sx];
		GET_LDOUBLE_EXP(i0,t);
		SET_LDOUBLE_EXP(t,(i0&0x7fff)|(sx<<15));
	        return t;
	    } else {
		i = (0xffffffff)>>j0;
		if(((i0&i)|i1)==0) return x; /* x is integral */
		i>>=1;
		if(((i0&i)|i1)!=0) {
		    if(j0==31) i1 = 0x40000000; else
		    i0 = (i0&(~i))|((0x20000000)>>j0);
		    /* Shouldn't this be
		         if (j0 >= 30) i1 = 0x80000000 >> (j0 - 30);
		         i0 = (i0&(~i))|((0x20000000)>>j0);
		       If yes, this should be correct in s_rint and
		       s_rintf, too.  -- drepper@cygnus.com */
		}
	    }
	} else if (j0>63) {
	    if(j0==0x4000) return x+x;	/* inf or NaN */
	    else return x;		/* x is integral */
	} else {
	    i = ((u_int32_t)(0xffffffff))>>(j0-32);
	    if((i1&i)==0) return x;	/* x is integral */
	    i>>=1;
	    if((i1&i)!=0) i1 = (i1&(~i))|((0x40000000)>>(j0-32));
	}
	SET_LDOUBLE_WORDS(x,se,i0,i1);
	w = TWO64[sx]+x;
	return w-TWO64[sx];
}
weak_alias (__rintl, rintl)
