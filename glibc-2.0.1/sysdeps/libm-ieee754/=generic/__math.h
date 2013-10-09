/* Inline math functions for i387.
Copyright (C) 1995, 1996 Free Software Foundation, Inc.
Contributed by John C. Bowman <bowman@hagar.ph.utexas.edu>

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
not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.  */

#ifndef __MATH_H
#define __MATH_H

#ifdef	__GNUC__
#ifndef __NO_MATH_INLINES

#ifdef __cplusplus
#define	__MATH_INLINE __inline
#else
#define	__MATH_INLINE extern __inline
#endif

__MATH_INLINE double cos (double);
__MATH_INLINE double sin (double);


__MATH_INLINE double __expm1 (double __x);
__MATH_INLINE double
__expm1 (double __x)
{
  register double __value, __exponent, __temp;
  __asm __volatile__
    ("fldl2e			# e^x - 1 = 2^(x * log2(e)) - 1\n\t"
     "fmul	%%st(1)		# x * log2(e)\n\t"
     "fstl	%%st(1)\n\t"
     "frndint			# int(x * log2(e))\n\t"
     "fxch\n\t"
     "fsub	%%st(1)		# fract(x * log2(e))\n\t"
     "f2xm1			# 2^(fract(x * log2(e))) - 1\n\t"
     "fscale			# 2^(x * log2(e)) - 2^(int(x * log2(e)))\n\t"
     : "=t" (__value), "=u" (__exponent) : "0" (__x));
  __asm __volatile__
    ("fscale			# 2^int(x * log2(e))\n\t"
     : "=t" (__temp) : "0" (1.0), "u" (__exponent));
  __temp -= 1.0;

  return __temp + __value;
}

__MATH_INLINE double __sgn1 (double __x);
__MATH_INLINE double
__sgn1 (double __x)
{
  return __x >= 0.0 ? 1.0 : -1.0;
}

__MATH_INLINE double sqrt (double __x);
__MATH_INLINE double
sqrt (double __x)
{
  register double __value;
  __asm __volatile__
    ("fsqrt"
     : "=t" (__value) : "0" (__x));

  return __value;
}

__MATH_INLINE double fabs (double __x);
__MATH_INLINE double
fabs (double __x)
{
  register double __value;
  __asm __volatile__
    ("fabs"
     : "=t" (__value) : "0" (__x));

  return __value;
}

__MATH_INLINE double sin (double __x);
__MATH_INLINE double
sin (double __x)
{
  register double __value;
  __asm __volatile__
    ("fsin"
     : "=t" (__value) : "0" (__x));

  return __value;
}

__MATH_INLINE double cos (double __x);
__MATH_INLINE double
cos (double __x)
{
  register double __value;
  __asm __volatile__
    ("fcos"
     : "=t" (__value): "0" (__x));

  return __value;
}

__MATH_INLINE double tan (double __x);
__MATH_INLINE double
tan (double __x)
{
  register double __value;
  __asm __volatile__
    ("fptan"
     : "=u" (__value) : "t" (__x));

  return __value;
}

__MATH_INLINE double atan2 (double __y, double __x);
__MATH_INLINE double
atan2 (double __y, double __x)
{
  register double __value;
  __asm __volatile__
    ("fpatan\n\t"
     "fldl %%st(0)"
     : "=t" (__value) : "0" (__x), "u" (__y));

  return __value;
}

__MATH_INLINE double asin (double __x);
__MATH_INLINE double
asin (double __x)
{
  return atan2 (__x, sqrt (1.0 - __x * __x));
}

__MATH_INLINE double acos (double __x);
__MATH_INLINE double
acos (double __x)
{
  return atan2 (sqrt (1.0 - __x * __x), __x);
}

__MATH_INLINE double atan (double __x);
__MATH_INLINE double
atan (double __x)
{
  register double __value;
  __asm __volatile__
    ("fld1\n\t"
     "fpatan"
     : "=t" (__value) : "0" (__x));

  return __value;
}

__MATH_INLINE double exp (double __x);
__MATH_INLINE double
exp (double __x)
{
  register double __value, __exponent;
  __asm __volatile__
    ("fldl2e			# e^x = 2^(x * log2(e))\n\t"
     "fmul	%%st(1)		# x * log2(e)\n\t"
     "fstl	%%st(1)\n\t"
     "frndint			# int(x * log2(e))\n\t"
     "fxch\n\t"
     "fsub	%%st(1)		# fract(x * log2(e))\n\t"
     "f2xm1			# 2^(fract(x * log2(e))) - 1\n\t"
     : "=t" (__value), "=u" (__exponent) : "0" (__x));
  __value += 1.0;
  __asm __volatile__
    ("fscale"
     : "=t" (__value) : "0" (__value), "u" (__exponent));

  return __value;
}

__MATH_INLINE double sinh (double __x);
__MATH_INLINE double
sinh (double __x)
{
  register double __exm1 = __expm1 (fabs (__x));

  return 0.5 * (__exm1 / (__exm1 + 1.0) + __exm1) * __sgn1 (__x);
}

__MATH_INLINE double cosh (double __x);
__MATH_INLINE double
cosh (double __x)
{
  register double __ex = exp (__x);

  return 0.5 * (__ex + 1.0 / __ex);
}

__MATH_INLINE double tanh (double __x);
__MATH_INLINE double
tanh (double __x)
{
  register double __exm1 = __expm1 (-fabs (__x + __x));

  return __exm1 / (__exm1 + 2.0) * __sgn1 (-__x);
}

__MATH_INLINE double log (double __x);
__MATH_INLINE double
log (double __x)
{
  register double __value;
  __asm __volatile__
    ("fldln2\n\t"
     "fxch\n\t"
     "fyl2x"
     : "=t" (__value) : "0" (__x));

  return __value;
}

__MATH_INLINE double log10 (double __x);
__MATH_INLINE double
log10 (double __x)
{
  register double __value;
  __asm __volatile__
    ("fldlg2\n\t"
     "fxch\n\t"
     "fyl2x"
     : "=t" (__value) : "0" (__x));

  return __value;
}

__MATH_INLINE double __log2 (double __x);
__MATH_INLINE double
__log2 (double __x)
{
  register double __value;
  __asm __volatile__
    ("fld1\n\t"
     "fxch\n\t"
     "fyl2x"
     : "=t" (__value) : "0" (__x));

  return __value;
}

__MATH_INLINE double fmod (double __x, double __y);
__MATH_INLINE double
fmod (double __x, double __y)
{
  register double __value;
  __asm __volatile__
    ("1:	fprem\n\t"
     "fstsw	%%ax\n\t"
     "sahf\n\t"
     "jp	1b"
     : "=t" (__value) : "0" (__x), "u" (__y) : "ax", "cc");

  return __value;
}

__MATH_INLINE double ldexp (double __x, int __y);
__MATH_INLINE double
ldexp (double __x, int __y)
{
  register double __value;
  __asm __volatile__
    ("fscale"
     : "=t" (__value) : "0" (__x), "u" ((double) __y));

  return __value;
}

__MATH_INLINE double pow (double __x, double __y);
__MATH_INLINE double
pow (double __x, double __y)
{
  register double __value, __exponent;
  long __p = (long) __y;

  if (__x == 0.0 && __y > 0.0)
    return 0.0;
  if (__y == (double) __p)
    {
      double __r = 1.0;
      if (__p == 0)
	return 1.0;
      if (__p < 0)
	{
	  __p = -__p;
	  __x = 1.0 / __x;
	}
      while (1)
	{
	  if (__p & 1)
	    __r *= __x;
	  __p >>= 1;
	  if (__p == 0)
	    return __r;
	  __x *= __x;
	}
      /* NOTREACHED */
    }
  __asm __volatile__
    ("fmul	%%st(1)		# y * log2(x)\n\t"
     "fstl	%%st(1)\n\t"
     "frndint			# int(y * log2(x))\n\t"
     "fxch\n\t"
     "fsub	%%st(1)		# fract(y * log2(x))\n\t"
     "f2xm1			# 2^(fract(y * log2(x))) - 1\n\t"
     : "=t" (__value), "=u" (__exponent) :  "0" (__log2 (__x)), "1" (__y));
  __value += 1.0;
  __asm __volatile__
    ("fscale"
     : "=t" (__value) : "0" (__value), "u" (__exponent));

  return __value;
}

__MATH_INLINE double floor (double __x);
__MATH_INLINE double
floor (double __x)
{
  register double __value;
  volatile short __cw, __cwtmp;

  __asm volatile ("fnstcw %0" : "=m" (__cw));
  __cwtmp = (__cw & 0xf3ff) | 0x0400; /* rounding down */
  __asm volatile ("fldcw %0" : : "m" (__cwtmp));
  __asm volatile ("frndint" : "=t" (__value) : "0" (__x));
  __asm volatile ("fldcw %0" : : "m" (__cw));

  return __value;
}

__MATH_INLINE double ceil (double __x);
__MATH_INLINE double
ceil (double __x)
{
  register double __value;
  volatile short __cw, __cwtmp;

  __asm volatile ("fnstcw %0" : "=m" (__cw));
  __cwtmp = (__cw & 0xf3ff) | 0x0800; /* rounding up */
  __asm volatile ("fldcw %0" : : "m" (__cwtmp));
  __asm volatile ("frndint" : "=t" (__value) : "0" (__x));
  __asm volatile ("fldcw %0" : : "m" (__cw));

  return __value;
}


/* Optimized versions for some non-standardized functions.  */
#ifdef __USE_MISC

__MATH_INLINE double __hypot (double __x, double __y);
__MATH_INLINE double
hypot (double __x, double __y)
{
  return sqrt (__x * __x + __y * __y);
}

__MATH_INLINE double
log1p (double __x)
{
  register double __value;

  if (fabs (__x) >= 1.0 - 0.5 * M_SQRT2)
    __value = log (1.0 + __x);
  else
    __asm __volatile__
      ("fldln2\n\t"
       "fxch\n\t"
       "fyl2xp1"
       : "=t" (__value) : "0" (__x));

  return __value;
}

__MATH_INLINE double __asinh (double __x);
__MATH_INLINE double
asinh (double __x)
{
  register double __y = fabs (__x);

  return log1p ((__y * __y / (sqrt (__y * __y + 1.0) + 1.0) + __y)
		* __sgn1 (__x));
}

__MATH_INLINE double __acosh (double __x);
__MATH_INLINE double
acosh (double __x)
{
  return log (__x + sqrt (__x - 1.0) * sqrt (__x + 1.0));
}

__MATH_INLINE double __atanh (double __x);
__MATH_INLINE double
atanh (double __x)
{
  register double __y = fabs (__x);

  return -0.5 * __log1p (-(__y + __y) / (1.0 + __y)) * __sgn1 (__x);
}

__MATH_INLINE double __coshm1 (double __x);
__MATH_INLINE double
coshm1 (double __x)
{
  register double __exm1 = __expm1 (fabs (__x));

  return 0.5 * (__exm1 / (__exm1 + 1.0)) * __exm1;
}

__MATH_INLINE double __acosh1p (double __x);
__MATH_INLINE double
acosh1p (double __x)
{
  return __log1p (__x + sqrt (__x) * sqrt (__x + 2.0));
}

__MATH_INLINE double __logb (double __x);
__MATH_INLINE double
logb (double __x)
{
  register double __value;
  __asm __volatile__
    ("fxtract\n\t"
     : "=t" (__value) : "0" (__x));

  return __value;
}

__MATH_INLINE double __drem (double __x, double __y);
__MATH_INLINE double
drem (double __x, double __y)
{
  register double __value;
  __asm __volatile__
    ("1:	fprem1\n\t"
     "fstsw	%%ax\n\t"
     "sahf\n\t"
     "jp	1b"
     : "=t" (__value) : "0" (__x), "u" (__y) : "ax", "cc");

  return __value;
}

__MATH_INLINE void __sincos (double __x, double *__sinx, double *__cosx);
__MATH_INLINE void
sincos (double __x, double *__sinx, double *__cosx)
{
  register double __cosr, __sinr;
  __asm __volatile__
    ("fsincos"
     : "=t" (__cosr), "=u" (__sinr) : "0" (__x));

  *__sinx = __sinr;
  *__cosx = __cosr;
}

__MATH_INLINE double __sgn (double __x);
__MATH_INLINE double
sgn (double __x)
{
  return (__x == 0.0 ? 0.0 : (__x > 0.0 ? 1.0 : -1.0));
}

__MATH_INLINE double __pow2 (double __x);
__MATH_INLINE double
pow2 (double __x)
{
  register double __value, __exponent;
  long __p = (long) __x;

  if (__x == (double) __p)
    return ldexp (1.0, __p);

  __asm __volatile__
    ("fldl	%%st(0)\n\t"
     "frndint			# int(x)\n\t"
     "fxch\n\t"
     "fsub	%%st(1)		# fract(x)\n\t"
     "f2xm1			# 2^(fract(x)) - 1\n\t"
     : "=t" (__value), "=u" (__exponent) : "0" (__x));
  __value += 1.0;
  __asm __volatile__
    ("fscale"
     : "=t" (__value) : "0" (__value), "u" (__exponent));

  return __value;
}

#endif /* __USE_MISC  */

#endif /* __NO_MATH_INLINES  */
#endif /* __GNUC__  */

#endif /* __MATH_H  */
