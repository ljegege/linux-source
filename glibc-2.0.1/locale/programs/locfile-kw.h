/* C code produced by gperf version 2.5 (GNU C++ version) */
/* Command-line: gperf -acCgopt -k1,2,5,$ -N locfile_hash programs/locfile-kw.gperf  */
/* Copyright (C) 1996 Free Software Foundation, Inc.
This file is part of the GNU C Library.
Contributed by Ulrich Drepper, <drepper@gnu.ai.mit.edu>.

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

#include <string.h>

#include "locfile-token.h"
struct keyword_t ;

#define TOTAL_KEYWORDS 73
#define MIN_WORD_LENGTH 3
#define MAX_WORD_LENGTH 17
#define MIN_HASH_VALUE 3
#define MAX_HASH_VALUE 132
/* maximum key range = 130, duplicates = 0 */

#ifdef __GNUC__
inline
#endif
static unsigned int
hash (register const char *str, register int len)
{
  static const unsigned char asso_values[] =
    {
     133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
     133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
     133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
     133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
     133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
     133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
     133, 133, 133, 133, 133, 133, 133,   0,   0,   0,
       0,   0, 133,   0, 133, 133,   0, 133,   0,  20,
     133, 133,   0,   0,   0,   5, 133, 133, 133,   5,
     133, 133, 133, 133, 133,   5, 133,   0,  60,   0,
      15,  10,  20,  40,   5,  20, 133,   0,  45,  40,
      10,   0,   0, 133,  15,  50,   0,  30,   0,  10,
      15,  15, 133, 133, 133, 133, 133, 133,
    };
  register int hval = len;

  switch (hval)
    {
      default:
      case 5:
        hval += asso_values[str[4]];
      case 4:
      case 3:
      case 2:
        hval += asso_values[str[1]];
      case 1:
        hval += asso_values[str[0]];
        break;
    }
  return hval + asso_values[str[len - 1]];
}

#ifdef __GNUC__
inline
#endif
const struct keyword_t *
locfile_hash (register const char *str, register int len)
{
  static const struct keyword_t wordlist[] =
    {
      {"",}, {"",}, {"",}, 
      {"END",                tok_end,               0},
      {"",}, {"",}, 
      {"IGNORE",             tok_ignore,            0},
      {"LC_TIME",            tok_lc_time,           0},
      {"LC_CTYPE",           tok_lc_ctype,          0},
      {"",}, 
      {"t_fmt",              tok_t_fmt,             0},
      {"LC_MESSAGES",        tok_lc_messages,       0},
      {"",}, 
      {"charconv",           tok_charconv,          0},
      {"UNDEFINED",          tok_undefined,         0},
      {"LC_NUMERIC",         tok_lc_numeric,        0},
      {"",}, 
      {"collating-element",  tok_collating_element, 0},
      {"position",           tok_position,          0},
      {"copy",               tok_copy,              0},
      {"print",              tok_print,             0},
      {"",}, 
      {"toupper",            tok_toupper,           0},
      {"positive_sign",      tok_positive_sign,     0},
      {"",}, 
      {"d_fmt",              tok_d_fmt,             0},
      {"",}, {"",}, 
      {"era",                tok_era,               0},
      {"p_sep_by_space",     tok_p_sep_by_space,    0},
      {"LC_COLLATE",         tok_lc_collate,        0},
      {"noexpr",             tok_noexpr,            0},
      {"tolower",            tok_tolower,           0},
      {"day",                tok_day,               0},
      {"era_t_fmt",          tok_era_t_fmt,         0},
      {"punct",              tok_punct,             0},
      {"LC_MONETARY",        tok_lc_monetary,       0},
      {"comment_char",       tok_comment_char,      0},
      {"",}, 
      {"n_sep_by_space",     tok_n_sep_by_space,    0},
      {"digit",              tok_digit,             0},
      {"order_start",        tok_order_start,       0},
      {"forward",            tok_forward,           0},
      {"negative_sign",      tok_negative_sign,     0},
      {"",}, 
      {"nostr",              tok_nostr,             0},
      {"yesstr",             tok_yesstr,            0},
      {"d_t_fmt",            tok_d_t_fmt,           0},
      {"",}, 
      {"era_d_fmt",          tok_era_d_fmt,         0},
      {"alpha",              tok_alpha,             0},
      {"era_d_t_fmt",        tok_era_d_t_fmt,       0},
      {"",}, 
      {"mon",                tok_mon,               0},
      {"order_end",          tok_order_end,         0},
      {"t_fmt_ampm",         tok_t_fmt_ampm,        0},
      {"xdigit",             tok_xdigit,            0},
      {"mon_thousands_sep",  tok_mon_thousands_sep, 0},
      {"",}, {"",}, {"",}, 
      {"collating-symbol",   tok_collating_symbol,  0},
      {"yesexpr",            tok_yesexpr,           0},
      {"era_year",           tok_era_year,          0},
      {"charclass",          tok_charclass,         0},
      {"upper",              tok_upper,             0},
      {"p_sign_posn",        tok_p_sign_posn,       0},
      {"",}, 
      {"thousands_sep",      tok_thousands_sep,     0},
      {"",}, 
      {"graph",              tok_graph,             0},
      {"",}, 
      {"mon_decimal_point",  tok_mon_decimal_point, 0},
      {"p_cs_precedes",      tok_p_cs_precedes,     0},
      {"",}, 
      {"space",              tok_space,             0},
      {"n_sign_posn",        tok_n_sign_posn,       0},
      {"",}, 
      {"decimal_point",      tok_decimal_point,     0},
      {"from",               tok_from,              0},
      {"lower",              tok_lower,             0},
      {"",}, {"",}, 
      {"n_cs_precedes",      tok_n_cs_precedes,     0},
      {"",}, 
      {"abmon",              tok_abmon,             0},
      {"escape_char",        tok_escape_char,       0},
      {"",}, {"",}, {"",}, 
      {"int_curr_symbol",    tok_int_curr_symbol,   0},
      {"",}, {"",}, 
      {"backward",           tok_backward,          0},
      {"",}, 
      {"abday",              tok_abday,             0},
      {"",}, {"",}, {"",}, {"",}, 
      {"currency_symbol",    tok_currency_symbol,   0},
      {"frac_digits",        tok_frac_digits,       0},
      {"",}, 
      {"grouping",           tok_grouping,          0},
      {"",}, 
      {"cntrl",              tok_cntrl,             0},
      {"",}, {"",}, {"",}, {"",}, 
      {"blank",              tok_blank,             0},
      {"",}, {"",}, {"",}, {"",}, 
      {"int_frac_digits",    tok_int_frac_digits,   0},
      {"",}, {"",}, {"",}, {"",}, 
      {"alt_digits",         tok_alt_digits,        0},
      {"",}, {"",}, {"",}, {"",}, 
      {"am_pm",              tok_am_pm,             0},
      {"",}, {"",}, {"",}, {"",}, 
      {"alnum",              tok_alnum,             0},
      {"",}, 
      {"mon_grouping",       tok_mon_grouping,      0},
    };

  if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH)
    {
      register int key = hash (str, len);

      if (key <= MAX_HASH_VALUE && key >= 0)
        {
          register const char *s = wordlist[key].name;

          if (*s == *str && !strncmp (str + 1, s + 1, len - 1))
            return &wordlist[key];
        }
    }
  return 0;
}
