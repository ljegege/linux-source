/* Copyright (C) 1991, 1992, 1996, 1997 Free Software Foundation, Inc.
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

#ifdef	BSD
#include </usr/include/stdio.h>
#else
#include <stdio.h>
#endif
#include <stdlib.h>
#include <string.h>


int
main (int argc, char **argv)
{
  char buf[BUFSIZ];
  FILE *in = stdin, *out = stdout;
  int x;

  if (sscanf ("0", "%d", &x) != 1)
    exit (EXIT_FAILURE);

  sscanf ("conversion] Zero flag Ze]ro#\n", "%*[^]] %[^#]\n", buf);
  if (strcmp (buf, "] Zero flag Ze]ro") != 0)
    {
      fputs ("test failed!\n", stderr);
      return 1;
    }

  if (argc == 2 && !strcmp (argv[1], "-opipe"))
    {
      out = popen ("/bin/cat", "w");
      if (out == NULL)
	{
	  perror ("popen: /bin/cat");
	  exit (EXIT_FAILURE);
	}
    }
  else if (argc == 3 && !strcmp (argv[1], "-ipipe"))
    {
      sprintf (buf, "/bin/cat %s", argv[2]);
      in = popen (buf, "r");
    }

  {
    char name[50];
    fprintf (out,
	     "sscanf (\"thompson\", \"%%s\", name) == %d, name == \"%s\"\n",
	     sscanf ("thompson", "%s", name),
	     name);
    if (strcmp (name, "thompson") != 0)
      return 1;
  }

  fputs ("Testing scanf (vfscanf)\n", out);

  fputs ("Test 1:\n", out);
  {
    int n, i;
    float x;
    char name[50];
    n = fscanf (in, "%d%f%s", &i, &x, name);
    fprintf (out, "n = %d, i = %d, x = %f, name = \"%.50s\"\n",
	     n, i, x, name);
    if (n != 3 || i != 25 || x != 5.432F || strcmp (name, "thompson"))
      return 1;
  }
  fprintf (out, "Residual: \"%s\"\n", fgets (buf, sizeof (buf), in));
  if (strcmp (buf, "\n"))
    return 1;
  fputs ("Test 2:\n", out);
  {
    int i;
    float x;
    char name[50];
    (void) fscanf (in, "%2d%f%*d %[0123456789]", &i, &x, name);
    fprintf (out, "i = %d, x = %f, name = \"%.50s\"\n", i, x, name);
    if (i != 56 || x != 789.0F || strcmp(name, "56"))
      return 1;
  }
  fprintf (out, "Residual: \"%s\"\n", fgets (buf, sizeof (buf), in));
  if (strcmp (buf, "a72\n"))
    return 1;
  fputs ("Test 3:\n", out);
  {
    static struct {
      int count;
      float quant;
      const char *units;
      const char *item;
    } ok[] = {
      { 3, 2.0F, "quarts", "oil" },
      { 2, -12.8F, "degrees", "" },
      { 0, 0.0F, "", "" },
      { 3, 10.0F, "LBS", "fertilizer" },
      { 3, 100.0F, "rgs", "energy" },
      { -1, 0.0F, "", "" }};
    size_t rounds = 0;
    float quant;
    char units[21], item[21];
    while (!feof (in) && !ferror (in))
      {
	int count;

	if (rounds++ >= sizeof (ok) / sizeof (ok[0]))
	  return 1;

	quant = 0.0;
	units[0] = item[0] = '\0';
	count = fscanf (in, "%f%20s of %20s", &quant, units, item);
	(void) fscanf (in, "%*[^\n]");
	fprintf (out, "count = %d, quant = %f, item = %.21s, units = %.21s\n",
		 count, quant, item, units);
	if (count != ok[rounds-1].count || quant != ok[rounds-1].quant
	    || strcmp (item, ok[rounds-1].item)
	    || strcmp (units, ok[rounds-1].units))
	  return 1;
      }
  }
  buf[0] = '\0';
  fprintf (out, "Residual: \"%s\"\n", fgets (buf, sizeof (buf), in));
  if (strcmp (buf, ""))
    return 1;

  if (out != stdout)
    pclose (out);

  exit(EXIT_SUCCESS);
}
