# Copyright (C) 1991, 92, 93, 94, 95, 96 Free Software Foundation, Inc.
# This file is part of the GNU C Library.

# The GNU C Library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Library General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.

# The GNU C Library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Library General Public License for more details.

# You should have received a copy of the GNU Library General Public
# License along with the GNU C Library; see the file COPYING.LIB.  If not,
# write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA.

$(common-objpfx)stdio_lim.h: $(common-objpfx)mk-stdiolim
	$(dir $<)$(notdir $<) > $@-t
	mv $@-t $@

# Turn into a version that works when cd'd into $(objdir).
cded-objdir-includes = $(patsubst -I$$cwd//%,-I/%,\
				  $(patsubst -I%,-I$$cwd/%,$(+includes)))
# $(BUILD_CFLAGS) needs to come last because it contains unwanted -Is.
$(common-objpfx)mk-stdiolim: $(sysdep_dir)/posix/mk-stdiolim.c \
			     $(..)posix/posix1_lim.h local_lim.h
	cwd=`pwd`; cd $(objpfx).; \
	$(BUILD_CC) $(cded-objdir-includes) $(BUILD_CFLAGS) \
	  $$cwd/$< -o $(patsubst $(common-objpfx)%,$(..)%,$@)


common-generated := $(common-generated) stdio_lim.h mk-stdiolim
before-compile := $(before-compile) $(common-objpfx)stdio_lim.h
