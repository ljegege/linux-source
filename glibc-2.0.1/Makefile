# Copyright (C) 1991, 92, 93, 94, 95, 96, 97 Free Software Foundation, Inc.
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

#
#	Master Makefile for the GNU C library
#
ifneq (,)
This makefile requires GNU Make.
endif


# This is the default target; it makes everything except the tests.
.PHONY: all
all: lib others

define autoconf-it
@-rm -f $@.new
autoconf $(ACFLAGS) $< > $@.new
chmod a-w,a+x $@.new
mv -f $@.new $@
test ! -d CVS || cvs commit -m'Regenerated: autoconf $(ACFLAGS) $<' $@
endef

configure: configure.in aclocal.m4; $(autoconf-it)
%/configure: %/configure.in aclocal.m4; $(autoconf-it)

include Makeconfig

ifndef avoid-generated
-include $(objpfx)sysd-dirs
define \n


endef
sysdep-subdirs := $(subst $(\n), ,$(sysdep-subdirs))
endif

# These are the subdirectories containing the library source.
subdirs = csu assert ctype db locale intl catgets math setjmp signal stdlib \
	  stdio-common $(stdio) malloc string wcsmbs time dirent grp pwd \
	  posix io termios resource misc login socket sysvipc gmon gnulib \
	  wctype manual shadow md5-crypt nss $(sysdep-subdirs) po \
	  $(add-ons) elf
export subdirs := $(subdirs)	# Benign, useless in GNU make before 3.63.

# The mach and hurd subdirectories have many generated header files which
# much of the rest of the library depends on, so it is best to build them
# first (and mach before hurd, at that).  The before-compile additions in
# sysdeps/{mach,hurd}/Makefile should make it reliably work for these files
# not to exist when making in other directories, but it will be slower that
# way with more somewhat expensive `make' invocations.
subdirs	:= $(filter mach,$(subdirs)) $(filter hurd,$(subdirs)) \
	   $(filter-out mach hurd,$(subdirs))

# All initialization source files.
+subdir_inits	:= $(wildcard $(foreach dir,$(subdirs),$(dir)/init-$(dir).c))
# All subdirectories containing initialization source files.
+init_subdirs	:= $(patsubst %/,%,$(dir $(+subdir_inits)))


# These are the targets that are made by making them in each subdirectory.
+subdir_targets	:= subdir_lib objects objs others subdir_mostlyclean	\
		   subdir_clean subdir_distclean subdir_realclean	\
		   tests subdir_lint.out				\
		   subdir_distinfo					\
		   subdir_echo-headers subdir_echo-distinfo		\
		   subdir_install					\
		   $(addprefix install-, no-libc.a bin lib data headers others)

headers := errno.h sys/errno.h errnos.h limits.h values.h	\
	   features.h gnu-versions.h libc-lock.h xopen_lim.h
aux	 = sysdep $(libc-init) version
before-compile = $(objpfx)version-info.h

echo-headers: subdir_echo-headers

# What to install.
install-others = $(inst_includedir)/gnu/stubs.h
install-bin = glibcbug

ifeq (yes,$(build-shared))
before-compile += $(objpfx)gnu/lib-names.h
install-others += $(inst_includedir)/gnu/lib-names.h
endif

ifeq (yes,$(gnu-ld))
libc-init = set-init
else
libc-init = munch-init
$(objpfx)munch-init.c: munch.awk munch-tmpl.c $(+subdir_inits)
	awk -f $< subdirs='$(+init_subdirs)' $(word 2,$^) > $@-t
	mv -f $@-t $@
generated := $(generated) munch-init.c
endif


include Makerules

# Install from subdirectories too.
install: subdir_install

# Create linkfs for shared libraries using the `ldconfig' program is possible.
ifeq (no,$(cross-compiling))
ifeq (yes,$(build-shared))
install:
	test ! -x $(common-objpfx)elf/ldconfig || \
	  $(common-objpfx)elf/ldconfig -d $(inst_slibdir) $(inst_libdir)
endif
endif

# Build subdirectory lib objects.
lib-noranlib: subdir_lib

ifeq (yes,$(build-shared))
# Build the shared object from the PIC object library.
lib: $(common-objpfx)libc.so
endif

all-Subdirs-files = $(wildcard $(addsuffix /Subdirs, $(config-sysdirs)))
$(objpfx)sysd-dirs: $(+sysdir_pfx)config.make $(all-Subdirs-files)
	(echo define sysdep-subdirs;				\
	 sed 's/#.*$$//' $(all-Subdirs-files) /dev/null;	\
	 echo endef) > $@-tmp
	mv -f $@-tmp $@

all-Banner-files = $(wildcard $(addsuffix /Banner, $(subdirs)))
$(objpfx)version-info.h: $(+sysdir_pfx)config.make $(all-Banner-files)
	(case $(config-os) in \
	   linux*) version=`(echo -e "#include <linux/version.h>\nUTS_RELEASE"\
			     | $(CC)  -E -P - | \
			     sed -e 's/"\([^"]*\)".*/\1/p' -e d) 2>/dev/null`;\
		   if [ -z "$$version" ]; then \
		     if [ -r /proc/version ]; then \
		       version=`sed 's/.*version \([^ ]*\) .*/>>\1<</' \
				< /proc/version`; \
		     else \
		       version=`uname -r`; \
		     fi; \
		   fi; \
		   echo -n "\"Compiled on a Linux $$version system "; \
		   echo "on `date +%Y/%m/%d`.\\n\"" ;; \
	   *) ;; \
	 esac; \
	 files="$(all-Banner-files)";				\
	 if test -n "$$files"; then				\
	   echo "\"Available extensions:";			\
	   sed -e '/^#/d' -e 's/^[[:space:]]*/	/' $$files;	\
	   echo "\"";						\
	 fi) > $@T
	mv -f $@T $@
generated += version-info.h

version.c-objects := $(addprefix $(objpfx)version,$(object-suffixes))
$(version.c-objects): $(objpfx)version-info.h

# Makerules creates a file `stub-$(subdir)' for each subdirectory, which
# contains `#define __stub_FUNCTION' for each function which is a stub.
# Here we paste all of these together into <gnu/stubs.h>.

subdir-stubs := $(foreach dir,$(subdirs),$(common-objpfx)stub-$(dir))

# Since stubs.h is never needed when building the library, we simplify the
# hairy installation process by producing it in place only as the last part
# of the top-level `make install'.  It depends on subdir_install, which
# iterates over all the subdirs; subdir_install in each subdir depends on
# the subdir's stubs file.  Having more direct dependencies would result in
# extra iterations over the list for subdirs and many recursive makes.
$(inst_includedir)/gnu/stubs.h: subdir_install
	@rm -f $(objpfx)stubs.h
	(echo '/* This file is automatically generated.';\
	 echo '   It defines a symbol `__stub_FUNCTION'\'' for each function';\
	 echo '   in the C library which is a stub, meaning it will fail';\
	 echo '   every time called, usually setting errno to ENOSYS.  */';\
	 sort $(subdir-stubs)) > $(objpfx)stubs.h
	if test -r $@ && cmp -s $(objpfx)stubs.h $@; \
	then echo 'stubs.h unchanged'; \
	else $(INSTALL_DATA) $(objpfx)stubs.h $@; fi
	rm -f $(objpfx)stubs.h

ifeq (yes,$(build-shared))

$(inst_includedir)/gnu/lib-names.h: $(common-objpfx)gnu/lib-names.h
	if test -r $@ && cmp -s $< $@; \
	then echo 'gnu/lib-names.h unchanged'; \
	else $(INSTALL_DATA) $< $@; fi
endif

# The `glibcbug' script contains the version number and it shall be rebuild
# whenever this changes or the `glibcbug.in' file.
$(objpfx)glibcbug: $(common-objpfx)config.status glibcbug.in
	cd $(<D); CONFIG_FILES=$(@F) CONFIG_HEADERS= $(SHELL) $(<F)

# This makes the Info or DVI file of the documentation from the Texinfo source.
.PHONY: info dvi
info dvi:
	$(MAKE) $(PARALLELMFLAGS) -C manual $@

# This makes all the subdirectory targets.

# For each target, make it depend on DIR/target for each subdirectory DIR.
$(+subdir_targets): %: $(addsuffix /%,$(subdirs))

# Compute a list of all those targets.
all-subdirs-targets := $(foreach dir,$(subdirs),\
				 $(addprefix $(dir)/,$(+subdir_targets)))

# The action for each of those is to cd into the directory and make the
# target there.
$(all-subdirs-targets):
	$(MAKE) $(PARALLELMFLAGS) -C $(@D) $(@F)

.PHONY: $(+subdir_targets) $(all-subdirs-targets)

# Targets to clean things up to various degrees.

.PHONY: clean realclean distclean distclean-1 parent-clean parent-mostlyclean

# Subroutines of all cleaning targets.
parent-mostlyclean: common-mostlyclean # common-mostlyclean is in Makerules.
	-rm -f $(foreach o,$(object-suffixes),\
		   $(common-objpfx)$(patsubst %,$(libtype$o),c)) \
	       $(addprefix $(objpfx),$(install-lib))
parent-clean: parent-mostlyclean common-clean
	-rm -f $(addprefix $(common-objpfx),$(common-generated))
	-rm -f $(addprefix $(objpfx),sysd-Makefile sysd-dirs sysd-rules)

clean: parent-clean
# This is done this way rather than having `subdir_clean' be a
# dependency of this target so that libc.a will be removed before the
# subdirectories are dealt with and so they won't try to remove object
# files from it when it's going to be removed anyway.
	@$(MAKE) subdir_clean no_deps=t
mostlyclean: parent-mostlyclean
	@$(MAKE) subdir_mostlyclean no_deps=t

# The realclean target is just like distclean for the parent, but we want
# the subdirs to know the difference in case they care.
realclean distclean: parent-clean
# This is done this way rather than having `subdir_distclean' be a
# dependency of this target so that libc.a will be removed before the
# subdirectories are dealt with and so they won't try to remove object
# files from it when it's going to be removed anyway.
	@$(MAKE) distclean-1 no_deps=t distclean-1=$@ avoid-generated=yes

# Subroutine of distclean and realclean.
distclean-1: subdir_$(distclean-1)
	-rm -f $(config-generated)
	-rm -f $(addprefix $(objpfx),config.status config.cache config.log)
	-rm -f $(addprefix $(objpfx),config.make config-name.h config.h)
ifdef objdir
	-rm -f $(objpfx)Makefile
endif
	-rm -f $(sysdep-$(distclean-1))

.PHONY: echo_subdirs
echo_subdirs:;@echo '$(subdirs)'

.PHONY: echo-distinfo parent_echo-distinfo
echo-distinfo: parent_echo-distinfo subdir_echo-distinfo
parent_echo-distinfo:
	@echo $(addprefix +header+,$(headers)) \
	      $(addprefix +nodist+,$(generated))


# Make the distribution tarfile.

distribute  := README INSTALL FAQ NOTES NEWS PROJECTS			\
	       COPYING.LIB COPYING ChangeLog ChangeLog.[0-9]		\
	       Makefile Makeconfig Makerules Rules Make-dist MakeTAGS	\
	       extra-lib.mk o-iterator.mk				\
	       ansidecl.h mkinstalldirs move-if-change install-sh	\
	       configure configure.in aclocal.m4 config.sub config.guess\
	       config.h.in config.make.in config-name.in Makefile.in	\
	       autolock.sh rellns-sh munch-tmpl.c munch.awk interp.c	\
	       sysdep.h set-hooks.h libc-symbols.h version.h shlib-versions \
	       rpm/Makefile rpm/template rpm/rpmrc nsswitch.h netgroup.h \
	       mcheck.h glibcbug.in

distribute := $(strip $(distribute))
generated := $(generated) stubs.h version-info.h

README: README.template version.h ; # Make-dist should update README.

define format-me
@rm -f $@
makeinfo --no-validate --no-warn --no-headers $< -o $@
-chmod a-w $@
endef
INSTALL: manual/maint.texi; $(format-me)
NOTES: manual/creature.texi; $(format-me)

rpm/%: subdir_distinfo
	$(MAKE) $(PARALLELMFLAGS) -C $(@D) subdirs='$(subdirs)' $(@F)

# This is a special goal for people making binary distributions.  Normally
# everybody uses the DES based crypt library but for the distribution we
# need the only-MD5 based one as well.
md5-crypt/libmd5crypt:
	$(MAKE) $(PARALLELMFLAGS) -C $(@D) $(@F)
