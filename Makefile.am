# this file is based upon the same file in the pam_ldap distribution

noinst_PROGRAMS = pam_require.so
pam_require_so_SOURCES = pam_require.c
pam_require_so_LDFLAGS = @pam_require_so_LDFLAGS@

EXTRA_DIST = debian

DEFS = @DEFS@

if USE_NATIVE_LINKER
NATIVE_LINK = $(pam_require_so_LD) $(AM_LDFLAGS) -o $@ 
else
GNU_LINK = $(CCLD) $(AM_CFLAGS) $(CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -o $@
endif

LINK = $(NATIVE_LINK) $(GNU_LINK)

install-exec-local: pam_require.so
	@$(NORMAL_INSTALL)
	$(mkinstalldirs) $(DESTDIR)$(libdir)/security
if EXTENSION_SO
	$(INSTALL_PROGRAM) -o root -g root pam_require.so $(DESTDIR)$(libdir)/security/pam_require.so
else
if EXTENSION_1
	$(INSTALL_PROGRAM) -o root -g root pam_require.so $(DESTDIR)$(libdir)/security/libpam_require.1
else
	$(INSTALL_PROGRAM) -o root -g root pam_require.so $(DESTDIR)$(libdir)/security/pam_require.so.1
	(cd $(DESTDIR)$(libdir)/security; rm -f pam_require.so; ln -s pam_require.so.1 pam_require.so)
endif
endif

uninstall-local:
	@$(NORMAL_UNINSTALL)

debian-package:
	dpkg-buildpackage -rfakeroot -tc -us -uc 
