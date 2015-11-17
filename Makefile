# makefile to build VSF
VCLDIR = /etc/varnish/security
INSTALLGROUP = root

RULES = $(shell ls vcl/rules/*.vcl)

build: libvmod-vsf/src/.libs/libvmod-vsf.so  libvmod-vsthrottle/src/.libs/libvmod-vsthrottle.so vcl

libvmod-vsf/src/.libs/libvmod-vsf.so: libvmod-vsf/utf8proc/utf8proc.c
	@cd libvmod-vsf && ./autogen.sh
	@cd libvmod-vsf && ./configure
	@${MAKE} -C libvmod-vsf

libvmod-vsf/utf8proc/utf8proc.c:
	@git submodule init
	@git submodule update

libvmod-vsthrottle/src/vmod_vsthrottle.c:
	@git submodule init
	@git submodule update

libvmod-vsthrottle/src/.libs/libvmod-vsthrottle.so: libvmod-vsthrottle/src/vmod_vsthrottle.c
	@cd libvmod-vsthrottle && ./autogen.sh && ./configure
	@${MAKE} -C libvmod-vsthrottle

vcl:
	@${MAKE} -C vcl

install: 
	@${MAKE} -C libvmod-vsf $@
	@${MAKE} -C libvmod-vsthrottle $@
	install -o root -g ${INSTALLGROUP} -d ${DESTDIR}${VCLDIR}
	install -o root -g ${INSTALLGROUP} -d ${DESTDIR}${VCLDIR}/rules
	install -o root -g ${INSTALLGROUP} -m 644 vcl/vsf.vcl ${DESTDIR}${VCLDIR}
	install -o root -g ${INSTALLGROUP} -m 644 vcl/config.vcl ${DESTDIR}${VCLDIR}
	install -o root -g ${INSTALLGROUP} -m 644 vcl/handlers.vcl ${DESTDIR}${VCLDIR}
	install -o root -g ${INSTALLGROUP} -m 644 vcl/local.vcl.example ${DESTDIR}${VCLDIR}/local.vcl
	for rule in ${RULES}; do install -o root -g ${INSTALLGROUP} -m 644 $$rule ${DESTDIR}${VCLDIR}/rules/$${rule#vcl/rules/}; done

check: build vcl-check
	@${MAKE} -C libvmod-vsf $@

vcl-check:
	cp vcl/local.vcl.example vcl/local.vcl
	varnishtest tests/*.vtc
	rm vcl/local.vcl
	
.PHONY: build vmod-vsthrottle check vcl-check vcl
