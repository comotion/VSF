# makefile to build VSF
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


.PHONY: build vmod-vsthrottle
