# makefile to build VSF
build: libvmod-vsf/src/.libs/libvmod-vsf.so 

libvmod-vsf/src/.libs/libvmod-vsf.so: libvmod-vsf/utf8proc/utf8proc.c
	@cd libvmod-vsf && ./autogen.sh
	@cd libvmod-vsf && ./configure
	@${MAKE} -C libvmod-vsf

libvmod-vsf/utf8proc/utf8proc.c:
	@git submodule init
	@git submodule update

.PHONY: build vmod-vsthrottle
