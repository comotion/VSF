# makefile to build VSF
build: libvmod-vsf/src/.libs/libvmod-vsf.so

libvmod-vsf/src/.libs/libvmod-vsf.so:
	@cd libvmod-vsf && ./autogen.sh
	@cd libvmod-vsf && ./configure
	@${MAKE} -C libvmod-vsf

libvmod-vsthrottle:
	git clone foo-bar

.PHONY: build vmod-vsthrottle
