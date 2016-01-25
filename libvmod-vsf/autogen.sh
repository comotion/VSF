#!/bin/sh

dataroot=$(pkg-config --variable=datarootdir varnishapi 2>/dev/null)
if [ -z "$dataroot" ] ; then
	cat <<_EOF

No package 'varnishapi' found

Consider adjusting the PKG_CONFIG_PATH environment variable if you
installed software in a non-standard prefix.

_EOF
	exit 1
fi
autoreconf -vif -I${dataroot}/aclocal
