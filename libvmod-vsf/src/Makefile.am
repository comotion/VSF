
vmoddir = $(VMOD_DIR)
vmod_LTLIBRARIES = libvmod_vsf.la

libvmod_vsf_la_CFLAGS = $(VMOD_INCLUDES)
libvmod_vsf_la_LDFLAGS = -module -export-dynamic -avoid-version -shared \
	$(LIBS)

libvmod_vsf_la_SOURCES = \
	vmod_vsf.c
nodist_libvmod_vsf_la_SOURCES = \
	vcc_if.c \
	vcc_if.h

libvmod_vsf_la_CFLAGS += -I$(top_srcdir)/../utf8proc -std=c99
libvmod_vsf_la_SOURCES += \
	$(top_srcdir)/../utf8proc/utf8proc.c \
	$(top_srcdir)/../utf8proc/utf8proc.h

dist_man_MANS = vmod_vsf.3

VTC_LOG_COMPILER = $(VARNISHTEST) -v -i \
	-Dvarnishd=$(VARNISHD) -Dvmod_topbuild=$(abs_top_builddir)
TEST_EXTENSIONS = .vtc
TESTS = @VMOD_TESTS@

$(libvmod_vsf_la_OBJECTS): vcc_if.h

vcc_if.c vcc_if.h vmod_vsf.man.rst: $(VMODTOOL) $(top_srcdir)/src/vmod.vcc
	$(PYTHON) $(VMODTOOL) $(top_srcdir)/src/vmod.vcc

vmod_vsf.3: vmod_vsf.man.rst
	${RST2MAN} $? $@

EXTRA_DIST = vmod.vcc \
	$(TESTS)

CLEANFILES = $(builddir)/vcc_if.c \
	$(builddir)/vcc_if.h \
	$(builddir)/vmod_vsf.man.rst \
	$(builddir)/vmod_vsf.rst \
	$(builddir)/$(dist_man_MANS)
