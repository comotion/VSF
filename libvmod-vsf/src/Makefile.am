
TESTS_ENVIRONMENT = PATH=$(VARNISH_BINDIR):$(VARNISH_SBINDIR):$$PATH

vmoddir = $(VMOD_DIR)
vmod_LTLIBRARIES = libvmod_vsf.la

libvmod_vsf_la_CFLAGS = $(VMOD_INCLUDES) -I$(top_srcdir)/utf8proc
libvmod_vsf_la_LDFLAGS = -module -export-dynamic -avoid-version -shared

libvmod_vsf_la_SOURCES = \
	vmod_vsf.c \
	vmod_vsthrottle.c \
	$(top_srcdir)/utf8proc/utf8proc.c \
	$(top_srcdir)/utf8proc/utf8proc.h

nodist_libvmod_vsf_la_SOURCES = \
	vcc_if.c \
	vcc_if.h

dist_man_MANS = vmod_vsf.3

VTC_LOG_COMPILER = $(VARNISHTEST) -v \
	-Dvmod_topbuild=$(abs_top_builddir)
TEST_EXTENSIONS = .vtc
TESTS = @VMOD_TESTS@

$(libvmod_vsf_la_OBJECTS): vcc_if.h

vcc_if.h vmod_utf8.man.rst vmod_utf8.rst: vcc_if.c

vcc_if.c: $(VMODTOOL) $(top_srcdir)/src/vmod_vsf.vcc
	$(PYTHON) $(VMODTOOL) $(top_srcdir)/src/vmod_vsf.vcc

vmod_vsf.3: vmod_vsf.man.rst
	${RST2MAN} $? $@

EXTRA_DIST = vmod_vsf.vcc \
	$(top_srcdir)/utf8proc/utf8proc_data.c \
	$(TESTS)

CLEANFILES = $(builddir)/vcc_if.c \
	$(builddir)/vcc_if.h \
	$(builddir)/vmod_vsf.man.rst \
	$(builddir)/vmod_vsf.rst \
	$(builddir)/$(dist_man_MANS)
