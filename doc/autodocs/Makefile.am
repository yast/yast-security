#
# Makefile.am for y2c_sec/doc/autodocs
#

docdir = @DOCDIR@
htmldir = $(docdir)/security/autodocs

html_DATA =                                                             \
	*.html

EXTRA_DIST = $(html_DATA)

MAINTAINERCLEANFILES = $(html_DATA)

$(filter-out index.html, $(html_DATA)): index.html
index.html: $(srcdir)/../../src/*.ycp
	@YAST2DIR@/bin/ycpdoc -d. $(srcdir)/../../src/*.ycp

clean:
	rm -f *.html
