#
# Makefile.am for .../testsuite
#

AUTOMAKE_OPTIONS = dejagnu

testsuite_prepare=/usr/lib/YaST2/testsuite/Makefile.testsuite

all-local: $(testsuite_prepare)
	make -f $(testsuite_prepare) RPMNAME=$(RPMNAME) srcdir=$(srcdir)

clean-local: $(testsuite_prepare)
	make -f $(testsuite_prepare) RPMNAME=$(RPMNAME) srcdir=$(srcdir) clean

#EXTRA_DIST = README
