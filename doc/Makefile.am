# Makefile.am for .../doc

SUBDIRS = autodocs

htmldir = @docdir@

CLEANFILES = $(wildcard *.png)
%.png: %.dia
	dia -n -e $@ $<

html_DATA = index.html $(wildcard *.html) workflow.png Todo.txt
EXTRA_DIST = $(html_DATA)
