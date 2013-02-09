realname = oacd_web

package = erlang-$(realname)
version = 2.0.0
tarname = $(package)
distdir = $(tarname)-$(version)

buildno = $(shell git describe --long --always | cut -d- -f2-3 | sed 's/-/./g')

srcdir = .
rpmbuilddir = rpmbuild

REBAR ?= rebar

edit = sed \
  -e 's|@PACKAGE_NAME[@]|$(package)|g' \
  -e 's|@PACKAGE_VERSION[@]|$(version)|g' \
  -e 's|@APP_NAME[@]|$(realname)|g'

all: compile

compile: src/$(realname).app.src
	REBAR_SHARED_DEPS=1 $(REBAR) compile skip_deps=true

clean:
	-rm -rf src/$(realname).app.src
	-rm -rf ebin
	-rm -rf $(distdir)
	-rm -rf $(distdir).tar.gz

src/$(realname).app.src specs/$(package).spec: % : %.in Makefile
	$(edit) $(srcdir)/$@.in > $@

check:
	REBAR_SHARED_DEPS=1 $(REBAR) eunit skip_deps=true

dist: $(distdir).tar.gz

$(distdir).tar.gz: $(distdir)
	tar chof - $(distdir) | gzip -9 -c > $@
	rm -rf $(distdir)

$(distdir): FORCE
	mkdir -p $(distdir)/src
	mkdir -p $(distdir)/include
	mkdir -p $(distdir)/specs
	cp Makefile $(distdir)
	cp rebar.config $(distdir)
	cp rebar.config.script $(distdir)
	cp src/$(realname).app.src.in $(distdir)/src
	cp $(wildcard src/*.erl) $(distdir)/src
	cp $(wildcard include/*.hrl) $(distdir)/include
	cp specs/$(package).spec.in $(distdir)/specs

distcheck: $(distdir).tar.gz
	gzip -cd $(distdir).tar.gz | tar xvf -
	cd $(distdir) && $(MAKE) all
	cd $(distdir) && $(MAKE) check
	cd $(distdir) && $(MAKE) clean
	rm -rf $(distdir)
	@echo "*** Package $(distdir).tar.gz is ready for distribution."

FORCE:
	-rm $(distdir).tar.gz >/dev/null 2>&1
	-rm -rf $(distdir) >/dev/null 2>&1

rpms: specs/$(package).spec $(distdir).tar.gz | $(rpmbuilddir)
	-rm -rf rpms/*.rpm
	cp $(distdir).tar.gz $(rpmbuilddir)/SOURCES
	rpmbuild --define "_topdir $(CURDIR)/rpmbuild" --define "buildno $(buildno)" -ba specs/$(package).spec
	cp $(distdir).tar.gz $(rpmbuilddir)/SOURCES
	mkdir -p rpms
	cp $(rpmbuilddir)/RPMS/**/*.rpm rpms
	rm -rf $(rpmbuilddir)

$(rpmbuilddir):
	rm -rf $(rpmbuilddir)
	mkdir -p $(rpmbuilddir)/BUILD
	mkdir -p $(rpmbuilddir)/RPMS
	mkdir -p $(rpmbuilddir)/SOURCES
	mkdir -p $(rpmbuilddir)/SPECS
	mkdir -p $(rpmbuilddir)/SRPMS

# START Local dependency management
deps: getdeps updatedeps

getdeps:
	$(REBAR) get-deps

updatedeps:
	$(REBAR) update-deps
# END Local dependency management

.PHONY: FORCE compile dist distcheck getdeps install install-lib install-bin
