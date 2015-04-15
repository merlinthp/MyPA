SUBDIRS = templates

PYTHON=python
PYFILES = $(wildcard *.py)
SHDIR = /usr/share/MyPA
INIFILE = ui.ini
INIDIR = /etc/MyPA
HTTPDCONF = mypa-ui.conf
HTTPDDIR = /etc/httpd/conf.d

_default:
	@echo "nothing to make"

clean:
	rm -f *.pyc

install:
	mkdir -p $(DESTDIR)/$(SHDIR)
	for p in $(PYFILES) ; do \
		install -p -m 644 $$p $(DESTDIR)/$(SHDIR)/$$p; \
	done
	$(PYTHON) -c "import compileall; compileall.compile_dir('$(DESTDIR)/$(SHDIR)', 1, '$(PYDIR)', 1)"
	mkdir -p $(DESTDIR)/$(INIDIR)
	install -p -m 600 $(INIFILE) $(DESTDIR)/$(INIDIR)/
	mkdir -p $(DESTDIR)/$(HTTPDDIR)
	install -p -m 644 $(HTTPDCONF) $(DESTDIR)/$(HTTPDDIR)/
	for d in $(SUBDIRS); do make DESTDIR=$(DESTDIR) \
		-C $$d install; [ $$? = 0 ] || exit 1; done
