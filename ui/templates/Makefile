
FILES = $(wildcard *.html)
TEMPLDIR = /usr/share/MyPA/templates

_default:
	@echo "nothing to make"

clean:
	@echo "nothing to clean"

install:
	mkdir -p $(DESTDIR)/$(TEMPLDIR)
	for f in $(FILES) ; do \
		install -p -m 644 $$f $(DESTDIR)/$(TEMPLDIR)/$$f; \
	done
