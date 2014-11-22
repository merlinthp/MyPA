
FILES = $(wildcard *.txt *.html)
TEMPLDIR = /usr/share/MyPA/mailtemplates

_default:
	@echo "nothing to make"

clean:
	@echo "nothing to do"

install:
	mkdir -p $(DESTDIR)/$(TEMPLDIR)
	for f in $(FILES) ; do \
		install -p -m 644 $$f $(DESTDIR)/$(TEMPLDIR)/$$f; \
	done
