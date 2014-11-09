NAME=MyPA
SUBDIRS = api lib

_default:
	@echo "read the makefile"

clean:
	for d in $(SUBDIRS); do make -s -C $$d clean; done

DESTDIR ?= /
install:
	@if [ "$(DESTDIR)" = "" ]; then \
		echo " "; \
		echo "ERROR: A destdir is required"; \
		exit 1; \
	fi

	mkdir -p $(DESTDIR)

	for d in $(SUBDIRS); do make DESTDIR=`cd $(DESTDIR) ; pwd` \
		-C $$d install; [ $$? = 0 ] || exit 1; done
