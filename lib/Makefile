SUBDIRS = MyPA

_default:
	@echo "Nothing to make."

clean:
	for d in $(SUBDIRS); do make -s -C $$d clean; done

install:
	for d in $(SUBDIRS); do make DESTDIR=$(DESTDIR) \
		-C $$d install; [ $$? = 0 ] || exit 1; done
