SHELL=/bin/sh
MAKE = make
SUBDIRS ?= wmediumd
BIN = wmediumd/wmediumd_802154
BINDIR = /usr/bin

all:

	@for i in $(SUBDIRS); do \
	echo "make all in $$i..."; \
	(cd $$i; $(MAKE) all); done

clean:

	@for i in $(SUBDIRS); do \
	echo "Clearing in $$i..."; \
	(cd $$i; $(MAKE) clean); done

install: all
	install -m 0755 $(BIN) $(BINDIR)
