.PHONY: all install clean test

all install clean test:
	$(MAKE) -C src $@
