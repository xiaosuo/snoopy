.PHONY: all install clean test unitest

all install clean test unitest:
	$(MAKE) -C src $@
