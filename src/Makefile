CFLAGS += -Wall -D_GNU_SOURCE
LDFLAGS += -lpcap -lz
TARGETS := snoopy
OBJS := $(filter-out gen_ctab.o,$(patsubst %.c,%.o,$(wildcard *.c))) ctab.o
PREFIX ?= /usr/local

ifeq (${DEBUG},)
CFLAGS += -DNDEBUG -O2
else
CFLAGS += -g -O0
endif

ifneq ($(shell uname),Linux)
LDFLAGS += -liconv
endif

.PHONY: all install clean test unitest

all: ${TARGETS}

snoopy: ${OBJS}

ctab.c: gen_ctab
	./gen_ctab > ctab.c

install: all
	install -d ${DESTDIR}${PREFIX}/sbin/
	install ${TARGETS} ${DESTDIR}${PREFIX}/sbin/

clean:
	$(RM) *.o ${TARGETS} ctab.c gen_ctab unit

test:
	../test/test.sh

unitest:
	$(MAKE) clean
	$(MAKE) DEBUG=1
	test -L unit || ln -sf snoopy unit
	./unit
