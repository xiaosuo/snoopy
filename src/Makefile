CFLAGS += -Wall -O2 -D_GNU_SOURCE
LDFLAGS += -lpcap -lz
TARGETS := snoopy
OBJS := $(filter-out gen_ctab.o,$(patsubst %.c,%.o,$(wildcard *.c))) ctab.o
PREFIX ?= /usr/local

ifeq (${DEBUG},)
CFLAGS += -DNDEBUG
else
CFLAGS += -g
endif

.PHONY: all install clean test

all: ${TARGETS}

snoopy: ${OBJS}

ctab.c: gen_ctab
	./gen_ctab > ctab.c

install: all
	install -d ${DESTDIR}${PREFIX}/sbin/
	install ${TARGETS} ${DESTDIR}${PREFIX}/sbin/

clean:
	$(RM) *.o ${TARGETS} ctab.c

test:
	../test/test.sh
