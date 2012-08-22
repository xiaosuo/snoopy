CFLAGS += -Wall -O2 -D_GNU_SOURCE
LDFLAGS += -lpcap
TARGETS := snoopy
OBJS := $(patsubst %.c,%.o,$(wildcard *.c))

ifeq (${DEBUG},)
CFLAGS += -DNDEBUG
else
CFLAGS += -g
endif

.PHONY: all install clean

all: ${TARGETS}

snoopy: ${OBJS}

install: all
	install -d ${DESTDIR}/usr/local/sbin/
	install ${TARGETS} ${DESTDIR}/usr/local/sbin/

clean:
	$(RM) *.o ${TARGETS}
