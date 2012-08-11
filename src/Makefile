CFLAGS += -Wall -O2
TARGETS := snoopy
OBJS := $(patsubst %.c,%.o,$(wildcard *.c))

.PHONY: all install clean

all: ${TARGETS}

snoopy: ${OBJS}

install: all
	install -d ${DESTDIR}/usr/local/sbin/
	install ${TARGETS} ${DESTDIR}/usr/local/sbin/

clean:
	$(RM) *.o ${TARGETS}
