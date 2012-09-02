
CFLAGS += -Wall -O2 -fPIC -I.

.PHONY: all install clean

all: libnetmap.so

libnetmap.so: pcap.o nm_util.o
	$(CC) -o $@ -shared ${CFLAGS} $<

install: all

clean:
	$(RM) *.so *.o
