CFLAGS := -Wall -Werror -Iinc -O2 -g

INSTALL ?= install
DESTDIR = 
PREFIX ?= /usr/local

all: libebpf-offload.a

libebpf-offload.a: ebpf-offload.o
	ar rc $@ $^

install: libebpf-offload.a 
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/lib
	$(INSTALL) -m 644 libebpf-offload.a $(DESTDIR)$(PREFIX)/lib
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/include
	$(INSTALL) -m 644 ebpf-offload.h $(DESTDIR)$(PREFIX)/include

clean:
	rm -f libebpf-offload.a *.o
