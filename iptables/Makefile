XTBL := $(shell pkg-config --variable=xtlibdir xtables)

CFLAGS = -fPIC -I../kernel -g -Wall

all:  libipt_TCPBREAK.so
install:  libipt_TCPBREAK.so
	if [ -d $(DESTDIR)$(XTBL) ]; then install libipt_TCPBREAK.so $(DESTDIR)$(XTBL); \
		else echo "No pkg-config --variable=xtlibdir xtables"; fi

lib%.so: lib%.o
	$(CC) -shared -o $@ $^;
lib%.o: lib%.c ../kernel/ipt_TCPBREAK.h
	$(CC) ${CFLAGS} -D_INIT=lib$*_init -c -o $@ $<;
clean:
	rm -rf libipt_TCPBREAK.so

