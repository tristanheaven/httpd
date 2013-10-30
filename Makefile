CC ?= gcc
CFLAGS ?= -O2 -pipe -ggdb
CFLAGS += -std=c99 -Wall -Wextra
LIBS = -lpthread

useless-httpd: useless-httpd.c
	$(CC) $(CFLAGS) $(LDFLAGS) useless-httpd.c -o $@ $(LIBS)

clean:
	rm -f useless-httpd
