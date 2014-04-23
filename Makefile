CFLAGS = -Wall -Wextra -g -pthread -DTCPR
LDFLAGS = -pthread
LIBS = /usr/local/ssl/lib/libssl.a /usr/local/ssl/lib/libcrypto.a -ldl

.PHONY: all
all: dc pmuplayer pmudumper pmucat

.PHONY: clean
clean:
	rm -f *.o dc pmuplayer pmudumper pmucat

dc: dc.o log.o $(LIBS)

pmuplayer: pmuplayer.o c37.o $(LIBS)

pmuplayer.o: pmuplayer.c c37.h $(LIBS)

pmudumper: pmudumper.o c37.o $(LIBS)

pmudumper.o: pmudumper.c c37.h $(LIBS)

pmucat: pmucat.c

c37.o: c37.c c37.h
