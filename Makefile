PREFIX ?= /usr/local

all: wghub-server wghub-client libnss_wghub.so

wghub-server: wghub-server.o libwghub.a
	g++ -std=c++20 -o $@ $^ -lcrypto -liniparser4

libnss_wghub.so: nss_wghub.cpp
	g++ -std=c++20 -o $@ $^ -fPIC -shared -Wl,-soname,libnss_wghub.so.2

wghub-client: wghub-client.o libwghub.a
	g++ -std=c++20 -o $@ $^ -lcrypto -lcurl

wghub.so: *.cpp
	g++ -std=c++20 -g -shared -fPIC -o $@ $^

wghub-test: wghub.cpp
	g++ -std=c++20 -g -DWGHUB_TEST -o $@ $^ -lcrypto

libwghub.a: wghub.o
	ar r $@ $^

.cpp.o:
	g++ -std=c++20 -Wall -c -o $@ $<

install: all
	install -Dm755 wghub-server $(DESTDIR)$(PREFIX)/bin/wghub-server
	install -Dm755 wghub-client $(DESTDIR)$(PREFIX)/bin/wghub-client
	install -Dm644 libwghub.a $(DESTDIR)$(PREFIX)/lib/libwghub.a
	install -Dm644 wghub.h $(DESTDIR)$(PREFIX)/include/wghub.h

clean:
	rm -f wghub-server whhub-client *.a *.o *.so privkey.txt


