all: wghub-server wghub-client libnss_wghub.so

wghub-server: wghub-server.o libwghub.a
	g++ -std=c++20 -o $@ $^ -lcrypto -liniparser4

libnss_wghub.so: nss_wghub.cpp
	g++ -std=c++20 -o $@ $^ -fPIC -shared -Wl,-soname,libnss_wghub.so.2

wghub-client: wghub-client.o libwghub.a
	g++ -std=c++20 -o $@ $^ -lcrypto -lcurl

wghub.so: *.cpp
	g++ -std=c++20 -g -shared -fPIC -o $@ $^


libwghub.a: wghub.o
	ar r $@ $^

.cpp.o:
	g++ -std=c++20 -Wall -c -o $@ $<

install: all
	cp -a wghub-server wghub-client /usr/local/bin/
	cp -a libwghub.a /usr/local/lib/
	cp -a wghub.h /usr/local/include/

clean:
	rm -f wghub-server whhub-client *.a *.o *.so privkey.txt


