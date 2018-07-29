CPP = g++ -g
CFLAGS = -std=gnu++11 -D_XOPEN_SOURCE=700 -Wall -Werror -pedantic

.PHONY: all clean

all: clean logauth logveri
clean:
	rm -f output.txt firstkey.dat logauth logauth.o logveri logveri.o

logveri: logveri.o
	$(CPP) -o $@ $^ -lcryptopp

logveri.o: logveri.cpp
	$(CPP) -c $(CFLAGS) $^

logauth: logauth.o logauth.h
	$(CPP) -o $@ $< -lcryptopp

logauth.o: logauth.cpp
	$(CPP) -c $(CFLAGS) $^
