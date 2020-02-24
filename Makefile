H=/home/mdw/t/kmip
I=-I $H/include
L=-L$H/lib -lkmip -lssl -lcrypto
X=-Wl,-rpath,$H/lib
CFLAGS=$I -g
CXXFLAGS=$I -g -std=c++11
all: kmip1 kmip2 kmip4
kmip1: kmip1.o
	$(CC) $(CFLAGS) $X -o kmip1 kmip1.o $L
kmip2: kmip2.o str.o
	$(CC) $(CFLAGS) $X -o kmip2 kmip2.o str.o $L
kmip2.o str.o: str.h
kmip4: kmip4.o kmip4lib.o
	$(CXX) $(CFLAGS) $X -o kmip4 kmip4.o kmip4lib.o $L
kmip4.o kmip4lib.o: kmip4lib.h
clean:
	rm -f str.o kmip1.o kmip2.o kmip1 kmip2
