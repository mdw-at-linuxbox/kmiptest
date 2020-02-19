H=/home/mdw/t/kmip
I=-I $H/include
L=-L$H/lib -lkmip -lssl -lcrypto
X=-Wl,-rpath,$H/lib
CFLAGS=$I -g
all: kmip1 kmip2
kmip1: kmip1.o
	$(CC) $(CFLAGS) $X -o kmip1 kmip1.o $L
kmip2: kmip2.o str.o
	$(CC) $(CFLAGS) $X -o kmip2 kmip2.o str.o $L
kmip2.o str.o: str.h
clean:
	rm -f str.o kmip1.o kmip2.o kmip1 kmip2
