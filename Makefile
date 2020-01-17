H=/home/mdw/t/kmip
I=-I $H/include
L=-L$H/lib -lkmip -lssl -lcrypto
X=-Wl,-rpath,$H/lib
CFLAGS=$I -g
kmip1: kmip1.o
	$(CC) $(CFLAGS) $X -o kmip1 kmip1.o $L
