CC=arm-linux-gnueabi-gcc
CFLAGS=-g -O2 -fPIC -c

hsalib=libHSAGuest.a
m2slib=libHSAGuestM2S.a
host=gcc
hostlib=libHSAHost.a

all:
	$(CC) src/cl.c $(CFLAGS) -Iinc -lm -DDEBUG_INFO -DARM
	ar -r $(hsalib) cl.o
	rm *.o
m2s:
	$(CC) src/cl.c $(CFLAGS) -Iinc -lm -DDEBUG_INFO -DARM -DUSE_M2S
	ar -r $(m2slib) cl.o
	rm *.o	
host:
	$(host) src/cl.c $(CFLAGS) -Iinc -lm -DHOST_DEBUG -DDEBUG_INFO
	ar -r $(hostlib) cl.o
	rm *.o
clean:
	rm *.a *.out
