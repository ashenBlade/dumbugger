CC := gcc
CFLAGS := -Iinclude -I../lib/libopcodes/include -I../lib/libdwarf/include -g -O0 -D_GNU_SOURCE -fPIE

OBJS = main.

main.o: main.c
	$(CC) $(CFLAGS) -c main.c -o main.o

dumbugger.o: dumbugger.c
	$(CC) $(CFLAGS) -c dumbugger.c -o dumbugger.o

utils.o: utils.c
	$(CC) $(CFLAGS) -c utils.c -o utils.o

commands.o: commands.c
	$(CC) $(CFLAGS) -c commands.c -o commands.o

debug_syms.o: debug_syms.c
	$(CC) $(CFLAGS) -c debug_syms.c -o debug_syms.o

dumbugger: main.o dumbugger.o utils.o commands.o debug_syms.o
	$(CC) $(CFLAGS) main.o dumbugger.o utils.o commands.o debug_syms.o -o dumbugger   \
			-L../lib/libdwarf/lib -ldwarf -lz -lzstd 								  \
			-L../lib/libdwarf/lib -ldwarf 											  \
			-L../lib/libopcodes/lib -lopcodes -lbfd -liberty -lsframe -lz				

all: dumbugger

clean:
	rm -f *.o
	rm -f dumbugger

sample.o: sample.c
	$(CC) -c -g -O0 sample.c -o sample.o

sample: sample.o
	$(CC) sample.o -o sample
