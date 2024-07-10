CC = gcc
CC_FLAGS = -I../include -I../libopcodes/include -g -O0

main.o: main.c
	$(CC) $(CC_FLAGS) -c main.c -o main.o

dumbugger.o: dumbugger.c
	$(CC) $(CC_FLAGS) -c dumbugger.c -o dumbugger.o

utils.o: utils.c
	$(CC) $(CC_FLAGS) -c utils.c -o utils.o

commands.o: commands.c
	$(CC) $(CC_FLAGS) -c commands.c -o commands.o

debug_syms.o: debug_syms.c
	$(CC) $(CC_FLAGS) -c debug_syms.c -o debug_syms.o

dumbugger: main.o dumbugger.o utils.o commands.o debug_syms.o
	$(CC) $(CC_FLAGS) main.o dumbugger.o utils.o commands.o debug_syms.o -o dumbugger -L../libdwarf/lib -ldwarf -lz -lzstd -L../libdwarf/lib -ldwarf -L../libopcodes/lib -lopcodes -lbfd -liberty -lsframe -lz

all: dumbugger

clean:
	rm -f *.o
	rm -f dumbugger

sample.o: sample.c
	$(CC) -c -g -O0 sample.c -o sample.o

sample: sample.o
	$(CC) sample.o -o sample
