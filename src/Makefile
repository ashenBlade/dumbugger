CC = gcc
CC_FLAGS = -Iinclude -Ilibopcodes/include -g -O0

main.o: dumbugger/main.c
	$(CC) $(CC_FLAGS) -c dumbugger/main.c -o dumbugger/main.o

dumbugger.o: dumbugger/dumbugger.c
	$(CC) $(CC_FLAGS) -c dumbugger/dumbugger.c -o dumbugger/dumbugger.o

dumbugger: main.o dumbugger.o
	$(CC) dumbugger/main.o dumbugger/dumbugger.o -o dumbugger/dumbugger -Llibopcodes/lib -lopcodes -lbfd -liberty -lsframe -lz

all: dumbugger

clean:
	rm -f dumbugger/*.o
	rm -f dumbugger/dumbugger
