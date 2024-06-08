CC = gcc
CC_FLAGS = -Iinclude -g -O0

main.o: bin/main.c
	$(CC) $(CC_FLAGS) -c bin/main.c -o bin/main.o 

dumbugger.o: bin/dumbugger.c
	$(CC) $(CC_FLAGS) -c bin/dumbugger.c -o bin/dumbugger.o

dumbugger: main.o dumbugger.o
	$(CC) bin/main.o bin/dumbugger.o -o bin/dumbugger

all: dumbugger

clean:
	rm -f bin/*.o
	rm -f bin/dumbugger
