CC = gcc
CC_FLAGS = -Iinclude -Ilibopcodes/include -g -O0

main.o: dumbugger/main.c
	$(CC) $(CC_FLAGS) -c dumbugger/main.c -o dumbugger/main.o

dumbugger.o: dumbugger/dumbugger.c
	$(CC) $(CC_FLAGS) -c dumbugger/dumbugger.c -o dumbugger/dumbugger.o

utils.o: dumbugger/utils.c
	$(CC) $(CC_FLAGS) -c dumbugger/utils.c -o dumbugger/utils.o

commands.o: dumbugger/commands.c
	$(CC) $(CC_FLAGS) -c dumbugger/commands.c -o dumbugger/commands.o

dumbugger: main.o dumbugger.o utils.o commands.o
	$(CC) $(CC_FLAGS) dumbugger/main.o dumbugger/dumbugger.o dumbugger/utils.o dumbugger/commands.o -o dumbugger/dumbugger -Llibopcodes/lib -lopcodes -lbfd -liberty -lsframe -lz

all: dumbugger

clean:
	rm -f dumbugger/*.o
	rm -f dumbugger/dumbugger
