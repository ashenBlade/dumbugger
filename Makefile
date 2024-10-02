.PHONY: all
all: libdwarf libopcodes dumbugger

.PHONY: libdwarf
libdwarf:
	make -C lib/libdwarf all

.PHONY: libopcodes
libopcodes:
	make -C lib/libopcodes all

.PHONY: dumbugger
dumbugger:
	make -C src all
