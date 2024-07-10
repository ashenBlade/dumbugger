.PHONY: libdwarf
libdwarf:
	make -C src/libdwarf all

.PHONY: libopcodes
libopcodes:
	make -C src/libopcodes all

.PHONY: dumbugger
dumbugger:
	make -C src/dumbugger all

.PHONY: all
all: libdwarf libopcodes dumbugger