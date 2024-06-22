GDB_VERSION=14.2
TAR_FILE_NAME=gdb-$(GDB_VERSION).tar.gz
SOURCES_DIR=gdb-src
INSTALL_DIR=$(shell pwd)

$(TAR_FILE_NAME):
	wget http://ftp.gnu.org/gnu/gdb/gdb-$(GDB_VERSION).tar.gz -O $(TAR_FILE_NAME)

extract: $(TAR_FILE_NAME)
	mkdir -p $(SOURCES_DIR)
	tar -xvzf $(TAR_FILE_NAME) -C $(SOURCES_DIR)

configure: extract
	cd $(SOURCES_DIR)/gdb-$(GDB_VERSION) && ./configure --prefix=$(INSTALL_DIR)

build: configure
	cd $(SOURCES_DIR)/gdb-$(GDB_VERSION) && make
	cd $(SOURCES_DIR)/gdb-$(GDB_VERSION) && make install
	cp $(SOURCES_DIR)/gdb-$(GDB_VERSION)/opcodes/config.h $(SOURCES_DIR)/include
	
all: build
