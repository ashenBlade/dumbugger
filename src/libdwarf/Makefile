LIB_VERSION=0.9.2
TAR_FILE_NAME=libdwarf-$(LIB_VERSION).tar.xz
SOURCES_DIR=libdwarf-$(LIB_VERSION)
INSTALL_DIR=$(shell pwd)

$(TAR_FILE_NAME):
	wget https://github.com/davea42/libdwarf-code/releases/download/v$(LIB_VERSION)/libdwarf-$(LIB_VERSION).tar.xz -O $(TAR_FILE_NAME)

$(SOURCES_DIR)/extracted: $(TAR_FILE_NAME)
	mkdir -p $(SOURCES_DIR)
	tar -xvf $(TAR_FILE_NAME) $(SOURCES_DIR)
	echo '1' >$(SOURCES_DIR)/extracted

.PHONY: extract
extract: $(SOURCES_DIR)/extracted

$(SOURCES_DIR)/Makefile: extract
	cd $(SOURCES_DIR) && ./configure --prefix=$(INSTALL_DIR)
	touch $(SOURCES_DIR)/Makefile

.PHONY: configure
configure: $(SOURCES_DIR)/Makefile

.PHONY: install
install: configure
	cd $(SOURCES_DIR) && make install

.PHONY: all
all: install



