-include config.mk

CC       ?= gcc
AR       ?= ar
RANLIB   ?= ranlib
INSTALL  ?= install

PREFIX   ?= /usr/local
DESTDIR  ?=

ARCH     ?= $(shell uname -m 2>/dev/null || echo unknown)
OS       ?= $(shell uname -s 2>/dev/null || echo unknown)

BUILD_SHARED ?= 0
DEBUG        ?= 0
SIMD         ?= 0

BUILD_DIR    := build
LIB_NAME     := gamepwnage

INC_DIR      := include/gamepwnage
CFLAGS       := -std=gnu11 -fPIC -I$(INC_DIR) -DGPWN_USING_BUILD_CONFIG
LDFLAGS      :=
LDLIBS       :=

SRCS := \
	src/dynlib.c \
	src/extras.c \
	src/inlinehook.c \
	src/mem.c \
	src/memscan.c \
	src/nop.c \
	src/plthook.c \
	src/proc.c \
	src/vftable.c

HEADERS := \
	$(INC_DIR)/config.h \
	$(INC_DIR)/dynlib.h \
	$(INC_DIR)/extras.h \
	$(INC_DIR)/inlinehook.h \
	$(INC_DIR)/mem.h \
	$(INC_DIR)/memscan.h \
	$(INC_DIR)/nop.h \
	$(INC_DIR)/plthook.h \
	$(INC_DIR)/proc.h \
	$(INC_DIR)/vftable.h

ifneq (,$(filter arm% aarch64,$(ARCH)))
SRCS += src/armhook.c
HEADERS += $(INC_DIR)/armhook.h
endif

ifneq (,$(filter x86_64 i386 i686 amd64,$(ARCH)))
SRCS += src/hook86.c
HEADERS += $(INC_DIR)/hook86.h
endif

OBJS := $(SRCS:src/%.c=$(BUILD_DIR)/%.o)

ifeq ($(DEBUG),1)
CFLAGS += -DGPWN_DEBUG -g -O0
else
CFLAGS += -O2
endif

ifeq ($(SIMD),1)
ifneq (,$(filter arm% armv7%,$(ARCH)))
CFLAGS += -DUSING_NEON -mfpu=neon -mfloat-abi=hard
endif
ifneq (,$(filter aarch64,$(ARCH)))
CFLAGS += -DUSING_NEON
endif
ifneq (,$(filter x86_64 i386 i686 amd64,$(ARCH)))
CFLAGS += -DUSING_AVX2 -mavx2
endif
endif

ifneq (,$(findstring android,$(CC)))
else ifeq ($(OS),Linux)
LDLIBS += -ldl
endif

ifeq ($(BUILD_SHARED),1)
LIB_FILE := $(BUILD_DIR)/lib$(LIB_NAME).so
CFLAGS += -DEXPORT_SYM
LDFLAGS += -shared -Wl,-soname,lib$(LIB_NAME).so
else
LIB_FILE := $(BUILD_DIR)/lib$(LIB_NAME).a
endif

.PHONY: all static shared clean install

all: $(LIB_FILE)

static:
	@$(MAKE) BUILD_SHARED=0 CC="$(CC)" AR="$(AR)" DEBUG="$(DEBUG)" SIMD="$(SIMD)" ARCH="$(ARCH)" all

shared:
	@$(MAKE) BUILD_SHARED=1 CC="$(CC)" AR="$(AR)" DEBUG="$(DEBUG)" SIMD="$(SIMD)" ARCH="$(ARCH)" all

$(BUILD_DIR)/%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/lib$(LIB_NAME).a: $(OBJS)
	$(AR) rcs $@ $^
	$(RANLIB) $@

$(BUILD_DIR)/lib$(LIB_NAME).so: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)

install: all
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/include/gamepwnage
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/lib
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/share/licenses/gamepwnage
	$(INSTALL) -m 644 $(HEADERS) $(DESTDIR)$(PREFIX)/include/gamepwnage/
	$(INSTALL) -m 644 $(LIB_FILE) $(DESTDIR)$(PREFIX)/lib/
	$(INSTALL) -m 644 LICENSE $(DESTDIR)$(PREFIX)/share/licenses/gamepwnage/
