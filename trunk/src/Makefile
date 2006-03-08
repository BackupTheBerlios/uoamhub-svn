# uoamhub Makefile
# (c) 2004-2005 Max Kellermann <max@duempel.org>
# $Id$

# auto-detect a C compiler
CC := $(shell which gcc-4.0 gcc-3.4 gcc-3.3 gcc cc |grep -v '^no' |grep -v 'not found' |head -1 )

# change the comments to enable the non-debugging version
CFLAGS = -g -O0
#CFLAGS = -Os -DNDEBUG=1

# uncomment this to enable the micro edition (16 kB binary size stripped)
#FEATURE_CFLAGS += -DDISABLE_DAEMON_CODE=1 -DDISABLE_LOGGING=1

WARNING_CFLAGS += -W -Wall -D_REENTRANT -std=gnu99 -Wmissing-prototypes -Wwrite-strings -Wcast-qual -Wfloat-equal -Wshadow -Wpointer-arith -Wbad-function-cast -Wsign-compare -Waggregate-return -Wmissing-declarations -Wmissing-noreturn -Wmissing-format-attribute -Wpacked -Wredundant-decls -Wnested-externs -Winline -Wdisabled-optimization -Wno-long-long -Wstrict-prototypes -Wundef -pedantic-errors -Werror

LDFLAGS =

ifeq ($(CC),)
$(error No C compiler detected; you could try "$(MAKE) CC=/usr/bin/my_c_compiler")
endif

ifeq ($(shell uname -s),SunOS)
LDFLAGS += -lsocket -lnsl
endif

ifeq ($(shell test -c /dev/urandom && echo yes),yes)
FEATURE_CFLAGS += -DHAVE_DEV_RANDOM -DRANDOM_DEVICE=\"/dev/urandom\"
else
ifeq ($(shell test -c /dev/random && echo yes),yes)
FEATURE_CFLAGS += -DHAVE_DEV_RANDOM -DRANDOM_DEVICE=\"/dev/random\"
endif
endif

all: uoamhub

clean:
	rm -f uoamhub

uoamhub: uoamhub.c
	$(CC) $(CFLAGS) $(WARNING_CFLAGS) $(FEATURE_CFLAGS) $(LDFLAGS) -o $@ $^

strip: uoamhub
	strip --strip-all uoamhub
