# uoamhub Makefile
# (c) 2004-2006 Max Kellermann <max@duempel.org>
# $Id: Makefile 140 2006-03-08 14:36:50Z make $

CC := gcc

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

all: src/uoamhub

clean:
	rm -f src/uoamhub

src/uoamhub: src/uoamhub.c
	$(CC) $(CFLAGS) $(WARNING_CFLAGS) $(FEATURE_CFLAGS) $(LDFLAGS) -o $@ $^

strip: src/uoamhub
	strip --strip-all src/uoamhub
