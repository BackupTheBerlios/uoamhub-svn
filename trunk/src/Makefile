CC := $(shell for i in gcc-3.4 gcc-3.3 gcc cc; do which $$i && break; done )
#CFLAGS = -g -O0
CFLAGS = -Os -DDISABLE_DAEMON_CODE=1
CFLAGS += -W -Wall -D_REENTRANT -std=gnu99 -Wmissing-prototypes -Wwrite-strings -Wcast-qual -Wfloat-equal -Wshadow -Wpointer-arith -Wbad-function-cast -Wsign-compare -Waggregate-return -Wmissing-declarations -Wmissing-noreturn -Wmissing-format-attribute -Wpacked -Wredundant-decls -Wnested-externs -Winline -Wdisabled-optimization -Wno-long-long -Wstrict-prototypes -Wundef -pedantic-errors -Werror

all: uoamhub

clean:
	rm -f uoamhub

uoamhub: uoamhub.c
	$(CC) $(CFLAGS) -o $@ $^

strip: uoamhub
	strip --strip-all uoamhub
