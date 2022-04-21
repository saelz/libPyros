WARNING +=-Wall -Werror -Wextra -Wdeclaration-after-statement -Wnull-dereference -Wmissing-prototypes -Wpointer-arith -Wcast-qual

BUILD_NAME = libpyros.so
PKG_CONFIG= libmagic libcrypto sqlite3
LIBS =`pkg-config --libs $(PKG_CONFIG)`

CFLAGS = $(WARNING) -std=c99 -fPIC -pedantic -g `pkg-config --cflags $(PKG_CONFIG)`

LDFLAGS = $(LIBS) -shared

SRC = database.c sqlite.c pyroslist.c hash.c str.c tagging.c search.c files.c
OBJS = $(SRC:.c=.o)

PREFIX ?=/usr
LIBPATH = $(PREFIX)/lib
INCLUDEPATH = $(PREFIX)/include

all: $(BUILD_NAME)

install: $(BUILD_NAME)
	install -c pyros.h $(INCLUDEPATH)
	install -c $(BUILD_NAME) $(LIBPATH)

%.o: %.c *.h
	$(CC) -c -o $(@F) $(CFLAGS) $<

$(BUILD_NAME): $(OBJS)
	$(CC) -o $(BUILD_NAME) $(OBJS) $(LDFLAGS)

clean:
	rm $(OBJS)
	rm $(BUILD_NAME)
