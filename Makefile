WARNING=-Wall -Werror -Wextra -Wdeclaration-after-statement

BUILD_NAME = libpyros.so
LIBS=-lsqlite3 -lcrypto -lmagic

CFLAGS=$(WARNING) -std=c99 -fPIC -pedantic -g

LDFLAGS=$(LIBS) -shared

SRC=database.c sqlite.c pyroslist.c hash.c str.c tagging.c search.c files.c
OBJS=$(SRC:.c=.o)

LIBPATH = /usr/lib64
INCLUDEPATH = /usr/include

all: $(BUILD_NAME)

install: $(EXEC_NAME)
	cp pyros.h $(INCLUDEPATH)
	cp $(BUILD_NAME) $(LIBPATH)
	ldconfig -v -n $(LIBPATH) > /dev/null

%.o: %.c
	$(CC) -c -o $(@F) $(CFLAGS) $<

$(BUILD_NAME): $(OBJS)
	$(CC) -o $(BUILD_NAME) $(OBJS) $(LDFLAGS)

clean:
	rm $(OBJS)
	rm $(BUILD_NAME)

%: %.c $(BUILD_NAME) pyros.h
	$(CC) -o $(TESTDIR)$(@F) -g -lpyros -L. $(WARNN) $<
