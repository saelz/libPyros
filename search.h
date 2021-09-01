#ifndef PYROS_SEARCH_H
#define PYROS_SEARCH_H
#include "pyros.h"

enum Order_Type{
	OT_NONE,
	OT_EXT,
	OT_HASH,
	OT_MIME,
	OT_TIME,
	OT_SIZE,
	OT_RANDOM,
};

enum Tag_Type{
	TT_NORMAL,
	TT_HASH,
	TT_EXT,
	TT_MIME,
	TT_IMPORTTIME,
	TT_TAGCOUNT,
	TT_IGNORE,
	TT_ALL
};

struct minmax{
	int min;
	int max;
};

union metaSearch {
	PyrosList *tags;
	char *text;
	struct minmax stat;
};

typedef struct {
	enum Tag_Type type;
	int filtered;
	union metaSearch meta;
} PrcsTags;

typedef struct {
	int reversed;
	enum Order_Type order;
	int page;
	int pageSize;
} querySettings;

#endif
