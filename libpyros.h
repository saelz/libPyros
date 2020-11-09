#ifndef PYROS_LIBPYROS_H
#define PYROS_LIBPYROS_H

#include "pyros.h"
#include <sqlite3.h>


#define TRUE (1==1)
#define FALSE !TRUE

#define STR_INDIR(x) #x
#define STR(x) STR_INDIR(x)

#define DBFILE "/pyros.db"

static const char HEX[] = "0123456789abcdef";

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

enum Order_Type{
	OT_NONE,
	OT_EXT,
	OT_HASH,
	OT_MIME,
	OT_TIME,
	OT_SIZE,
	OT_RANDOM,
};

enum Tag_Ext{
	TAG_TYPE_ALIAS,
	TAG_TYPE_CHILD,
	TAG_TYPE_PARENT,
};

typedef struct PyrosMeta{
	int id;
	char *check1;
	char *check2;
} PyrosMeta;

typedef struct PyrosHook{
	void(*callback)();
	void(*freecallback)();
	char *str;
	char *str2;
} PyrosHook;

struct PyrosTagRaw{
	int isAlias;
	sqlite3_int64 id;
	size_t par;
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

/*
#define TAG_TYPE_ALIAS 0
#define TAG_TYPE_PARENT 1
#define TAG_TYPE_CHILD 2
*/

int getBiggestTag(char *tags[], int tagc);

PyrosList *Get_Aliased_Ids(PyrosDB *pyrosDB, sqlite3_int64 *sTag);

PyrosList *Get_Children_Ids(PyrosDB *pyrosDB, sqlite3_int64 *sTag);

PyrosList *Get_Parent_Ids(PyrosDB *pyrosDB, sqlite3_int64 *sTag);

PyrosList *getTagIdByGlob(PyrosDB *pyrosDB,const char *sTag);

sqlite3_int64 *getTagId(PyrosDB *pyrosDB,const char *sTag);

#endif
