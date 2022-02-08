#ifndef PYROS_LIBPYROS_H
#define PYROS_LIBPYROS_H

#include "pyros.h"
#include <sqlite3.h>

#define TRUE (1 == 1)
#define FALSE !TRUE

#define STR_INDIR(x) #x
#define STR(x) STR_INDIR(x)

#define DBFILE "/pyros.db"

static const char HEX[] = "0123456789abcdef";

PyrosList *Get_Aliased_Ids(PyrosDB *pyrosDB, sqlite3_int64 *sTag);
PyrosList *Get_Children_Ids(PyrosDB *pyrosDB, sqlite3_int64 *sTag);
PyrosList *Get_Parent_Ids(PyrosDB *pyrosDB, sqlite3_int64 *sTag);

PyrosList *getTagIdByGlob(PyrosDB *pyrosDB, const char *sTag);

sqlite3_int64 *getTagId(PyrosDB *pyrosDB, const char *sTag);

#endif
