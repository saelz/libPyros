#ifndef PYROS_LIBPYROS_H
#define PYROS_LIBPYROS_H

#include "pyros.h"
#include <stdint.h>

#define TRUE 1
#define FALSE 0

#define STR_INDIR(x) #x
#define STR(x) STR_INDIR(x)

#define DBFILE "/pyros.db"

#define LENGTH(array) (sizeof(array) / sizeof(*(array)))

#define RETURN_IF_ERR(pyrosDB)                                                 \
	if (pyrosDB->error != PYROS_OK)                                        \
		return pyrosDB->error;                                         \
	if (pyrosDB->database == NULL)                                         \
		return setError(pyrosDB, PYROS_ERROR_INVALID_ARGUMENT,         \
		                "No database currently open");

#define RETURN_IF_ERR_WRET(pyrosDB, ret)                                       \
	if (pyrosDB->error != PYROS_OK)                                        \
		return ret;                                                    \
	if (pyrosDB->database == NULL) {                                       \
		setError(pyrosDB, PYROS_ERROR_INVALID_ARGUMENT,                \
		         "No database currently open");                        \
		return ret;                                                    \
	}

typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;

struct PyrosDB {
	sqlite3 *database;
	char *path;
	sqlite3_stmt **commands;
	PyrosList *hook;
	int64_t is_ext_case_sensitive; /* UNUSED */
	int64_t is_tag_case_sensitive; /* UNUSED */
	int64_t preserve_ext;          /* UNUSED */
	int64_t inTransaction;
	int64_t version;
	int64_t hashtype;
	enum PYROS_ERROR error;
	char *error_msg;
	size_t error_msg_len;
};

static const char HEX[] = "0123456789abcdef";

PyrosList *Get_Aliased_Ids(PyrosDB *pyrosDB, int64_t *sTag);
PyrosList *Get_Children_Ids(PyrosDB *pyrosDB, int64_t *sTag);
PyrosList *Get_Parent_Ids(PyrosDB *pyrosDB, int64_t *sTag);

enum PYROS_ERROR mergeRelatedTagIds(PyrosDB *pyrosDB, PyrosList *tagids,
                                    enum PYROS_TAG_RELATION_FLAGS type);
PyrosList *getTagIdByGlob(PyrosDB *pyrosDB, const char *sTag);

int64_t *getTagId(PyrosDB *pyrosDB, const char *sTag);

int setError(PyrosDB *pyrosDB, enum PYROS_ERROR error, const char *message);
#endif
