#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "database.h"
#include "libpyros.h"
#include "pyros.h"
#include "sqlite.h"
#include "str.h"

typedef struct PyrosHook {
	void (*callback)();
	void (*freecallback)();
	char *str;
	char *str2;
} PyrosHook;

enum PYROS_ERROR
addHook(PyrosDB *pyrosDB, void (*callback)(), char *str, char *str2,
        void (*freecallback)()) {
	PyrosHook *hook;

	hook = malloc(sizeof(*hook));
	if (hook == NULL)
		return setError(pyrosDB, PYROS_ERROR_OOM, "Out of memory");

	hook->callback = callback;
	hook->freecallback = freecallback;
	hook->str = str;
	hook->str2 = str2;
	Pyros_List_Append(pyrosDB->hook, hook);

	return PYROS_OK;
}

static void
freeHook(PyrosHook *hook) {
	void (*freecallback)();
	if (hook->freecallback != NULL) {
		freecallback = hook->freecallback;
		if (hook->str != NULL)
			freecallback(hook->str);
		if (hook->str2 != NULL)
			freecallback(hook->str2);
	}
	free(hook);
}

PyrosDB *
Pyros_Alloc_Database(const char *path) {
	PyrosDB *pyrosDB = NULL;
	sqlite3_stmt **stmts = NULL;
	PyrosList *hooks = NULL;
	int i;

	assert(path != NULL);

	if ((pyrosDB = malloc(sizeof(*pyrosDB))) == NULL)
		goto error;

	if ((stmts = malloc(sizeof(*stmts) * STMT_COUNT)) == NULL)
		goto error;

	if ((hooks = Pyros_Create_List(1)) == NULL)
		goto error;

	if ((pyrosDB->path = duplicate_str(path)) == NULL)
		goto error;

	strcpy(pyrosDB->path, path);

	pyrosDB->inTransaction = FALSE;

	for (i = 0; i < STMT_COUNT; i++)
		stmts[i] = NULL;

	pyrosDB->hook = hooks;
	pyrosDB->commands = stmts;
	pyrosDB->database = NULL;
	pyrosDB->error = PYROS_OK;
	pyrosDB->error_msg = NULL;
	pyrosDB->error_msg_len = 0;

	return pyrosDB;

error:
	free(pyrosDB);
	free(stmts);
	Pyros_List_Free(hooks, NULL);
	return NULL;
}

enum PYROS_ERROR
Pyros_Open_Database(PyrosDB *pyrosDB) {
	int ret;
	sqlite3_stmt *Query_Master = NULL;

	assert(pyrosDB != NULL);

	if (pyrosDB->database != NULL)
		return PYROS_OK;

	ret = sqlInitDB(pyrosDB, FALSE);
	if (ret != PYROS_OK)
		return ret;

	ret = sqlPrepareStmt(pyrosDB, "SELECT val FROM master WHERE id=?;",
	                     &Query_Master);
	if (ret != PYROS_OK)
		return ret;

	sqlBind(pyrosDB, Query_Master, FALSE, SQL_CHAR, "hashtype");
	ret = sqlStmtGetResults(pyrosDB, Query_Master, &pyrosDB->hashtype);
	if (ret != PYROS_OK)
		goto error;

	sqlBind(pyrosDB, Query_Master, FALSE, SQL_CHAR, "ext case-sensitive");
	ret = sqlStmtGetResults(pyrosDB, Query_Master,
	                        &pyrosDB->is_ext_case_sensitive);
	if (ret != PYROS_OK)
		goto error;

	sqlBind(pyrosDB, Query_Master, FALSE, SQL_CHAR, "tag case-sensitive");
	ret = sqlStmtGetResults(pyrosDB, Query_Master,
	                        &pyrosDB->is_tag_case_sensitive);
	if (ret != PYROS_OK)
		goto error;

	sqlBind(pyrosDB, Query_Master, FALSE, SQL_CHAR, "version");
	ret = sqlStmtGetResults(pyrosDB, Query_Master, &pyrosDB->version);
	if (ret != PYROS_OK)
		goto error;

	sqlBind(pyrosDB, Query_Master, FALSE, SQL_CHAR, "preserve-ext");
	ret = sqlStmtGetResults(pyrosDB, Query_Master, &pyrosDB->preserve_ext);
	if (ret != PYROS_OK)
		goto error;

	sqlite3_finalize(Query_Master);

	return PYROS_OK;

error:
	sqlite3_finalize(Query_Master);
	return ret;
}

int
Pyros_Database_Exists(const char *path) {
	char dbfile[strlen(path) + strlen(DBFILE) + 1];

	strcpy(dbfile, path);
	strcat(dbfile, DBFILE);
	if (access(dbfile, F_OK) != -1) {
		return TRUE;
	}

	return FALSE;
}

enum PYROS_ERROR
Pyros_Close_Database(PyrosDB *pyrosDB) {
	if (pyrosDB == NULL)
		return PYROS_OK;

	if (sqlCloseDB(pyrosDB) != PYROS_OK)
		return pyrosDB->error;

	Pyros_List_Free(pyrosDB->hook, (Pyros_Free_Callback)freeHook);

	free(pyrosDB->commands);
	free(pyrosDB->error_msg);
	free(pyrosDB->path);
	free(pyrosDB);

	return PYROS_OK;
}

enum PYROS_ERROR
Pyros_Commit(PyrosDB *pyrosDB) {
	const PyrosHook *hook;
	int ret = PYROS_OK;
	size_t i;

	assert(pyrosDB != NULL);

	RETURN_IF_ERR(pyrosDB);

	if (pyrosDB->inTransaction) {

		ret = sqlStmtGetResults(pyrosDB, sqlGetStmt(pyrosDB, STMT_END),
		                        0);
		pyrosDB->inTransaction = FALSE;

		if (ret == PYROS_OK) {
			for (i = 0; i < pyrosDB->hook->length; i++) {
				hook = pyrosDB->hook->list[i];
				(*hook->callback)(hook->str, hook->str2);
			}

			Pyros_List_Clear(pyrosDB->hook,
			                 (Pyros_Free_Callback)freeHook);
		}
	}
	return ret;
}
enum PYROS_ERROR
Pyros_Rollback(PyrosDB *pyrosDB) {
	int ret = PYROS_OK;

	assert(pyrosDB != NULL);

	if (pyrosDB->inTransaction) {

		ret = sqlStmtGetResults(pyrosDB,
		                        sqlGetStmt(pyrosDB, STMT_ROLLBACK), 0);
		pyrosDB->inTransaction = FALSE;
		Pyros_List_Clear(pyrosDB->hook, (Pyros_Free_Callback)freeHook);
	}

	return ret;
}

enum PYROS_ERROR
Pyros_Create_Database(PyrosDB *pyrosDB, enum PYROS_HASHTYPE hashtype) {
	size_t i, j;
	size_t pathlen;
	char *dbpath;
	int ret;

	assert(pyrosDB != NULL);

	if (pyrosDB->database != NULL)
		return PYROS_OK;

	pathlen = strlen(pyrosDB->path);
	dbpath = malloc(pathlen + strlen(DBFILE));
	if (dbpath == NULL)
		return setError(pyrosDB, PYROS_ERROR_OOM, "Out of memory");

	/* makes entire path */
	for (i = 1; i < pathlen; i++) {
		if (pyrosDB->path[i] == '/') {
			pyrosDB->path[i] = '\0';
			mkdir(pyrosDB->path, 0777);
			pyrosDB->path[i] = '/';
		}
	}
	/* make path */
	mkdir(pyrosDB->path, 0777);

	/* create path/db folder */
	strcpy(dbpath, pyrosDB->path);
	strcat(dbpath, "/db/");
	mkdir(dbpath, 0777);

	/* create path/db/xx folder */
	dbpath[pathlen + 6] = '\0';
	for (i = 0; i < 16; i++) {
		for (j = 0; j < 16; j++) {
			dbpath[pathlen + 4] = HEX[i];
			dbpath[pathlen + 5] = HEX[j];
			mkdir(dbpath, 0777);
		}
	}
	free(dbpath);

	/* create sqlite database */
	ret = sqlInitDB(pyrosDB, TRUE);
	if (ret != PYROS_OK)
		return ret;

	pyrosDB->hashtype = hashtype;
	pyrosDB->is_ext_case_sensitive = 1;
	pyrosDB->is_tag_case_sensitive = 1;
	pyrosDB->version = PYROS_VERSION;
	pyrosDB->inTransaction = TRUE;
	pyrosDB->preserve_ext = TRUE;
	if (sqlCreateTables(pyrosDB) != PYROS_OK)
		goto error;

	return PYROS_OK;

error:
	sqlDeleteDBFile(pyrosDB);
	return pyrosDB->error;
}

enum PYROS_ERROR
Pyros_Vacuum_Database(PyrosDB *pyrosDB) {
	assert(pyrosDB != NULL);

	RETURN_IF_ERR(pyrosDB);

	return sqlStmtGetResults(pyrosDB, sqlGetStmt(pyrosDB, STMT_VACUUM), 0);
}

const char *
Pyros_Get_Database_Path(PyrosDB *pyrosDB) {
	assert(pyrosDB != NULL);

	RETURN_IF_ERR_WRET(pyrosDB, NULL);

	return pyrosDB->path;
}

enum PYROS_HASHTYPE
Pyros_Get_Hash_Type(PyrosDB *pyrosDB) {
	assert(pyrosDB != NULL);

	RETURN_IF_ERR_WRET(pyrosDB, PYROS_UNKOWNHASH);

	return pyrosDB->hashtype;
}

enum PYROS_ERROR
Pyros_Get_Error_Type(PyrosDB *pyrosDB) {
	assert(pyrosDB != NULL);

	return pyrosDB->error;
}

const char *
Pyros_Get_Error_Message(PyrosDB *pyrosDB) {
	assert(pyrosDB != NULL);

	if (pyrosDB->error_msg == NULL) {
		if (pyrosDB->error == PYROS_ERROR_OOM)
			return "Out of memory";
		else
			return "";
	}

	return pyrosDB->error_msg;
}

void
Pyros_Clear_Error(PyrosDB *pyrosDB) {
	assert(pyrosDB != NULL);

	if (pyrosDB->error == PYROS_OK)
		return;

	pyrosDB->error = PYROS_OK;
	setError(pyrosDB, PYROS_OK, "No error has occurred");
}

int
setError(PyrosDB *pyrosDB, enum PYROS_ERROR error, const char *message) {
	size_t msg_len = strlen(message);
	pyrosDB->error = error;

	if (msg_len > pyrosDB->error_msg_len) {
		pyrosDB->error_msg_len = msg_len;
		pyrosDB->error_msg =
		    realloc(pyrosDB->error_msg, pyrosDB->error_msg_len + 1);
	}

	strcpy(pyrosDB->error_msg, message);

	if (pyrosDB->error_msg == NULL) {
		pyrosDB->error_msg_len = 0;
		pyrosDB->error = PYROS_ERROR_OOM;
	}

	return pyrosDB->error;
}
