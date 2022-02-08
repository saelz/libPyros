#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "libpyros.h"
#include "pyros.h"
#include "sqlite.h"

typedef struct PyrosHook {
	void (*callback)();
	void (*freecallback)();
	char *str;
	char *str2;
} PyrosHook;

void
addHook(PyrosDB *pyrosDB, void (*callback)(), char *str, char *str2,
        void (*freecallback)()) {
	PyrosHook *hook;

	hook = malloc(sizeof(*hook));
	hook->callback = callback;
	hook->freecallback = freecallback;
	hook->str = str;
	hook->str2 = str2;
	Pyros_List_Append(pyrosDB->hook, hook);
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

static PyrosDB *
Init_Pyros_DB(const char *path, int isNew) {
	PyrosDB *pyrosDB = NULL;
	sqlite3_stmt **stmts = NULL;
	int i;

	if ((pyrosDB = malloc(sizeof(*pyrosDB))) == NULL)
		goto error;

	if ((stmts = malloc(sizeof(*stmts) * STMT_COUNT)) == NULL)
		goto error;

	if ((pyrosDB->path =
	         malloc(sizeof(*pyrosDB->path) * (strlen(path) + 1))) == NULL)
		goto error;

	if ((pyrosDB->database = initDB(path, isNew)) == NULL) {
		free(pyrosDB->path);
		goto error;
	}

	if ((pyrosDB->hook = Pyros_Create_List(1, sizeof(PyrosHook *))) ==
	    NULL) {
		free(pyrosDB->path);
		goto error;
	}

	strcpy(pyrosDB->path, path);

	pyrosDB->inTransaction = FALSE;

	for (i = 0; i < STMT_COUNT; i++)
		stmts[i] = NULL;

	pyrosDB->commands = stmts;

	return pyrosDB;

error:
	free(pyrosDB);
	free(stmts);
	fprintf(stderr, "Error allocating memory");
	return NULL;
}

PyrosDB *
Pyros_Open_Database(const char *path) {
	PyrosDB *pyrosDB;
	sqlite3_stmt *Query_Master;

	pyrosDB = Init_Pyros_DB(path, FALSE);
	if (pyrosDB == NULL)
		return NULL;

	sqlPrepareStmt(pyrosDB, "SELECT val FROM master WHERE id=?;",
	               &Query_Master);

	sqlBind(Query_Master, FALSE, 1, SQL_CHAR, "hashtype");
	sqlStmtGetResults(Query_Master, 1, SQL_INT, &pyrosDB->hashtype);

	sqlBind(Query_Master, FALSE, 1, SQL_CHAR, "ext case-sensitive");
	sqlStmtGetResults(Query_Master, 1, SQL_INT,
	                  &pyrosDB->is_ext_case_sensitive);

	sqlBind(Query_Master, FALSE, 1, SQL_CHAR, "tag case-sensitive");
	sqlStmtGetResults(Query_Master, 1, SQL_INT,
	                  &pyrosDB->is_tag_case_sensitive);

	sqlBind(Query_Master, FALSE, 1, SQL_CHAR, "version");
	sqlStmtGetResults(Query_Master, 1, SQL_INT, &pyrosDB->version);

	sqlBind(Query_Master, FALSE, 1, SQL_CHAR, "preserve-ext");
	sqlStmtGetResults(Query_Master, 1, SQL_INT, &pyrosDB->preserve_ext);

	sqlite3_finalize(Query_Master);
	return pyrosDB;
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

void
Pyros_Close_Database(PyrosDB *pyrosDB) {
	sqlite3_stmt **stmts;
	int i;

	if (pyrosDB == NULL)
		return;

	stmts = pyrosDB->commands;
	for (i = 0; i < STMT_COUNT; i++)
		if (stmts[i] != NULL)
			sqlite3_finalize(stmts[i]);

	Pyros_List_Free(pyrosDB->hook, (Pyros_Free_Callback)freeHook);
	closeDB(pyrosDB->database);
	free(pyrosDB->commands);
	free(pyrosDB->path);
	free(pyrosDB);
}

int
Pyros_Commit(PyrosDB *pyrosDB) {
	PyrosHook *hook;
	int ret = PYROS_OK;
	size_t i;

	if (pyrosDB->inTransaction) {

		ret = sqlStmtGetResults(sqlGetStmt(pyrosDB, STMT_END), 0);
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

PyrosDB *
Pyros_Create_Database(char *path, enum PYROS_HASHTYPE hashtype) {
	size_t i, j;
	size_t pathlen = strlen(path);
	char dbpath[pathlen + strlen(DBFILE)];

	PyrosDB *pyrosDB;
	sqlite3_stmt *create_DB;

	/* makes entire path */
	for (i = 1; i < pathlen; i++) {
		if (path[i] == '/') {
			path[i] = '\0';
			mkdir(path, 0777);
			path[i] = '/';
		}
	}
	/* make path */
	mkdir(path, 0777);

	/* create path/db folder */
	strcpy(dbpath, path);
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

	/* create sqlite database */
	pyrosDB = Init_Pyros_DB(path, TRUE);
	if (pyrosDB == NULL)
		return NULL;

	pyrosDB->hashtype = hashtype;
	pyrosDB->is_ext_case_sensitive = 1;
	pyrosDB->is_tag_case_sensitive = 1;
	pyrosDB->version = PYROS_VERSION;
	pyrosDB->inTransaction = TRUE;
	pyrosDB->preserve_ext = TRUE;
	sqlStmtGetResults(sqlGetStmt(pyrosDB, STMT_BEGIN), 0);

	/* master table */
	/* stores settings */
	sqlPrepareStmt(pyrosDB,
	               "CREATE TABLE IF NOT EXISTS master(id TEXT PRIMARY KEY,"
	               "val INT NOT NULL)WITHOUT ROWID;",
	               &create_DB);
	sqlStmtGetResults(create_DB, 0);
	sqlite3_finalize(create_DB);

	/* hashes table */
	/* stores hash,hash metadata and id */
	sqlPrepareStmt(
	    pyrosDB,
	    "CREATE TABLE IF NOT EXISTS hashes(id INTEGER PRIMARY KEY,"
	    "hash TEXT UNIQUE COLLATE NOCASE,"
	    "import_time INT,"
	    "mimetype TEXT,ext TEXT COLLATE NOCASE,filesize INT);",
	    &create_DB);
	sqlStmtGetResults(create_DB, 0);
	sqlite3_finalize(create_DB);

	/* tag table */
	/* stores tag and id */
	sqlPrepareStmt(pyrosDB,
	               "CREATE TABLE IF NOT EXISTS tag(id INTEGER PRIMARY KEY,"
	               "tag TEXT COLLATE NOCASE UNIQUE,"
	               "aliases INT,parents INT,children INT);",
	               &create_DB);
	sqlStmtGetResults(create_DB, 0);
	sqlite3_finalize(create_DB);

	/* tags table */
	/* stores relations between tags and hashes */
	sqlPrepareStmt(pyrosDB,
	               "CREATE TABLE IF NOT EXISTS tags(hashid INT NOT NULL,"
	               " tagid INT NOT NULL,isantitag INT NOT NULL,"
	               " PRIMARY KEY(hashid,tagid,isantitag),"
	               " CONSTRAINT fk_hashes"
	               "  FOREIGN KEY (hashid) REFERENCES hashes(id)"
	               "  ON DELETE CASCADE,"
	               " CONSTRAINT fk_tag"
	               "  FOREIGN KEY (tagid) REFERENCES  tag(id)"
	               "  ON DELETE CASCADE)"
	               "WITHOUT ROWID;",
	               &create_DB);
	sqlStmtGetResults(create_DB, 0);
	sqlite3_finalize(create_DB);

	/* tagrelations table */
	/* stores relations between tags */
	sqlPrepareStmt(pyrosDB,
	               "CREATE TABLE IF NOT EXISTS tagrelations(tag INT NOT "
	               "NULL, tag2 INT NOT NULL,"
	               " type INT NOT NULL,PRIMARY KEY(tag,tag2))"
	               "WITHOUT ROWID;",
	               &create_DB);
	sqlStmtGetResults(create_DB, 0);
	sqlite3_finalize(create_DB);

	/* merged_hashes table */
	/* stores hashes for files marked as duplicates/merged */
	sqlPrepareStmt(pyrosDB,
	               "CREATE TABLE IF NOT EXISTS merged_hashes("
	               " masterfile_hash TEXT NOT NULL,"
	               " hash TEXT PRIMARY KEY,"
	               " CONSTRAINT fk_masterhash"
	               "  FOREIGN KEY (masterfile_hash) REFERENCES hashes(hash)"
	               "  ON DELETE CASCADE)"
	               "WITHOUT ROWID;",
	               &create_DB);
	sqlStmtGetResults(create_DB, 0);
	sqlite3_finalize(create_DB);

	sqlPrepareStmt(pyrosDB, "INSERT OR IGNORE INTO master VALUES(?,?);",
	               &create_DB);

	sqlBind(create_DB, TRUE, 2, SQL_CHAR, "version", SQL_INT,
	        PYROS_VERSION);
	sqlBind(create_DB, TRUE, 2, SQL_CHAR, "hashtype", SQL_INT, hashtype);
	sqlBind(create_DB, TRUE, 2, SQL_CHAR, "ext case-sensitive", SQL_INT,
	        FALSE);
	sqlBind(create_DB, TRUE, 2, SQL_CHAR, "tag case-sensitive", SQL_INT,
	        FALSE);
	sqlBind(create_DB, TRUE, 2, SQL_CHAR, "preserve-ext", SQL_INT, TRUE);

	sqlite3_finalize(create_DB);
	return pyrosDB;
}

void
Pyros_Vacuum_Database(PyrosDB *pyrosDB) {
	sqlStmtGetResults(sqlGetStmt(pyrosDB, STMT_VACUUM), 0);
}
