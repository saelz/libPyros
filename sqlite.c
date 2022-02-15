#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libpyros.h"
#include "pyros.h"
#include "search.h"
#include "sqlite.h"
#include "str.h"

static enum PYROS_ERROR setSQLError(PyrosDB *pyrosDB, int rc);

static char *STMT_COMMAND[STMT_COUNT] = {
    // STMT_BEGIN
    "BEGIN;",

    // STMT_END
    "COMMIT;",

    // STMT_ADD_FILE
    "INSERT OR IGNORE INTO hashes "
    "(hash,import_time,mimetype,ext,filesize) "
    "VALUES(?,?,?,?,?);",

    // STMT_ADD_TAG
    "INSERT OR IGNORE INTO tag(tag) VALUES(LOWER(?));",

    // STMT_ADD_TAG_TO_FILE
    "INSERT OR IGNORE INTO tags VALUES("
    "(SELECT id FROM hashes WHERE hash=TRIM(LOWER(?),'\n\t\r\f ')),"
    "(SELECT id FROM tag WHERE tag=LOWER(?)),?);",

    // STMT_ADD_RELATION
    "INSERT OR IGNORE INTO tagrelations "
    "VALUES((SELECT id FROM tag WHERE tag=?),"
    "(SELECT id FROM tag WHERE tag=?),?);",

    // STMT_QUERY_RELATION1
    "SELECT tag2 FROM tagrelations "
    "WHERE type=? AND tag=?;",
    // STMT_QUERY_RELATION2,
    "SELECT tag FROM tagrelations "
    "WHERE type=? AND tag2=?;",

    // STMT_QUERY_ALL_HASH
    "SELECT hash FROM hashes;",

    // STMT_QUERY_ALL_TAGS
    "SELECT tag FROM tag;",

    // STMT_QUERY_TAG_BY_HASH
    "SELECT tagid FROM tags LEFT JOIN hashes ON tags.hashid = hashes.id WHERE "
    "hash=? AND isantitag=0;",

    // STMT_QUERY_TAG_ID_BY_GLOB
    "SELECT id FROM tag WHERE tag GLOB LOWER(?);",

    // STMT_QUERY_TAG_ID
    "SELECT id FROM tag WHERE tag=LOWER(?);",

    // STMT_QUERY_FILE_FROM_HASH
    "SELECT hash,mimetype,ext,import_time,filesize "
    "FROM hashes WHERE hash=LOWER(?);",

    // STMT_QUERY_HASH_COUNT
    "SELECT COUNT(1) FROM hashes",

    // STMT_QUERY_FILE_COUNT
    "SELECT COUNT(1) FROM tag",

    // STMT_REMOVE_TAG_FROM_FILE
    "DELETE FROM tags WHERE hashid="
    "(SELECT id FROM hashes WHERE hash=?) AND "
    "tagid=(SELECT id FROM tag WHERE tag=LOWER(?));",

    // STMT_REMOVE_ALL_TAGS_FROM_FILE
    "DELETE FROM tags WHERE hashid="
    "(SELECT id FROM hashes WHERE hash=TRIM(LOWER(?),'\n\t\r\f '));",

    // STMT_MERGE_HASH
    "INSERT OR IGNORE INTO merged_hashes VALUES(?,?)",

    // STMT_UPDATE_MERGED
    "UPDATE merged_hashes SET masterfile_hash=? WHERE masterfile_hash=?",

    // STMT_QUERY_MERGE_MASTER
    "SELECT masterfile_hash FROM merged_hashes WHERE hash=?",

    // STMT_REMOVE_FILE
    "DELETE FROM hashes WHERE hash=LOWER(?);",

    // STMT_REMOVE_TAG
    "DELETE FROM tags WHERE hashid="
    "(SELECT id FROM hashes WHERE hash=?) AND "
    "tagid=(SELECT id FROM tag WHERE tag=LOWER(?));",

    // STMT_REMOVE_RELATION
    "DELETE FROM tagrelations WHERE tag="
    "(SELECT id FROM tag WHERE tag=?) AND tag2="
    "(SELECT id FROM tag WHERE tag=?);",

    // STMT_REMOVE_DEAD_TAG
    "DELETE FROM tag WHERE"
    " id NOT IN (SELECT tag FROM tagrelations)"
    " AND id NOT IN (SELECT tag2 FROM tagrelations)"
    " AND id NOT IN (SELECT tagid FROM tags)",

    // STMT_VACUUM
    "VACUUM"

    // STMT_ROLLBACK
    "ROLLBACK"};

static enum PYROS_ERROR
setSQLError(PyrosDB *pyrosDB, int rc) {
	assert(rc != SQLITE_MISUSE);

	if (rc == SQLITE_OK)
		return PYROS_OK;
	else if (rc == SQLITE_NOMEM)
		return setError(pyrosDB, PYROS_ERROR_OOM, "Out of memory");

	return setError(pyrosDB, PYROS_ERROR_DATABASE,
	                sqlite3_errmsg(pyrosDB->database));
}

enum PYROS_ERROR
sqlInitDB(PyrosDB *pyrosDB, int isNew) {
	sqlite3 *pyrosdb;
	char dbfile[strlen(pyrosDB->path) + strlen(DBFILE) + 1];
	int rc;

	strcpy(dbfile, pyrosDB->path);
	strcat(dbfile, DBFILE);

	if ((access(dbfile, F_OK) != -1 && !isNew) || isNew) {
		if ((rc = sqlite3_open(dbfile, &pyrosdb)) == SQLITE_OK) {
			pyrosDB->database = pyrosdb;
			return PYROS_OK;
		} else {
			pyrosDB->database = NULL;
			sqlite3_close(pyrosdb);
			return setSQLError(pyrosDB, rc);
		}
	}

	pyrosDB->database = NULL;

	if (isNew)
		return setError(
		    pyrosDB, PYROS_ERROR_DATABASE,
		    "Can't create new database, database already exists");
	else
		return setError(pyrosDB, PYROS_ERROR_DATABASE,
		                "Can't open database, database does not exist");
}

void
sqlDeleteDBFile(PyrosDB *pyrosDB) {
	char dbfile[strlen(pyrosDB->path) + strlen(DBFILE) + 1];
	strcpy(dbfile, pyrosDB->path);
	strcat(dbfile, DBFILE);
	remove(dbfile);
}

enum PYROS_ERROR
sqlCloseDB(PyrosDB *pyrosDB) {
	int rc, i;
	if (pyrosDB->database == NULL)
		return PYROS_OK;

	for (i = 0; i < STMT_COUNT; i++) {
		if (pyrosDB->commands[i] != NULL) {
			sqlite3_finalize(pyrosDB->commands[i]);
			pyrosDB->commands[i] = NULL;
		}
	}

	rc = sqlite3_close(pyrosDB->database);
	if (rc != SQLITE_OK)
		return setSQLError(pyrosDB, rc);

	pyrosDB->database = NULL;
	return PYROS_OK;
}

enum PYROS_ERROR
sqlCreateTables(PyrosDB *pyrosDB) {
	sqlite3_stmt *create_DB;
	int ret;
	size_t i;
	char *tablelist[] = {
	    /* master table */
	    /* stores settings */
	    "CREATE TABLE IF NOT EXISTS master(id TEXT PRIMARY KEY,"
	    "val INT NOT NULL)WITHOUT ROWID;",

	    /* hashes table */
	    /* stores hash,hash metadata and id */
	    "CREATE TABLE IF NOT EXISTS hashes(id INTEGER PRIMARY KEY,"
	    "hash TEXT UNIQUE COLLATE NOCASE,"
	    "import_time INT,"
	    "mimetype TEXT,ext TEXT COLLATE NOCASE,filesize INT);",

	    /* tag table */
	    /* stores tag and id */
	    "CREATE TABLE IF NOT EXISTS tag(id INTEGER PRIMARY KEY,"
	    "tag TEXT COLLATE NOCASE UNIQUE,"
	    "aliases INT,parents INT,children INT);",

	    /* tags table */
	    /* stores relations between tags and hashes */
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

	    /* tagrelations table */
	    /* stores relations between tags */
	    "CREATE TABLE IF NOT EXISTS tagrelations(tag INT NOT "
	    "NULL, tag2 INT NOT NULL,"
	    " type INT NOT NULL,PRIMARY KEY(tag,tag2))"
	    "WITHOUT ROWID;",

	    /* merged_hashes table */
	    /* stores hashes for files marked as duplicates/merged */
	    "CREATE TABLE IF NOT EXISTS merged_hashes("
	    " masterfile_hash TEXT NOT NULL,"
	    " hash TEXT PRIMARY KEY,"
	    " CONSTRAINT fk_masterhash"
	    "  FOREIGN KEY (masterfile_hash) REFERENCES hashes(hash)"
	    "  ON DELETE CASCADE)"
	    "WITHOUT ROWID;",
	};

	for (i = 0; i < LENGTH(tablelist); i++) {
		ret = sqlPrepareStmt(pyrosDB, tablelist[i], &create_DB);
		if (ret != PYROS_OK)
			goto error;

		ret = sqlStmtGetResults(pyrosDB, create_DB);
		if (ret != PYROS_OK)
			goto error;

		sqlite3_finalize(create_DB);
	}

	ret = sqlPrepareStmt(
	    pyrosDB, "INSERT OR IGNORE INTO master VALUES(?,?);", &create_DB);
	if (ret != PYROS_OK)
		goto error;

	ret = sqlBind(pyrosDB, create_DB, TRUE, SQL_CHAR, "version", SQL_INT,
	              PYROS_VERSION);
	if (ret != PYROS_OK)
		goto error;

	ret = sqlBind(pyrosDB, create_DB, TRUE, SQL_CHAR, "hashtype", SQL_INT,
	              pyrosDB->hashtype);
	if (ret != PYROS_OK)
		goto error;

	ret = sqlBind(pyrosDB, create_DB, TRUE, SQL_CHAR, "ext case-sensitive",
	              SQL_INT, FALSE);
	if (ret != PYROS_OK)
		goto error;

	ret = sqlBind(pyrosDB, create_DB, TRUE, SQL_CHAR, "tag case-sensitive",
	              SQL_INT, FALSE);
	if (ret != PYROS_OK)
		goto error;

	ret = sqlBind(pyrosDB, create_DB, TRUE, SQL_CHAR, "preserve-ext",
	              SQL_INT, TRUE);
	if (ret != PYROS_OK)
		goto error;

	sqlite3_finalize(create_DB);

	return sqlStmtGetResults(pyrosDB, sqlGetStmt(pyrosDB, STMT_BEGIN), 0);

error:
	sqlite3_finalize(create_DB);
	return pyrosDB->error;
}

enum PYROS_ERROR
sqlPrepareStmt(PyrosDB *pyrosDB, char *cmd, sqlite3_stmt **stmt) {
	int rc;

	rc = sqlite3_prepare_v2(pyrosDB->database, cmd, -1, stmt, NULL);
	if (rc != SQLITE_OK) {
		sqlite3_finalize(*stmt);
		return setSQLError(pyrosDB, rc);
	}

	return PYROS_OK;
}

enum PYROS_ERROR
sqlBind(PyrosDB *pyrosDB, sqlite3_stmt *stmt, int execute, ...) {
	va_list list;
	int i;
	int count;
	int arg_type;
	char *strarg;
	int iarg;
	sqlite3_int64 i64arg;
	sqlite3_int64 *i64parg;

	if (stmt == NULL && pyrosDB->error != PYROS_OK)
		return pyrosDB->error;

	assert(stmt != NULL);

	va_start(list, execute);
	count = sqlite3_bind_parameter_count(stmt);
	for (i = 1; i <= count; i++) {
		arg_type = va_arg(list, int);
		switch (arg_type) {
		case SQL_CHAR:
			strarg = va_arg(list, char *);
			sqlite3_bind_text(stmt, i, strarg, -1, NULL);
			break;
		case SQL_INT:
			iarg = va_arg(list, int);
			sqlite3_bind_int(stmt, i, iarg);
			break;
		case SQL_INT64:
			i64arg = va_arg(list, sqlite3_int64);
			sqlite3_bind_int64(stmt, i, i64arg);
			break;
		case SQL_INT64P:
			i64parg = va_arg(list, sqlite3_int64 *);
			sqlite3_bind_int64(stmt, i, *i64parg);
			break;
		}
	}
	va_end(list);

	if (execute)
		return sqlStmtGetResults(pyrosDB, stmt, 0);

	return PYROS_OK;
}

void
sqlBindList(sqlite3_stmt *stmt, PyrosList *pList, enum SQL_BIND_TYPE type) {
	size_t i;

	assert(stmt != NULL);

	for (i = 0; i < pList->length; i++) {
		if (type == SQL_CHAR)
			sqlite3_bind_text(stmt, i + 1, pList->list[i], -1,
			                  NULL);
		else if (type == SQL_INT64P)
			sqlite3_bind_int64(
			    stmt, i + 1,
			    *(const sqlite3_int64 *)pList->list[i]);
	}
}

#include <stdio.h>

void
sqlBindTags(sqlite3_stmt *stmt, PrcsTags *prcsTags, size_t tagc,
            querySettings qSet) {
	size_t i, j;
	size_t pos = 1;
	int group_count = 0;

	assert(stmt != NULL);

	for (i = 0; i < tagc; i++) {
		switch (prcsTags[i].type) {
		case TT_NORMAL:
			group_count++;
			for (j = 0; j < prcsTags[i].meta.tags->length; j++) {
				sqlite3_bind_int64(
				    stmt, pos,
				    *(const sqlite3_int64 *)prcsTags[i]
				         .meta.tags->list[j]);
				pos++;
			}
			break;
		case TT_HASH:
		case TT_MIME:
		case TT_EXT:
			group_count++;
			sqlite3_bind_text(stmt, pos, prcsTags[i].meta.text, -1,
			                  NULL);
			pos++;
			break;
		case TT_TAGCOUNT:
			if (prcsTags[i].meta.stat.min ==
			    prcsTags[i].meta.stat.max) {
				sqlite3_bind_int(stmt, pos,
				                 prcsTags[i].meta.stat.min);
				pos++;
				break;
			}
			if (prcsTags[i].meta.stat.min >= 0) {
				sqlite3_bind_int(stmt, pos,
				                 prcsTags[i].meta.stat.min);
				pos++;
			}
			if (prcsTags[i].meta.stat.max >= 0) {
				sqlite3_bind_int(stmt, pos,
				                 prcsTags[i].meta.stat.max);
				pos++;
			}
			break;
		case TT_IGNORE:
			break;
		default:
			sqlite3_bind_text(stmt, pos, prcsTags[i].meta.text, -1,
			                  NULL);
			pos++;
			break;
		}
	}

	if (qSet.pageSize > 0) {
		sqlite3_bind_int(stmt, pos, qSet.pageSize);
		pos++;
		if (qSet.page >= 0)
			sqlite3_bind_int(stmt, pos, qSet.page * qSet.pageSize);
	}
}

enum PYROS_ERROR
sqlStmtGetResults(PyrosDB *pyrosDB, sqlite3_stmt *stmt, ...) {
	va_list list;
	size_t i;
	int type;
	size_t args;

	int rc;
	char **strptr;
	int64_t *i64ptr;

	if (stmt == NULL && pyrosDB->error != PYROS_OK)
		return pyrosDB->error;
	assert(stmt != NULL);

	rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW) {
		va_start(list, stmt);
		args = sqlite3_column_count(stmt);
		for (i = 0; i < args; i++) {
			type = sqlite3_column_type(stmt, i);
			switch (type) {
			case SQLITE_TEXT:
				strptr = va_arg(list, char **);
				*strptr = duplicate_str(
				    (const char *)sqlite3_column_text(stmt, i));
				if (*strptr == NULL)
					goto error_oom;

				break;
			case SQLITE_INTEGER:
				i64ptr = va_arg(list, int64_t *);
				*i64ptr = sqlite3_column_int64(stmt, i);
				break;
			}
		}
		va_end(list);
	} else if (rc != SQLITE_DONE && rc != SQLITE_OK) {
		sqlite3_reset(stmt);
		return setSQLError(pyrosDB, rc);
	}

	sqlite3_reset(stmt);
	return SQLITE_OK;

error_oom:
	sqlite3_reset(stmt);
	return setError(pyrosDB, PYROS_ERROR_OOM, "Out of Memory");
}

PyrosList *
sqlStmtGetAllFiles(PyrosDB *pyrosDB, sqlite3_stmt *stmt) {
	PyrosList *files = NULL;
	PyrosFile *pFile;
	int rc;

	if (stmt == NULL && pyrosDB->error != PYROS_OK)
		return NULL;
	assert(stmt != NULL);

	files = Pyros_Create_List(1);
	if (files == NULL)
		goto error_oom;

	rc = sqlite3_step(stmt);
	while (rc == SQLITE_ROW) {
		pFile = malloc(sizeof(*pFile));
		if (pFile == NULL)
			goto error_oom;

		pFile->hash =
		    duplicate_str((const char *)sqlite3_column_text(stmt, 0));
		pFile->mime =
		    duplicate_str((const char *)sqlite3_column_text(stmt, 1));
		pFile->ext =
		    duplicate_str((const char *)sqlite3_column_text(stmt, 2));
		pFile->import_time = sqlite3_column_int64(stmt, 3);
		pFile->file_size = sqlite3_column_int64(stmt, 4);

		if (pFile->hash == NULL || pFile->mime == NULL ||
		    pFile->ext == NULL) {
			free(pFile->hash);
			free(pFile->mime);
			free(pFile->ext);
			goto error_oom;
		}

		pFile->path = getFilePath(pyrosDB, pFile->hash, pFile->ext);
		if (pFile->path == NULL) {
			Pyros_Free_File(pFile);
			goto error_oom;
		}

		Pyros_List_Append(files, pFile);
		rc = sqlite3_step(stmt);
	}

	sqlite3_reset(stmt);

	if (rc != SQLITE_DONE && rc != SQLITE_OK) {
		Pyros_List_Free(files, (Pyros_Free_Callback)Pyros_Free_File);
		setSQLError(pyrosDB, rc);
		return NULL;
	}

	return files;

error_oom:
	sqlite3_reset(stmt);
	setError(pyrosDB, PYROS_ERROR_OOM, "Out of Memory");
	Pyros_List_Free(files, (Pyros_Free_Callback)Pyros_Free_File);
	return NULL;
}

PyrosList *
sqlStmtGetAll(PyrosDB *pyrosDB, sqlite3_stmt *stmt) {
	PyrosList *items;
	int rc;
	sqlite3_int64 *intptr;
	char *newstr;
	int type;

	if (stmt == NULL && pyrosDB->error != PYROS_OK)
		return NULL;

	assert(stmt != NULL);

	items = Pyros_Create_List(1);

	if (items == NULL)
		goto error_oom;

	rc = sqlite3_step(stmt);
	type = sqlite3_column_type(stmt, 0);

	while (rc == SQLITE_ROW) {
		if (type == SQLITE_TEXT) {
			newstr = duplicate_str(
			    (const char *)sqlite3_column_text(stmt, 0));
			if (newstr == NULL)
				goto error_oom;

			Pyros_List_Append(items, newstr);
		} else if (type == SQLITE_INTEGER) {
			intptr = malloc(sizeof(*intptr));
			if (intptr == NULL)
				goto error_oom;

			*intptr = sqlite3_column_int64(stmt, 0);
			Pyros_List_Append(items, intptr);
		}
		rc = sqlite3_step(stmt);
	}
	sqlite3_reset(stmt);

	if (rc != SQLITE_DONE && rc != SQLITE_OK) {
		Pyros_List_Free(items, (Pyros_Free_Callback)Pyros_Free_File);
		setSQLError(pyrosDB, rc);
		return NULL;
	}
	return items;

error_oom:
	sqlite3_reset(stmt);
	setError(pyrosDB, PYROS_ERROR_OOM, "Out of Memory");
	Pyros_List_Free(items, free);
	return NULL;
}

enum PYROS_ERROR
sqlStartTransaction(PyrosDB *pyrosDB) {
	int ret;
	if (!pyrosDB->inTransaction) {
		ret = sqlStmtGetResults(pyrosDB,
		                        sqlGetStmt(pyrosDB, STMT_BEGIN), 0);
		if (ret != PYROS_OK)
			return ret;
		pyrosDB->inTransaction = TRUE;
	}
	return PYROS_OK;
}

sqlite3_stmt *
sqlGetStmt(PyrosDB *pyrosDB, enum COMMAND_STMTS stmt) {
	int ret;
	sqlite3_stmt **stmts = pyrosDB->commands;

	if (stmts[stmt] == NULL) {
		ret = sqlPrepareStmt(pyrosDB, STMT_COMMAND[stmt], &stmts[stmt]);
		if (ret != PYROS_OK)
			return NULL;
	}

	return stmts[stmt];
}
