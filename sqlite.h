#ifndef PYROS_SQL_H
#define PYROS_SQL_H

#include "search.h"

#include <sqlite3.h>

enum SQL_BIND_TYPE {
	SQL_CHAR,
	SQL_INT,
	SQL_INT64,
	SQL_INT64P,
};

enum COMMAND_STMTS {
	STMT_BEGIN = 0,
	STMT_END,
	STMT_ADD_FILE,
	STMT_ADD_TAG,
	STMT_ADD_TAG_TO_FILE,
	STMT_ADD_RELATION,
	STMT_QUERY_RELATION1,
	STMT_QUERY_RELATION2,
	STMT_QUERY_ALL_HASH,
	STMT_QUERY_ALL_TAGS,
	STMT_QUERY_TAG_BY_HASH,
	STMT_QUERY_TAG_ID_BY_GLOB,
	STMT_QUERY_TAG_ID,
	STMT_QUERY_FILE_FROM_HASH,
	STMT_QUERY_HASH_COUNT,
	STMT_QUERY_FILE_COUNT,
	STMT_REMOVE_TAG_FROM_FILE,
	STMT_REMOVE_ALL_TAGS_FROM_FILE,
	STMT_MERGE_HASH,
	STMT_UPDATE_MERGED,
	STMT_QUERY_MERGE_MASTER,
	STMT_REMOVE_FILE,
	STMT_REMOVE_TAG,
	STMT_REMOVE_RELATION,
	STMT_REMOVE_DEAD_TAG,
	STMT_VACUUM,
	STMT_COUNT,
};

enum PYROS_ERROR sqlInitDB(PyrosDB *pyrosDB, int isNew);
enum PYROS_ERROR sqlCloseDB(PyrosDB *pyrosDB);
void sqlDeleteDBFile(PyrosDB *pyrosDB);
enum PYROS_ERROR sqlCreateTables(PyrosDB *pyrosDB);

enum PYROS_ERROR sqlPrepareStmt(PyrosDB *pyrosDB, char *cmd,
                                sqlite3_stmt **stmt);

enum PYROS_ERROR sqlBind(PyrosDB *pyrosDB, sqlite3_stmt *stmt, int execute,
                         ...);
void sqlBindList(sqlite3_stmt *stmt, PyrosList *pList, enum SQL_BIND_TYPE type);
void sqlBindTags(sqlite3_stmt *stmt, PrcsTags *prcsTags, size_t tagc,
                 querySettings qSet);

enum PYROS_ERROR sqlStmtGetResults(PyrosDB *pyrosDB, sqlite3_stmt *stmt, ...);
PyrosList *sqlStmtGetAllFiles(PyrosDB *pyrosDB, sqlite3_stmt *stmt);
PyrosList *sqlStmtGetAll(PyrosDB *pyrosDB, sqlite3_stmt *stmt);

enum PYROS_ERROR sqlStartTransaction(PyrosDB *pyrosDB);
sqlite3_stmt *sqlGetStmt(PyrosDB *db, enum COMMAND_STMTS stmt);
#endif
