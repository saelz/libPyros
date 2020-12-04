#ifndef PYROS_SQL_H
#define PYROS_SQL_H

#include "search.h"

#include <sqlite3.h>

enum SQL_GET_TYPE{
	SQL_CHAR,
	SQL_INT,
	SQL_INT64,
	SQL_INT64P,
};

enum COMMAND_STMTS{
	STMT_BEGIN = 0,
	STMT_END,
	STMT_ADD_FILE,
	STMT_ADD_TAG,
	STMT_ADD_TAG_TO_FILE,
	STMT_ADD_RELATION,
	STMT_QUERY_RELATION1,
	STMT_QUERY_RELATION2,
	STMT_QUERY_HASH_BY_TAG,
	STMT_QUERY_ALL_HASH,
	STMT_QUERY_ALL_TAGS,
	STMT_QUERY_TAG_BY_HASH,
	STMT_QUERY_TAG_ID_BY_GLOB,
	STMT_QUERY_TAG_ID,
	STMT_QUERY_FILE_FROM_HASH,
	STMT_QUERY_HASH_COUNT,
	STMT_QUERY_FILE_COUNT,
	STMT_REMOVE_TAG_FROM_FILE,
	STMT_REMOVE_TAGS_FROM_FILE,
	STMT_MERGE_HASH,
	STMT_QUERY_TAG_COUNT,
	STMT_REMOVE_FILE,
	STMT_REMOVE_TAG,
	STMT_REMOVE_RELATION,
	STMT_REMOVE_DEAD_TAG,
	STMT_COUNT,
};

sqlite3 *initDB(const char *database, int isNew);
void closeDB(sqlite3 *pyrosdb);

//PyrosList *sqlGetAll(PyrosDB *pyrosDB, char *sqlcommand);
//PyrosList *sqlGetAllFiles(PyrosDB *pyrosDB, char *sqlcommand);

//int sqlGet(sqlite3 *pyrosdb, char *sqlcommand,int args, ...);

//int sqlexec(char* cmd,PyrosDB *pyrosDB);

int sqlPrepareStmt(PyrosDB *pyrosDB,char *cmd,sqlite3_stmt **stmt);

int sqlBind(sqlite3_stmt *stmt,int execute, size_t count, ...);
int sqlBindList(sqlite3_stmt *stmt,PyrosList *pList,enum SQL_GET_TYPE type);
int sqlBindTags(sqlite3_stmt *stmt,PrcsTags *prcsTags, size_t tagc,
				querySettings qSet);

int sqlStmtGet(sqlite3_stmt *stmt, size_t args, ...);
PyrosList *sqlStmtGetAllFiles(PyrosDB *pyrosDB, sqlite3_stmt *stmt);
PyrosList *sqlStmtGetAll(sqlite3_stmt *stmt,enum SQL_GET_TYPE);

void sqlStartTransaction(PyrosDB *pyrosDB);
void sqlCompileStmt(PyrosDB *db, enum COMMAND_STMTS stmt,char *cmd);
#endif
