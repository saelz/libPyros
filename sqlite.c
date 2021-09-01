#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "pyros.h"
#include "str.h"
#include "sqlite.h"
#include "libpyros.h"

sqlite3*
initDB(const char *database,int isNew){
	sqlite3 *pyrosdb;
	char dbfile[strlen(database)+strlen(DBFILE)+1];

	strcpy(dbfile,database);
	strcat(dbfile,DBFILE);

	if((access(dbfile, F_OK ) != -1 && !isNew) || isNew) {
		if (sqlite3_open(dbfile,&pyrosdb)) {
			sqlite3_close(pyrosdb);
			return NULL;
		} else {
			return pyrosdb;
		}
	}
	return NULL;
}

void
closeDB(sqlite3 *pyrosdb){
	if (sqlite3_close(pyrosdb) == SQLITE_BUSY)
		fprintf(stderr,"Pyros: database busy!\n");
}

int
sqlPrepareStmt(PyrosDB *pyrosDB,char *cmd,sqlite3_stmt **stmt){
	int rc;

	rc = sqlite3_prepare_v2(pyrosDB->database,cmd,-1, stmt, NULL);
	if (rc != SQLITE_OK) {
		fprintf(stderr,"Pyros: SQLite ERROR %d in \"%s\"\n",rc,cmd);
		sqlite3_finalize(*stmt);
		return PYROS_DB_ERR;
	}

	return PYROS_OK;
}

int
sqlBind(sqlite3_stmt *stmt,int execute, size_t count, ...){
	va_list list;
	size_t i;

	int arg_type;
	char *strarg;
	int iarg;
	sqlite3_int64 i64arg;
	sqlite3_int64 *i64parg;

	count *= 2;
	va_start(list,count);
	for (i = 1; i < count/2+1;i++){
		arg_type = va_arg(list,int);
		if (arg_type == SQL_CHAR){
			strarg = va_arg(list,char*);
			sqlite3_bind_text(stmt,i,strarg,-1,NULL);
		} else if (arg_type == SQL_INT){
			iarg = va_arg(list,int);
			sqlite3_bind_int(stmt,i,iarg);
		} else if (arg_type == SQL_INT64){
			i64arg = va_arg(list,sqlite3_int64);
			sqlite3_bind_int64(stmt,i,i64arg);
		} else if (arg_type == SQL_INT64P){
			i64parg = va_arg(list,sqlite3_int64*);
			sqlite3_bind_int64(stmt,i,*i64parg);
		}
	}
	va_end(list);
	if (execute){
		sqlStmtGet(stmt,0);
	}
	return PYROS_OK;

}

int
sqlBindList(sqlite3_stmt *stmt,PyrosList *pList,enum SQL_GET_TYPE type){
	size_t i;
	for (i = 0; i < pList->length;i++){
		if (type == SQL_CHAR)
			sqlite3_bind_text(stmt,i+1,pList->list[i],-1,NULL);
		else if (type == SQL_INT64P)
			sqlite3_bind_int64(stmt,i+1,*(sqlite3_int64*)pList->list[i]);
	}
	return PYROS_OK;
}

int
sqlBindTags(sqlite3_stmt *stmt,PrcsTags *prcsTags, size_t tagc, querySettings qSet){
	size_t i,j;
	size_t pos = 1;

	for (i = 0; i < tagc;i++){
		switch (prcsTags[i].type) {
		case TT_NORMAL:
			for (j = 0; j < prcsTags[i].meta.tags->length;j++){
				sqlite3_bind_int64(stmt,pos,
								   *(sqlite3_int64*)prcsTags[i].meta.tags->list[j]);
				pos++;
			}
			break;
		case TT_TAGCOUNT:
			if (prcsTags[i].meta.stat.min >= 0){
				sqlite3_bind_int(stmt,pos,prcsTags[i].meta.stat.min);
				pos++;
			}
			if (prcsTags[i].meta.stat.max >= 0){
				sqlite3_bind_int(stmt,pos,prcsTags[i].meta.stat.max);
				pos++;
			}
			break;
		case TT_IGNORE:
			break;
		default:
			sqlite3_bind_text(stmt,pos,prcsTags[i].meta.text,-1,NULL);
			pos++;
			break;
		}
	}
	if (qSet.pageSize > 0){
		sqlite3_bind_int(stmt,pos,qSet.pageSize);
		pos++;
		if (qSet.page >= 0)
			sqlite3_bind_int(stmt,pos,qSet.page*qSet.pageSize);
	}

	return PYROS_OK;
}

int
sqlStmtGet(sqlite3_stmt *stmt,size_t args, ...){
	va_list list;
	size_t i;
	int arg_type;

	int rc;
	char **strptr;
	int *iptr;
	sqlite3_int64 **i64ptrptr;
	sqlite3_int64 *i64ptr;
	char *str;

	rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW){
		args *= 2;
		va_start(list,args);
		for (i = 0; i < args/2;i++){
			arg_type = va_arg(list,int);
			if (arg_type == SQL_CHAR){
				strptr = va_arg(list,char**);

				str = (char*)sqlite3_column_text(stmt, i);
				*strptr = malloc(sizeof(**strptr)*(strlen(str)+1));
				if (*strptr == NULL)
					exit(1);

				strcpy(*strptr,str);
			} else if (arg_type == SQL_INT){
				iptr = va_arg(list,int*);
				*iptr = sqlite3_column_int(stmt,i);
			} else if (arg_type == SQL_INT64){
				i64ptr  = va_arg(list,sqlite3_int64*);
				*i64ptr = sqlite3_column_int64(stmt,i);
			} else if (arg_type == SQL_INT64P){
				i64ptrptr = va_arg(list,sqlite3_int64**);
				*i64ptrptr = malloc(sizeof(**i64ptrptr));
				if (*i64ptrptr == NULL)
					exit(1);
				**i64ptrptr = sqlite3_column_int64(stmt,i);
			}

		}
		va_end(list);
	} else if (rc != SQLITE_DONE && rc != SQLITE_OK){
		printf("SQLCODE:%d\n",rc);
		return PYROS_DB_ERR;
	}
	sqlite3_reset(stmt);
	return PYROS_OK;
}

PyrosList *
sqlStmtGetAllFiles(PyrosDB *pyrosDB, sqlite3_stmt *stmt){
	PyrosList *files;
	PyrosFile *pFile;
	const char *hash;
	const char *mime;
	const char *ext;

	int rc;


	rc = sqlite3_step(stmt);

	files = Pyros_Create_List(1,sizeof(char*));
	while (rc == SQLITE_ROW) {
		pFile = malloc(sizeof(*pFile));
		if (pFile == NULL)
			exit(1);

		hash = (char*)sqlite3_column_text(stmt, 0);
		mime = (char*)sqlite3_column_text(stmt, 1);
		ext  = (char*)sqlite3_column_text(stmt, 2);
		pFile->import_time = sqlite3_column_int64(stmt, 3);
		pFile->file_size = sqlite3_column_int64(stmt, 4);

		pFile->hash = malloc(sizeof(*pFile->hash)*(strlen(hash)+1));
		pFile->mime = malloc(sizeof(*pFile->mime)*(strlen(mime)+1));
		pFile->ext  = malloc(sizeof(*pFile->ext )*(strlen(ext )+1));

		if (pFile->hash == NULL ||
			pFile->mime == NULL ||
			pFile->ext == NULL){
			exit(1);
		}
		strcpy(pFile->hash,hash);
		strcpy(pFile->mime,mime);
		strcpy(pFile->ext,ext);
		pFile->path = getFilePath(pyrosDB,pFile->hash,pFile->ext);


		Pyros_List_Append(files,pFile);
		rc = sqlite3_step(stmt);
	}
	sqlite3_reset(stmt);
	return files;
}

PyrosList *
sqlStmtGetAll(sqlite3_stmt *stmt,enum SQL_GET_TYPE type){
	PyrosList *items;
	int rc;
	sqlite3_int64 *intptr;
	char *str;
	char *newstr;

	if (type == SQL_CHAR)
		items = Pyros_Create_List(1,sizeof(char*));
	else if (type == SQL_INT64P)
		items = Pyros_Create_List(1,sizeof(sqlite3_int64*));

	rc = sqlite3_step(stmt);
	while (rc == SQLITE_ROW) {
		if (type == SQL_CHAR){
			str = (char*)sqlite3_column_text(stmt, 0);
			newstr = malloc(sizeof(*newstr)*(strlen(str)+1));
			if (newstr == NULL)
				exit(1);
			strcpy(newstr,str);

			Pyros_List_Append(items,newstr);
		} else if (type == SQL_INT64P){
			intptr = malloc(sizeof(*intptr));
			*intptr = sqlite3_column_int64(stmt, 0);
			Pyros_List_Append(items,intptr);
		}
		rc = sqlite3_step(stmt);
	}
	//sqlite3_finalize(stmt);
	sqlite3_reset(stmt);
	return items;
}

void
sqlStartTransaction(PyrosDB *pyrosDB){
	sqlite3_stmt **stmts = pyrosDB->commands;
	if (!pyrosDB->inTransaction){
		sqlStmtGet(stmts[STMT_BEGIN],0);
		pyrosDB->inTransaction = TRUE;
	}
}

void
sqlCompileStmt(PyrosDB *pyrosDB, enum COMMAND_STMTS stmt,char *cmd){
	sqlite3_stmt **stmts = pyrosDB->commands;
	if (stmts[stmt] == NULL)
		sqlPrepareStmt(pyrosDB,cmd, &stmts[stmt]);
}
