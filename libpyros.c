#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>

#include <magic.h>

#include "pyros.h"
#include "sqlite.h"
#include "libpyros.h"
#include "str.h"
#include "hash.h"

#define FILEBUFSIZE 6000

static PyrosList *getStructuredTags(PyrosDB *pyrosDB,PyrosList *tagids,unsigned int flags);
static void mergeTagidsIntoPyrosTagList(PyrosDB *pyrosDB,PyrosList *tagids,PyrosList *ptaglist,const char *glob);

static void
importFile( char *file,char *path){
	if(access(path, F_OK ) != 0 &&
	   access(file, R_OK ) == 0){
		rename(file,path);
	}
}

static void
removeFile(char *path){
	if(access(path, W_OK ) == 0)
		remove(path);
}

static char *
getHash(const char *file,PyrosDB *pyrosDB){
	char *filehash;

	switch (pyrosDB->hashtype){
	case PYROS_MD5HASH:
		filehash = getMD5(file);
		break;
	case PYROS_SHA1HASH:
		filehash = getSHA1(file);
		break;
	case PYROS_SHA256HASH:
		filehash = getSHA256(file);
		break;
	case PYROS_SHA512HASH:
		filehash = getSHA512(file);
		break;
	case PYROS_BLAKE2BHASH:
		filehash = getBLAKE2B(file);
		break;
	case PYROS_BLAKE2SHASH:
		filehash = getBLAKE2S(file);
		break;
	default:
		return NULL;
	}

	return filehash;
}

static void
getExt(char fileext[],const char *file){
	size_t i,j;

	fileext[0] = '\0';
	for (i = strlen(file); i > 0; i--){
		if (file[i] == '/' || file[i-1] == '/' || i == 1){
			break;
		} else if (file[i] == '.'){
			i++;
			for (j = 0;i <= strlen(file);j++,i++){
				fileext[j] = file[i];
			}
			break;
		}
	}
}

static char *
getMime(const char *file){
	const char *filemime;
	char *returnMime;
	magic_t magic_cookie;

	magic_cookie = magic_open(MAGIC_MIME_TYPE);
	magic_load(magic_cookie, NULL);

	filemime = magic_file(magic_cookie, file);
	returnMime = malloc(sizeof(*returnMime)*(strlen(filemime)+1));
	if (returnMime != NULL)
		strcpy(returnMime,filemime);

	magic_close(magic_cookie);
	return returnMime;
}

static size_t
getFileSize(const char *file){
	struct stat st;
	stat(file, &st);
	return st.st_size;
}

static int
isFile(const char *path){
	struct stat statbuf;
	if (stat(path, &statbuf) != 0)
		return 0;
	return S_ISREG(statbuf.st_mode);
}

static void
addHook(PyrosDB *pyrosDB,void(*callback)(), char *str, char *str2,void(*freecallback)()){
	PyrosHook *hook;

	hook = malloc(sizeof(*hook));
	hook->callback = callback;
	hook->freecallback = freecallback;
	hook->str = str;
	hook->str2 = str2;
	Pyros_List_Append(pyrosDB->hook,hook);
}

static void
freeHook(PyrosHook *hook){
	void(*freecallback)();
	if (hook->freecallback != NULL){
		freecallback = hook->freecallback;
		if (hook->str != NULL)
			freecallback(hook->str);
		if (hook->str2 != NULL)
			freecallback(hook->str2);
	}
	free(hook);
}

static PyrosDB*
Init_Pyros_DB(const char *path,int isNew){
	PyrosDB *pyrosDB = malloc(sizeof(*pyrosDB));
	sqlite3_stmt **stmts;
	int i;

	if (pyrosDB == NULL)
		return NULL;

	stmts = malloc(sizeof(*stmts)*STMT_COUNT);

	if (stmts == NULL)
		return NULL;

	pyrosDB->path = malloc(sizeof(*pyrosDB->path)*(strlen(path)+1));
	strcpy(pyrosDB->path,path);
	if (pyrosDB->path == NULL){
		free(pyrosDB);
		return NULL;
	}

	if((pyrosDB->database = initDB(path,isNew)) == NULL){
		free(pyrosDB);
		return NULL;
	}



	pyrosDB->hook = Pyros_Create_List(1,sizeof(PyrosHook*));
	//strcpy(pyrosDB->err,"no error has occured");
	pyrosDB->inTransaction = FALSE;



	sqlPrepareStmt(pyrosDB,"BEGIN;" ,&stmts[STMT_BEGIN]);
	sqlPrepareStmt(pyrosDB,"COMMIT;",&stmts[STMT_END]);
	for (i = STMT_END+1; i < STMT_COUNT; i++)
		stmts[i] = NULL;

	pyrosDB->commands = stmts;

	return pyrosDB;
}

PyrosDB*
Pyros_Open_Database(const char *path){
	PyrosDB *pyrosDB;
	sqlite3_stmt *Query_Master;

	pyrosDB = Init_Pyros_DB(path,FALSE);
	if (pyrosDB == NULL)
		return NULL;


	sqlPrepareStmt(pyrosDB,"SELECT val FROM master WHERE id=?;",
				   &Query_Master);

	sqlBind(Query_Master,FALSE,1,SQL_CHAR,"hashtype");
	sqlStmtGet(Query_Master,1,SQL_INT,&pyrosDB->hashtype);

	sqlBind(Query_Master,FALSE,1,SQL_CHAR,"ext case-sensitive");
	sqlStmtGet(Query_Master,1,SQL_INT,&pyrosDB->is_ext_case_sensitive);

	sqlBind(Query_Master,FALSE,1,SQL_CHAR,"tag case-sensitive");
	sqlStmtGet(Query_Master,1,SQL_INT,&pyrosDB->is_tag_case_sensitive);

	sqlBind(Query_Master,FALSE,1,SQL_CHAR,"version");
	sqlStmtGet(Query_Master,1,SQL_INT,&pyrosDB->version);

	sqlBind(Query_Master,FALSE,1,SQL_CHAR,"preserve-ext");
	sqlStmtGet(Query_Master,1,SQL_INT,&pyrosDB->preserve_ext);

	sqlite3_finalize(Query_Master);
	return pyrosDB;
}

int
Pyros_Database_Exists(const char *path){
	char dbfile[strlen(path)+strlen(DBFILE)+1];

	strcpy(dbfile,path);
	strcat(dbfile,DBFILE);
	if (access(dbfile,F_OK) != -1){
		return TRUE;
	}


	return FALSE;
}

void
Pyros_Close_Database(PyrosDB *pyrosDB){
	sqlite3_stmt **stmts;
	int i;

	if (pyrosDB == NULL)
		return;

	stmts = pyrosDB->commands;
	for (i = 0; i < STMT_COUNT; i++)
		if (stmts[i] != NULL)
			sqlite3_finalize(stmts[i]);


	Pyros_List_Free(pyrosDB->hook,(Pyros_Free_Callback)freeHook);
	closeDB(pyrosDB->database);
	free(pyrosDB->commands);
	free(pyrosDB->path);
	free(pyrosDB);
}

void
Pyros_Close_File(PyrosFile *pFile){
	if (pFile == NULL)
		return;
	free(pFile->hash);
	free(pFile->mime);
	free(pFile->ext);
	free(pFile->path);
	free(pFile);
}

PyrosFile*
Pyros_Duplicate_File(PyrosFile *pFile){
	PyrosFile *newFile;

	if (pFile == NULL)
		return NULL;

	newFile = malloc(sizeof(*newFile));

	if (newFile == NULL)
		return NULL;

	*newFile = *pFile;
	if ((newFile->path = malloc(strlen(pFile->path)+1)) == NULL){
		free(newFile);
		return NULL;
	}
	if ((newFile->hash = malloc(strlen(pFile->hash)+1)) == NULL){
		free(newFile->path);
		free(newFile);
		return NULL;
	}
	if ((newFile->ext = malloc(strlen(pFile->ext)+1)) == NULL){
		free(newFile->hash);
		free(newFile->path);
		free(newFile);
		return NULL;
	}
	if ((newFile->mime = malloc(strlen(pFile->mime)+1)) == NULL){
		free(newFile->ext);
		free(newFile->hash);
		free(newFile->path);
		free(newFile);
		return NULL;
	}

	strcpy(newFile->path,pFile->path);
	strcpy(newFile->hash,pFile->hash);
	strcpy(newFile->ext ,pFile->ext);
	strcpy(newFile->mime,pFile->mime);
	return newFile;
}

int
Pyros_Execute(PyrosDB *pyrosDB){
	PyrosHook *hook;
	int ret = PYROS_OK;
	size_t i;
	sqlite3_stmt **stmts = pyrosDB->commands;

	if(pyrosDB->inTransaction){

		ret = sqlStmtGet(stmts[STMT_END],0);
		pyrosDB->inTransaction = FALSE;

		if (ret == PYROS_OK){
			for (i = 0; i < pyrosDB->hook->length; i++) {
				hook = pyrosDB->hook->list[i];
				(*hook->callback)(hook->str, hook->str2);
			}

			Pyros_List_Free(pyrosDB->hook,(Pyros_Free_Callback)freeHook);
			pyrosDB->hook = Pyros_Create_List(1,sizeof(PyrosHook*));
		}
	}
	return ret;
}


PyrosDB*
Pyros_Create_Database(char *path,enum PYROS_HASHTYPE hashtype){
	size_t i, j;
	size_t pathlen = strlen(path);
	char dbpath[pathlen+strlen(DBFILE)];

	PyrosDB *pyrosDB;
	sqlite3_stmt **stmts;
	sqlite3_stmt *create_DB;

	/* makes entire path */
	for (i = 1; i < pathlen; i++){
		if (path[i] == '/'){
			path[i] = '\0';
			mkdir(path,0777);
			path[i] = '/';
		}
	}
	/* make path */
	mkdir(path,0777);

	/* create path/db folder */
	strcpy(dbpath,path);
	strcat(dbpath,"/db/");
	mkdir(dbpath,0777);

	/* create path/db/xx folder */

	dbpath[pathlen+6] = '\0';
	for (i = 0; i < 16; i++){
		for (j = 0; j < 16; j++){
			dbpath[pathlen+4] = HEX[i];
			dbpath[pathlen+5] = HEX[j];
			mkdir(dbpath,0777);
		}
	}

	/* create sqlite database */
	pyrosDB = Init_Pyros_DB(path,TRUE);


	pyrosDB->hashtype = hashtype;
	pyrosDB->is_ext_case_sensitive = 1;
	pyrosDB->is_tag_case_sensitive = 1;
	pyrosDB->version = PYROS_VERSION;
	pyrosDB->inTransaction = TRUE;
	pyrosDB->preserve_ext = TRUE;
	stmts = pyrosDB->commands;
	sqlStmtGet(stmts[STMT_BEGIN],0);


	/* master table */
	/* stores settings */
	sqlPrepareStmt(pyrosDB,
				   "CREATE TABLE IF NOT EXISTS master(id TEXT PRIMARY KEY,"
				   "val INT NOT NULL)WITHOUT ROWID;",&create_DB);
	sqlStmtGet(create_DB,0);
	sqlite3_finalize(create_DB);

	/* hashes table */
	/* stores hash,hash metadata and id */
	sqlPrepareStmt(pyrosDB,
				   "CREATE TABLE IF NOT EXISTS hashes(id INTEGER PRIMARY KEY,"
				   "hash TEXT COLLATE NOCASE,truehash TEXT UNIQUE COLLATE NOCASE,"
				   "import_time INT,"
				   "mimetype TEXT,ext TEXT COLLATE NOCASE,filesize INT);",
				   &create_DB);
	sqlStmtGet(create_DB,0);
	sqlite3_finalize(create_DB);

	/* tag table */
	/* stores tag and id */
	sqlPrepareStmt(pyrosDB,
				   "CREATE TABLE IF NOT EXISTS tag(id INTEGER PRIMARY KEY,"
				   "tag TEXT COLLATE NOCASE UNIQUE,"
				   "aliases INT,parents INT,children INT);"
				   ,&create_DB);
	sqlStmtGet(create_DB,0);
	sqlite3_finalize(create_DB);

	/* tags table */
	/* stores relations between tags and hashes */
	sqlPrepareStmt(pyrosDB,
				   "CREATE TABLE IF NOT EXISTS tags(hashid INT NOT NULL, "
				   "tagid INT NOT NULL,isantitag INT NOT NULL,"
				   "PRIMARY KEY(hashid,tagid,isantitag),"
				   "CONSTRAINT fk_hashes"
				   " FOREIGN KEY (hashid) REFERENCES hashes(id)"
				   " ON DELETE CASCADE"
				   ",CONSTRAINT fk_tag"
				   " FOREIGN KEY (tagid) REFERENCES  tag(id)"
				   " ON DELETE CASCADE)WITHOUT ROWID;",&create_DB);
	sqlStmtGet(create_DB,0);
	sqlite3_finalize(create_DB);

	/* tagrelations table */
	/* stores relations between tags */
	/* NO FOREIGN KEY */
	sqlPrepareStmt(pyrosDB,
				   "CREATE TABLE IF NOT EXISTS tagrelations(tag INT NOT NULL, tag2 INT NOT NULL,"
				   "type INT NOT NULL,PRIMARY KEY(tag,tag2))"
				   "WITHOUT ROWID;",&create_DB);
	sqlStmtGet(create_DB,0);
	sqlite3_finalize(create_DB);

	/* tagrelations compiled */
	/* stores relations between tags */
	/* NO FOREIGN KEY */
	sqlPrepareStmt(pyrosDB,
				   "CREATE TABLE IF NOT EXISTS tagcomp(id INTEGER PRIMARY KEY,"
				    "tags BLOB, type INT NOT NULL)"
				   "WITHOUT ROWID;",&create_DB);
	sqlStmtGet(create_DB,0);
	sqlite3_finalize(create_DB);


	sqlPrepareStmt(pyrosDB,
				   "INSERT OR IGNORE INTO master VALUES(?,?);",&create_DB);

	sqlBind(create_DB,TRUE,2,
			SQL_CHAR,"version",
			SQL_INT,PYROS_VERSION);
	sqlBind(create_DB,TRUE,2,
			SQL_CHAR,"hashtype",
			SQL_INT,hashtype);
	sqlBind(create_DB,TRUE,2,
			SQL_CHAR,"preserve-ext",
			SQL_INT,TRUE);
	sqlBind(create_DB,TRUE,2,
			SQL_CHAR,"ext case-sensitive",
			SQL_INT,FALSE);
	sqlBind(create_DB,TRUE,2,
			SQL_CHAR,"tag case-sensitive",
			SQL_INT,FALSE);
	sqlBind(create_DB,TRUE,2,
			SQL_CHAR,"preserve-ext",
			SQL_INT,TRUE);

	sqlite3_finalize(create_DB);
	return pyrosDB;
}

static void
AddTag(PyrosDB *pyrosDB, const char* tag){
	sqlite3_stmt **stmts = pyrosDB->commands;
	if (stmts[STMT_ADD_TAG] == NULL)
		sqlPrepareStmt(pyrosDB,
					   "INSERT OR IGNORE INTO tag(tag) VALUES(TRIM(LOWER(?),'\n\t\r '));",
					   &stmts[STMT_ADD_TAG]);

	sqlBind(stmts[STMT_ADD_TAG],TRUE,1,SQL_CHAR,tag);
}

char *
Pyros_Add(PyrosDB *pyrosDB, const char *filePath){
	char *file;
	size_t filetime;
	size_t filesize;
	char fileext[strlen(filePath)+1];
	char *filehash;
	char *filepath;
	char *filemime;

	sqlite3_stmt **stmts = pyrosDB->commands;

	if (!isFile(filePath)){
		/* should set an error */
		return NULL;
	}

	file = malloc(sizeof(*file)*(strlen(filePath)+1));
	if (file == NULL){
		return NULL;
	}
	strcpy(file,filePath);

	filehash = getHash(file,pyrosDB);
	if (filehash == NULL){
		return NULL;
	}

	filemime = getMime(file);
	getExt(fileext,file);
	filepath = getFilePath(pyrosDB,filehash,fileext);
	filetime = time(NULL);
	filesize = getFileSize(file);

	if (!pyrosDB->inTransaction){
		sqlStmtGet(stmts[STMT_BEGIN],0);
		pyrosDB->inTransaction = TRUE;
	}

	if (stmts[STMT_ADD_FILE] == NULL)
		sqlPrepareStmt(pyrosDB,
					   "INSERT OR IGNORE INTO hashes "
					   "(hash,truehash,import_time,mimetype,ext,filesize) "
					   "VALUES(?,?,?,?,?,?);",
					   &stmts[STMT_ADD_FILE]);

	sqlBind(stmts[STMT_ADD_FILE],TRUE,6,
			SQL_CHAR,filehash,
			SQL_CHAR,filehash,
			SQL_INT64,filetime,
			SQL_CHAR,filemime,
			SQL_CHAR,fileext,
			SQL_INT64,filesize);

	addHook(pyrosDB,&importFile,file,filepath,&free);

	free(filemime);
	return filehash;
}

static void
importTagsFromTagFile(PyrosDB *pyrosDB,char *hash,char *filepath){
	size_t i,j;
	size_t buffersize = 20;
	char *tagbuffer = malloc(buffersize);
	char filebuf[FILEBUFSIZE];
	FILE *tagFile;
	PyrosList *tagFileTags;
	char lastchar = '0';

	int tagfilelen = strlen(filepath)+4+1;
	char *tagFilePath = malloc(sizeof(*tagFilePath)*tagfilelen);

	sprintf(tagFilePath,"%s.txt",filepath);

	if (!isFile(tagFilePath))
		return;

	tagFile = fopen(tagFilePath, "r");
	tagFileTags = Pyros_Create_List(1,sizeof(char*));

	j = 0;
	while(fgets(filebuf, FILEBUFSIZE, tagFile) != NULL){
		for (i = 0; i < strlen(filebuf); i++) {
			lastchar = filebuf[i];
			switch (filebuf[i]) {
			default:
				tagbuffer[j] = filebuf[i];
				j++;
				if (j+1 >= buffersize){
					buffersize *= 2;
					tagbuffer = realloc(tagbuffer,buffersize);
					/*WEW*/
					if (tagbuffer == NULL)
						fprintf(stderr,"pyros: allocation error");
				}
				break;
			case '\n':
				/* append tag to taglist*/
				tagbuffer[j] = '\0';
				Pyros_List_Append(tagFileTags,tagbuffer);
				j = 0;
				tagbuffer = malloc(sizeof(*tagbuffer)*buffersize);
				if (tagbuffer == NULL)
					fprintf(stderr,"pyros: allocation error");
				break;
			}
		}
	}
	if (lastchar != '\n'){
		tagbuffer[j] = '\0';
		Pyros_List_Append(tagFileTags,tagbuffer);
	}else{
		free(tagbuffer);
	}
	fclose(tagFile);

	Pyros_Add_Tag(pyrosDB,hash,(char**)tagFileTags->list,
				  tagFileTags->length);

	addHook(pyrosDB,&removeFile,tagFilePath,NULL,free);
	Pyros_List_Free(tagFileTags,free);
}

static int
isTagFile(char *filePaths[], size_t filec, size_t p){
	size_t i;
	size_t filelen = strlen(filePaths[p])-4;

	/* check if filename ends in .txt*/
	if (filelen < 1 || strcmp(&filePaths[p][filelen],".txt"))
		return FALSE;


	/* check if another file exists without the '.txt' */
	for (i = 0; i < filec; i++)
		if ( p != i && !strncmp(filePaths[p],filePaths[i],filelen))
			return TRUE;

	return FALSE;
}

PyrosList *
Pyros_Add_Full(PyrosDB *pyrosDB, char *filePaths[], size_t filec,
			   char *tags[], size_t tagc,int useTagfile,int returnHashes,
			   Pyros_Add_Full_Callback callback,void *callback_data){
	PyrosList *files = Pyros_Create_List(filec,sizeof(char*));
	PyrosList *hashes = NULL;
	size_t i;
	char *hash;

	for (i = 0; i < filec; i++) {
		if (!(useTagfile && isTagFile(filePaths,filec,i))){
			Pyros_List_Append(files,filePaths[i]);
		}
	}

	if (returnHashes)
		hashes = Pyros_Create_List(files->length, sizeof(char*));

	for (i = 0; i < files->length; i++) {
		hash = Pyros_Add(pyrosDB,files->list[i]);
		if (hash != NULL){
			if (useTagfile)
				importTagsFromTagFile(pyrosDB,hash,files->list[i]);

			Pyros_Add_Tag(pyrosDB,hash, (char**)tags, tagc);

			if (callback != NULL)
				(*callback)(hash,files->list[i],i,callback_data);

			if (returnHashes && !PyrosListContainsStr(hashes, hash, NULL)){
				Pyros_List_Append(hashes, hash);
			} else{
				free(hash);
			}
		}
	}

	return hashes;
}

int
Pyros_Add_Tag(PyrosDB *pyrosDB, const char *hash, char *tags[], size_t tagc){
	size_t i;

	sqlite3_stmt **stmts = pyrosDB->commands;

	if (tagc == 0)
		return PYROS_OK;


	if (!pyrosDB->inTransaction){
		sqlStmtGet(stmts[STMT_BEGIN],0);
		pyrosDB->inTransaction = TRUE;
	}
	if (stmts[STMT_ADD_TAG_TO_FILE] == NULL)
		sqlPrepareStmt(pyrosDB,
					   "INSERT OR IGNORE INTO tags VALUES("
					   "(SELECT id FROM hashes WHERE truehash=LOWER(?)),"
					   "(SELECT id FROM tag WHERE tag=TRIM(LOWER(?),'\n\t\r ')),?);",
					   &stmts[STMT_ADD_TAG_TO_FILE]);

	for (i = 0;i < tagc;i++){
		if (tags[i][0] != '\0'){
			if (tags[i][0] == '-'){
				AddTag(pyrosDB,&tags[i][1]);
				sqlBind(stmts[STMT_ADD_TAG_TO_FILE],TRUE,3,
						SQL_CHAR,hash,
						SQL_CHAR,&tags[i][1],
						SQL_INT, TRUE);

			} else{
				AddTag(pyrosDB,tags[i]);
				sqlBind(stmts[STMT_ADD_TAG_TO_FILE],TRUE,3,
						SQL_CHAR,hash,
						SQL_CHAR,tags[i],
						SQL_INT, FALSE);
			}
		}
	}
	return PYROS_OK;
}

static PrcsTags*
ProcessTags(PyrosDB *pyrosDB, char **tags, size_t tagc, querySettings *qSet){
	size_t i,j;
	sqlite3_int64 *tagid;
	char *tag;

	PrcsTags *prcsTags = malloc(sizeof(*prcsTags)*(tagc));
	if (prcsTags == NULL){
		return NULL;
	}

	for (i=0; i < tagc; i++){
		prcsTags[i].type = TT_NORMAL;

		if(tags[i][0] == '-'){
			prcsTags[i].filtered = TRUE;
			tag = &tags[i][1];
		} else{
			prcsTags[i].filtered = FALSE;
			tag = tags[i];
		}
		for (j = 0; j < i; j++) {
			if (strcmp(tag,tags[j]) == 0){
				prcsTags[i].type = TT_IGNORE;
				break;
			}
		}

		if (prcsTags[i].type == TT_IGNORE){
			/* PASS */
		} else if(strcmp("*",tag) == 0){
			prcsTags[i].type = TT_ALL;
			if (prcsTags[i].filtered == TRUE)
					goto noresults;

			/* Remove all TT_NORMAL tags that aren't filtered */
		} else if(strncmp("hash:",tag,5) == 0){
			prcsTags[i].type = TT_HASH;
			prcsTags[i].meta.text = &tag[5];

		} else if(strncmp("mime:",tag,5) == 0){
			prcsTags[i].type = TT_MIME;
			prcsTags[i].meta.text = &tag[5];

		} else if(strncmp("ext:",tag,4) == 0){
			prcsTags[i].type = TT_EXT;
			prcsTags[i].meta.text = &tag[4];

		} else if(strncmp("tagcount:",tag,9) == 0){
			prcsTags[i].type = TT_TAGCOUNT;
			switch (tag[9]) {
			case '\0':
				goto noresults;
			case '<':
				tag = &tags[i][10];
				prcsTags[i].meta.stat.max = atoi(tag);
				prcsTags[i].meta.stat.min = -1;
				break;
			case '>':
				tag = &tags[i][10];
				prcsTags[i].meta.stat.min = atoi(tag);
				prcsTags[i].meta.stat.max = -1;
				break;
			case '=':
				tag = &tags[i][10];
				prcsTags[i].meta.stat.min = atoi(tag)-1;
				prcsTags[i].meta.stat.max = atoi(tag)+1;
				break;
			default:
				tag = &tags[i][9];
				prcsTags[i].meta.stat.min = atoi(tag)-1;
				prcsTags[i].meta.stat.max = atoi(tag)+1;
				break;
			}
		} else if(strncmp("order:",tag,6) == 0){
			tag = &tag[6];

			(*qSet).reversed = prcsTags[i].filtered;
			prcsTags[i].type = TT_IGNORE;

			if (strcmp("ext",tag) == 0)
				(*qSet).order = OT_EXT;
			else if (strcmp("hash",tag) == 0)
				 (*qSet).order = OT_HASH;
			else if (strcmp("mime",tag) == 0)
				 (*qSet).order = OT_MIME;
			else if (strcmp("time",tag) == 0)
				 (*qSet).order = OT_TIME;
			else if (strcmp("size",tag) == 0)
				(*qSet).order = OT_SIZE;
			else if (strcmp("random",tag) == 0)
				(*qSet).order = OT_RANDOM;

		} else if(strncmp("limit:",tag,6) == 0){
			prcsTags[i].type = TT_IGNORE;

			tag = &tags[i][6];
			(*qSet).pageSize = atoi(tag);
		} else if(strncmp("page:",tag,5) == 0){
			prcsTags[i].type = TT_IGNORE;

			tag = &tags[i][5];
			(*qSet).page = atoi(tag)-1;
		} else {
			if (containsGlobChar(tag)){
				prcsTags[i].meta.tags = getTagIdByGlob(pyrosDB,tag);
			} else{
				prcsTags[i].meta.tags = Pyros_Create_List(1,sizeof(sqlite3_int64*));
				tagid = getTagId(pyrosDB,tag);
				if (tagid != NULL){
					Pyros_List_Append(prcsTags[i].meta.tags,tagid);
				} else if (!prcsTags[i].filtered){//if tag does not exist
					goto noresults;
				}
			}

			/* get ext tags */
			for (j = 0; j < prcsTags[i].meta.tags->length; j++) {
				PyrosStrListMerge(prcsTags[i].meta.tags,
								  Get_Aliased_Ids(pyrosDB,prcsTags[i].meta.tags->list[j]));
				PyrosStrListMerge(prcsTags[i].meta.tags,
								  Get_Children_Ids(pyrosDB,prcsTags[i].meta.tags->list[j]));
			}
		}

	}

	return prcsTags;

	noresults:
	for (j=0; j <= i; j++)
		if (prcsTags[j].type == TT_NORMAL)
			Pyros_List_Free(prcsTags[j].meta.tags,free);

	free(prcsTags);

	return NULL;

}

static void
catTagGroup(char *str, PrcsTags prcsTags){
	size_t i;

	strcat(str," SELECT hashid FROM tags WHERE tagid IN (");
	for (i=0; i < prcsTags.meta.tags->length; i++)
		strcat(str,"?,");

	strcat(str,"NULL) AND isantitag=0 ");
}

static void
catStatGroup(char *str, PrcsTags prcsTags){
	strcat(str," SELECT hashid FROM tags GROUP BY hashid HAVING COUNT(hashid)");
	if (prcsTags.meta.stat.min >= 0 && prcsTags.meta.stat.max >= 0 )
		strcat(str," > ? AND COUNT(hashid) < ? ");
	else if (prcsTags.meta.stat.min >= 0)
		strcat(str," > ? ");
	else if (prcsTags.meta.stat.max >= 0)
		strcat(str," < ? ");

}


static void
catMetaGroup(char *str, PrcsTags prcsTags, char *label){
	strcat(str," SELECT id FROM hashes WHERE ");
	strcat(str,label);
	if (containsGlobChar(prcsTags.meta.text)){
		strcat(str," GLOB ? ");
	} else{
		strcat(str,"=? ");
	}
}

PyrosList *
Pyros_Search(PyrosDB *pyrosDB, char **rawTags, size_t tagc){
	size_t i,j;
	size_t cmdSize;
	char *cmd;
	int firstGroup = TRUE;

	querySettings qSet;
	PrcsTags *prcsTags;

	PyrosList *hashes;
	sqlite3_stmt *Query_Hash_By_Tags;

	qSet.reversed = FALSE;
	qSet.order = OT_NONE;
	qSet.page = -1;
	qSet.pageSize = -1;

	prcsTags = ProcessTags(pyrosDB,rawTags,tagc,&qSet);
	if (prcsTags == NULL)
		return Pyros_Create_List(1,sizeof(char*));//returns empty list

	cmdSize = strlen("SELECT truehash,mimetype,ext,import_time,filesize "
					 "FROM hashes WHERE id IN ( GROUP BY hashid)");

	for (i=0; i < tagc; i++){
		cmdSize += strlen("INTERSECT SELECT hashid FROM tags WHERE tagid IN (NULL) AND isantitag=0")*2;
		if (prcsTags[i].type == TT_NORMAL){
			for (j=0; j < prcsTags[i].meta.tags->length; j++){
				cmdSize += strlen("?,");
			}
		} else {
			cmdSize += strlen("AND NOT GLOB ?");
		}
	}

	cmd = malloc(sizeof(*cmd)*(cmdSize+1));
	if (cmd == NULL){
		free(prcsTags);
		return NULL;
	}

	strcpy(cmd,"SELECT truehash,mimetype,ext,import_time,filesize "
		   "FROM hashes WHERE id IN (");

	for (i=0; i < tagc; i++){
		if (prcsTags[i].type != TT_IGNORE){
			if (firstGroup && prcsTags[i].filtered){
				strcat(cmd,"SELECT hashid FROM tags EXCEPT");
				firstGroup = FALSE;
			} else if (firstGroup){
				firstGroup = FALSE;
			} else if (prcsTags[i].filtered){
				strcat(cmd,"EXCEPT");
			} else{
				strcat(cmd,"INTERSECT");
			}

			switch (prcsTags[i].type){
			case TT_NORMAL:
				catTagGroup(cmd,prcsTags[i]);
				break;
			case TT_TAGCOUNT:
				catStatGroup(cmd, prcsTags[i]);
				break;
			case TT_ALL:
				strcat(cmd," SELECT id FROM hashes ");
				prcsTags[i].type = TT_IGNORE;
				break;
			case TT_HASH:
				catMetaGroup(cmd,prcsTags[i],"hash");
				break;
			case TT_MIME:
				catMetaGroup(cmd,prcsTags[i],"mimetype");
				break;
			case TT_EXT:
				catMetaGroup(cmd,prcsTags[i],"ext");
				break;
			default:
				return NULL;
			}
		}
	}

	strcat(cmd,") GROUP BY hash");

	if (qSet.order != OT_NONE){
		strcat(cmd," ORDER BY ");
		switch (qSet.order){
		case OT_EXT:
			strcat(cmd,"ext");
			break;
		case OT_HASH:
			strcat(cmd,"hash");
			break;
		case OT_MIME:
			strcat(cmd,"mimetype");
			break;
		case OT_TIME:
			strcat(cmd,"import_time");
			break;
		case OT_SIZE:
			strcat(cmd,"filesize");
			break;
		case OT_RANDOM:
			strcat(cmd,"RANDOM()");
			break;
		default:
			return NULL;
		}
		if (qSet.reversed)
			strcat(cmd," ASC");
		else
			strcat(cmd," DESC");
	}
	if (qSet.pageSize > 0)
		strcat(cmd," LIMIT ?");
	if (qSet.page >= 0){
		if (qSet.pageSize <= 0){
			qSet.pageSize = 1000;
			strcat(cmd," LIMIT ? OFFSET ?");
		} else{
			strcat(cmd," OFFSET ?");
		}
	}


	sqlPrepareStmt(pyrosDB,cmd,&Query_Hash_By_Tags);
	sqlBindTags(Query_Hash_By_Tags,prcsTags,tagc,qSet);
	hashes = sqlStmtGetAllFiles(pyrosDB, Query_Hash_By_Tags);

	/* clean up */
	for (i=0; i < tagc; i++)
		if (prcsTags[i].type == TT_NORMAL)
				Pyros_List_Free(prcsTags[i].meta.tags,free);


	free(cmd);
	free(prcsTags);
	sqlite3_finalize(Query_Hash_By_Tags);
	return hashes;
}


PyrosList*
Pyros_Get_All_Hashes(PyrosDB *pyrosDB){
	sqlite3_stmt **stmts = pyrosDB->commands;
	if (stmts[STMT_QUERY_ALL_HASH] == NULL)
		sqlPrepareStmt(pyrosDB,"SELECT hash FROM hashes;",
					   &stmts[STMT_QUERY_ALL_HASH]);

	return sqlStmtGetAll(stmts[STMT_QUERY_ALL_HASH],SQL_CHAR);
}

PyrosList*
Pyros_Get_All_Tags(PyrosDB *pyrosDB){
	sqlite3_stmt **stmts = pyrosDB->commands;
	if (stmts[STMT_QUERY_ALL_TAGS] == NULL)
		sqlPrepareStmt(pyrosDB,"SELECT tag FROM tag;",
					   &stmts[STMT_QUERY_ALL_TAGS]);

	return sqlStmtGetAll(stmts[STMT_QUERY_ALL_TAGS],SQL_CHAR);
}

PyrosList *
Pyros_Get_Tags_From_Hash_Simple(PyrosDB *pyrosDB, const char *hash, int showExt){
	PyrosList *tags;
	PyrosList *final_tags;
	size_t i;
	char *cmd;
	int cmdlength;

	sqlite3_stmt **stmts = pyrosDB->commands;
	sqlite3_stmt *Query_Tag_By_Id;

	if (stmts[STMT_QUERY_TAG_BY_HASH] == NULL)
		sqlPrepareStmt(pyrosDB,"SELECT tagid FROM tags WHERE hashid="
					   "(SELECT id FROM hashes WHERE hash=?) AND isantitag=0;",
					   &stmts[STMT_QUERY_TAG_BY_HASH]);

	sqlBind(stmts[STMT_QUERY_TAG_BY_HASH],FALSE,1,SQL_CHAR,hash);


	tags = sqlStmtGetAll(stmts[STMT_QUERY_TAG_BY_HASH],SQL_INT64P);

	if (tags == NULL)
		return NULL;

	cmdlength = strlen("SELECT tag FROM tag WHERE id IN () ORDER BY tag")+1;
	for (i = 0; i < tags->length; i++) {
		if (showExt){
			PyrosStrListMerge(tags,Get_Aliased_Ids(pyrosDB,tags->list[i]));
			PyrosStrListMerge(tags,Get_Parent_Ids(pyrosDB,tags->list[i]));
		}
		cmdlength += 3;
	}
	
	cmd = malloc(sizeof(*cmd)*cmdlength);
	strcpy(cmd,"SELECT tag FROM tag WHERE  id IN (");

	for (i = 0; i < tags->length; i++) {
		strcat(cmd,"?");
		if (i+1 < tags->length)
			strcat(cmd,",");
	}
	strcat(cmd,") ORDER BY tag");

	sqlPrepareStmt(pyrosDB,cmd,&Query_Tag_By_Id);
	free(cmd);

	sqlBindList(Query_Tag_By_Id,tags,SQL_INT64P);

	final_tags = sqlStmtGetAll(Query_Tag_By_Id,SQL_CHAR);
	Pyros_List_Free(tags,free);
	sqlite3_finalize(Query_Tag_By_Id);

	return final_tags;
}

PyrosList *
Pyros_Get_Tags_From_Hash(PyrosDB *pyrosDB, const char *hash){
	PyrosList *tags;
	PyrosList *structured_tags;

	sqlite3_stmt **stmts = pyrosDB->commands;

	if (stmts[STMT_QUERY_TAG_BY_HASH] == NULL)
		sqlPrepareStmt(pyrosDB,"SELECT tagid FROM tags WHERE hashid="
					   "(SELECT id FROM hashes WHERE truehash=?) AND isantitag=0;",
					   &stmts[STMT_QUERY_TAG_BY_HASH]);

	sqlBind(stmts[STMT_QUERY_TAG_BY_HASH],FALSE,1,SQL_CHAR,hash);


	tags = sqlStmtGetAll(stmts[STMT_QUERY_TAG_BY_HASH],SQL_INT64P);

	if (tags == NULL)
		return NULL;

	structured_tags = getStructuredTags(pyrosDB,tags,PYROS_FILE_EXT);
	mergeTagidsIntoPyrosTagList(pyrosDB,tags,structured_tags,NULL);
	Pyros_List_Free(tags,free);
	return structured_tags;
}

PyrosList *
getExtIds(PyrosDB *pyrosDB, sqlite3_int64 *tag, int type1, int type2){
	sqlite3_stmt **stmts = pyrosDB->commands;
	PyrosList *pList;

	if (stmts[STMT_QUERY_EXT1] == NULL)
		sqlPrepareStmt(pyrosDB,"SELECT tag2 FROM tagrelations "
					   "WHERE type=? AND tag=?;",
					   &stmts[STMT_QUERY_EXT1]);
	if (stmts[STMT_QUERY_EXT2] == NULL)
		sqlPrepareStmt(pyrosDB,"SELECT tag FROM tagrelations "
					   "WHERE type=? AND tag2=?;",
					   &stmts[STMT_QUERY_EXT2]);
	/* SELECT tag FROM tagrelations WHERE (type=? AND tag2=?) OR (type=? AND tag1=?) */

	sqlBind(stmts[STMT_QUERY_EXT1],FALSE,2,
			SQL_INT ,type1,
			SQL_INT64P,tag);

	pList = sqlStmtGetAll(stmts[STMT_QUERY_EXT1],SQL_INT64P);
	sqlBind(stmts[STMT_QUERY_EXT2],FALSE,2,
			SQL_INT ,type2,
			SQL_INT64P,tag);

	PyrosListMerge(pList,sqlStmtGetAll(stmts[STMT_QUERY_EXT2],SQL_INT64P));

	return pList;
}

PyrosList *
Get_Aliased_Ids(PyrosDB *pyrosDB, sqlite3_int64 *tag){
	return getExtIds(pyrosDB,tag,TAG_TYPE_ALIAS,TAG_TYPE_ALIAS);

}

PyrosList *
Get_Children_Ids(PyrosDB *pyrosDB, sqlite3_int64 *tag){
	return getExtIds(pyrosDB,tag,TAG_TYPE_CHILD,TAG_TYPE_PARENT);
}

PyrosList *
Get_Parent_Ids(PyrosDB *pyrosDB, sqlite3_int64 *tag){
	return getExtIds(pyrosDB,tag,TAG_TYPE_PARENT,TAG_TYPE_CHILD);
}

PyrosList *
getTagIdByGlob(PyrosDB *pyrosDB,const char *tag){
	sqlite3_stmt **stmts = pyrosDB->commands;

	if (stmts[STMT_QUERY_TAG_ID_BY_GLOB] == NULL)
		sqlPrepareStmt(pyrosDB,"SELECT id FROM tag WHERE tag GLOB TRIM(LOWER(?),'\n\t\r ');",
					   &stmts[STMT_QUERY_TAG_ID_BY_GLOB]);

	sqlBind(stmts[STMT_QUERY_TAG_ID_BY_GLOB],FALSE,1,
			SQL_CHAR,tag);


	return sqlStmtGetAll(stmts[STMT_QUERY_TAG_ID_BY_GLOB],SQL_INT64P);
}

sqlite3_int64*
getTagId(PyrosDB *pyrosDB,const char *tag){
	sqlite3_int64 *id = NULL;
	sqlite3_stmt **stmts = pyrosDB->commands;

	if (stmts[STMT_QUERY_TAG_ID] == NULL)
		sqlPrepareStmt(pyrosDB,"SELECT id FROM tag WHERE tag=TRIM(LOWER(?),'\n\t\r ');",
					   &stmts[STMT_QUERY_TAG_ID]);

	sqlBind(stmts[STMT_QUERY_TAG_ID],FALSE,1,
			SQL_CHAR,tag);

	sqlStmtGet(stmts[STMT_QUERY_TAG_ID],1,SQL_INT64P,&id);

	return id;
}

PyrosList *
GetExtTags(PyrosDB *pyrosDB, const char *tag,PyrosList *(*getExtIds)()){
	PyrosList *extTags = Pyros_Create_List(1,sizeof(char*));
	PyrosList *foundTags;
	char *cmd;
	int cmdlength;
	sqlite3_int64 *id;

	size_t i;
	sqlite3_stmt *Get_Tags_From_Ids;

	id = getTagId(pyrosDB,tag);
	if (id == NULL)
		return extTags;

	Pyros_List_Append(extTags,id);

	cmdlength = strlen("SELECT tag FROM tag WHERE id IN ()")+1;
	for (i = 0; i < extTags->length; i++){
		PyrosStrListMerge(extTags,(*getExtIds)(pyrosDB,extTags->list[i]));
		cmdlength += 2;
	}

	Pyros_List_RShift(&extTags,1);
	if (extTags->length == 0)
		return extTags;

	/* BAD MALLOC */
	cmd = malloc(sizeof(*cmd)*cmdlength);
	strcpy(cmd,"SELECT tag FROM tag WHERE id IN (");

	for (i = 0; i < extTags->length; i++){
		strcat(cmd,"?");
		if (i+1 < extTags->length)
			strcat(cmd,",");
	}
	strcat(cmd,")");
	sqlPrepareStmt(pyrosDB,cmd,&Get_Tags_From_Ids);


	sqlBindList(Get_Tags_From_Ids,extTags,SQL_INT64P);
	foundTags = sqlStmtGetAll(Get_Tags_From_Ids,SQL_CHAR);

	free(cmd);
	Pyros_List_Free(extTags,free);
	sqlite3_finalize(Get_Tags_From_Ids);


	return foundTags;
}

PyrosList *
Pyros_Get_Aliases(PyrosDB *pyrosDB, const char *tag){
	return GetExtTags(pyrosDB,tag,&Get_Aliased_Ids);
}
PyrosList *
Pyros_Get_Parents(PyrosDB *pyrosDB, const char *tag){
	return GetExtTags(pyrosDB,tag,&Get_Parent_Ids);
}
PyrosList *
Pyros_Get_Children(PyrosDB *pyrosDB, const char *tag){
	return GetExtTags(pyrosDB,tag,&Get_Children_Ids);
}



PyrosFile *
Pyros_Get_File_From_Hash(PyrosDB *pyrosDB, const char *hash){
	int result;
	sqlite3_stmt **stmts = pyrosDB->commands;

	PyrosFile *pFile = malloc(sizeof(*pFile));
	if (pFile == NULL){
		return NULL;
	}

	if (stmts[STMT_QUERY_FILE_FROM_HASH] == NULL)
		sqlPrepareStmt(pyrosDB,
					   "SELECT hash,mimetype,ext,import_time,filesize "
					   "FROM hashes WHERE truehash=LOWER(?);",
					   &stmts[STMT_QUERY_FILE_FROM_HASH]);



	sqlBind(stmts[STMT_QUERY_FILE_FROM_HASH],FALSE,1,
			SQL_CHAR,hash);

	result = sqlStmtGet(stmts[STMT_QUERY_FILE_FROM_HASH],5,
						SQL_CHAR,&pFile->hash,
						SQL_CHAR,&pFile->mime,
						SQL_CHAR,&pFile->ext,
						SQL_INT64,&pFile->import_time,
						SQL_INT64,&pFile->file_size);

	if (result == PYROS_OK){
		pFile->path = getFilePath(pyrosDB,pFile->hash,pFile->ext);
		return pFile;
	} else{
		free(pFile);
		return NULL;
	}

}

int
Pyros_Get_File_Count(PyrosDB *pyrosDB){
	int filecount = -1;
	sqlite3_stmt **stmts = pyrosDB->commands;

	if (stmts[STMT_QUERY_HASH_COUNT] == NULL)
		sqlPrepareStmt(pyrosDB,"SELECT COUNT(1) FROM hashes",
					   &stmts[STMT_QUERY_HASH_COUNT]);

	sqlStmtGet(stmts[STMT_QUERY_HASH_COUNT],1,SQL_INT,&filecount);

	return filecount;
}

int
Pyros_Get_Tag_Count(PyrosDB *pyrosDB){
	int filecount = -1;
	sqlite3_stmt **stmts = pyrosDB->commands;

	if (stmts[STMT_QUERY_FILE_COUNT] == NULL)
		sqlPrepareStmt(pyrosDB,"SELECT COUNT(1) FROM tag",
					   &stmts[STMT_QUERY_FILE_COUNT]);

	sqlStmtGet(stmts[STMT_QUERY_FILE_COUNT],1,SQL_INT,&filecount);

	return filecount;
}

static PyrosTag*
newPyrosTag(int isAlias,int parent){
	PyrosTag *newTag;

	newTag = malloc(sizeof(*newTag));
	newTag->isAlias = isAlias;
	newTag->par = parent;

	return newTag;
}

void
Pyros_Free_Tag(PyrosTag* tag){
	free(tag->tag);
	free(tag);
}

static void
mergeTagidsIntoPyrosTagList(PyrosDB *pyrosDB,PyrosList *tagids,PyrosList *ptaglist,const char *glob){
	sqlite3_stmt *Get_Ext_Tags;
	PyrosTag *currentTag;

	if (tagids->length == 0)
		return;

	sqlPrepareStmt(pyrosDB,"SELECT tag FROM tag WHERE id=?;",&Get_Ext_Tags);

	for (size_t i = 0; i < tagids->length; i++){
		currentTag = ((PyrosTag*)ptaglist->list[i]);
		if (i == 0 && glob != NULL){
			char *copy;
			copy = malloc(strlen(glob)+1);
			strcpy(copy, glob);
			currentTag->tag = copy;
		} else {
			sqlBind(Get_Ext_Tags,FALSE,1,SQL_INT64P,tagids->list[i]);
			sqlStmtGet(Get_Ext_Tags,1,SQL_CHAR,&currentTag->tag);
		}
	}

	sqlite3_finalize(Get_Ext_Tags);

}

static PyrosList *
getStructuredTags(PyrosDB *pyrosDB,PyrosList *tagids,unsigned int flags){
	PyrosList *structured_tags;
	size_t i;
	size_t lastlength;

	structured_tags = Pyros_Create_List(1,sizeof(PyrosTag*));
	if (tagids->length < 1){
		return structured_tags;
	}

	if (flags & PYROS_GLOB){
		Pyros_List_Append(structured_tags,newPyrosTag(FALSE,-1));
		for (i = 1; i < tagids->length; i++)
			Pyros_List_Append(structured_tags,newPyrosTag(FALSE,0));
	} else {
		for (i = 0; i < tagids->length; i++)
			Pyros_List_Append(structured_tags,newPyrosTag(FALSE,-1));
	}

	lastlength = tagids->length;

	for (i = 0; i < tagids->length; i++){
		if (flags & PYROS_ALIAS){
			PyrosListMerge(tagids,Get_Aliased_Ids(pyrosDB,tagids->list[i]));
			while (lastlength < tagids->length){
				Pyros_List_Append(structured_tags,newPyrosTag(TRUE,i));
				lastlength++;
			}
		}
		if (flags & PYROS_CHILD){
			PyrosListMerge(tagids,Get_Children_Ids(pyrosDB,tagids->list[i]));
			while (lastlength < tagids->length){
				Pyros_List_Append(structured_tags,newPyrosTag(FALSE,i));
				lastlength++;
			}
		}
		if (flags & PYROS_PARENT){
			PyrosListMerge(tagids,Get_Parent_Ids(pyrosDB,tagids->list[i]));
			while (lastlength < tagids->length){
				Pyros_List_Append(structured_tags,newPyrosTag(FALSE,i));
				lastlength++;
			}
		}

	}
	return structured_tags;
}


PyrosList *
Pyros_Get_Ext_Tags_Structured(PyrosDB *pyrosDB, const char *tag,unsigned int flags){
	PyrosList *tagids;
	PyrosList *structured_tags;
	sqlite3_int64 *tagid = NULL;


	if ((flags & PYROS_GLOB) && containsGlobChar(tag)){
		tagids = getTagIdByGlob(pyrosDB,tag);
	} else{
		tagids = Pyros_Create_List(1,sizeof(sqlite3_int64*));
		tagid = getTagId(pyrosDB,tag);
		if (tagid != NULL)
			Pyros_List_Append(tagids,tagid);
		else
			return tagids;
	}

	structured_tags = getStructuredTags(pyrosDB,tagids,flags);
	mergeTagidsIntoPyrosTagList(pyrosDB,tagids,structured_tags,tag);
	Pyros_List_Free(tagids,free);
	return structured_tags;
}

PyrosList *
Pyros_Get_Ext_Tags(PyrosDB *pyrosDB,const char *tag, int showChildren,int ignoreGlobs){
	PyrosList *tagids;
	sqlite3_int64 *tagid = NULL;
	size_t i;
	PyrosList *tags;
	char *cmd;
	sqlite3_stmt *Get_Ext_Tags;

	if (!ignoreGlobs && containsGlobChar(tag)){
		tagids = getTagIdByGlob(pyrosDB,tag);
	} else{
		tagids = Pyros_Create_List(1,sizeof(char*));
		tagid = getTagId(pyrosDB,tag);
		if (tagid != NULL){
			Pyros_List_Append(tagids,tagid);
		}
	}
	for (i = 0; i < tagids->length; i++){
		PyrosListMerge(tagids,Get_Aliased_Ids(pyrosDB,tagids->list[i]));
		if (showChildren)
			PyrosListMerge(tagids,Get_Children_Ids(pyrosDB,tagids->list[i]));
		else
			PyrosListMerge(tagids,Get_Parent_Ids(pyrosDB,tagids->list[i]));
	}
	cmd = malloc(sizeof(*cmd)*(
					 strlen("SELECT tag FROM tag WHERE id IN ();")+
					 (tagids->length*2) + 1));
	strcpy(cmd,"SELECT tag FROM tag WHERE id IN (");

	for (i = 0; i < tagids->length; i++){
		if (i != 0)
			strcat(cmd,",?");
		else
			strcat(cmd,"?");

	}
	strcat(cmd,");");
	sqlPrepareStmt(pyrosDB,cmd,&Get_Ext_Tags);

	sqlBindList(Get_Ext_Tags,tagids,SQL_INT64P);
	tags = sqlStmtGetAll(Get_Ext_Tags,SQL_CHAR);

	free(cmd);
	Pyros_List_Free(tagids,free);
	sqlite3_finalize(Get_Ext_Tags);

	return tags;
}

/*static void
compileTagRelations(PyrosDB *pyrosDB, sqlite3_int64 tagid){
	(void)(pyrosDB);
	printf("%ld\n",sizeof(tagid));

	}*/

void
Pyros_Add_Ext(PyrosDB *pyrosDB,const char *tag1, const char *tag2, int type){
	sqlite3_stmt **stmts = pyrosDB->commands;

	if (!pyrosDB->inTransaction){
		sqlStmtGet(stmts[STMT_BEGIN],0);
		pyrosDB->inTransaction = TRUE;
	}


	if (stmts[STMT_ADD_EXT] == NULL)
		sqlPrepareStmt(pyrosDB,"INSERT OR IGNORE INTO tagrelations "
					   "VALUES((SELECT id FROM tag WHERE tag=?),"
					   "(SELECT id FROM tag WHERE tag=?),?);",
					   &stmts[STMT_ADD_EXT]);


	sqlBind(stmts[STMT_ADD_EXT],TRUE,3,
			SQL_CHAR,tag1,
			SQL_CHAR,tag2,
			SQL_INT,type);

}

static void
Add_Family_Ext(PyrosDB *pyrosDB,int type, const char *tag1, const char *tag2){
	int cmp;

	cmp = strcmp(tag2, tag1);
	if(tag1[0] != '\0' && tag2[0] != '\0' && cmp != 0){
		AddTag(pyrosDB,tag1);
		AddTag(pyrosDB,tag2);
		if (cmp > 0){
			Pyros_Add_Ext(pyrosDB,tag1,tag2,type);
		} else{
			switch (type){
			case TAG_TYPE_CHILD:
				Pyros_Add_Ext(pyrosDB,tag2,tag1,TAG_TYPE_PARENT);
				break;
			case TAG_TYPE_PARENT:
				Pyros_Add_Ext(pyrosDB,tag2,tag1,TAG_TYPE_CHILD);
				break;
			case TAG_TYPE_ALIAS:
				Pyros_Add_Ext(pyrosDB,tag2,tag1,TAG_TYPE_ALIAS);
			}
		}
	}
}

void
Pyros_Add_Alias(PyrosDB *pyrosDB, const char *tag1,const char *tag2){
	Add_Family_Ext(pyrosDB,TAG_TYPE_ALIAS,tag1,tag2);
}

void
Pyros_Add_Parent(PyrosDB *pyrosDB, const char *child, const char *parent){
	Add_Family_Ext(pyrosDB,TAG_TYPE_PARENT,child,parent);
}
void
Pyros_Add_Child(PyrosDB *pyrosDB, const char *parent, const char *child){
	Add_Family_Ext(pyrosDB,TAG_TYPE_CHILD,parent,child);
}
void
Pyros_Remove_Tag_From_Hash(PyrosDB *pyrosDB, const char *hash, const char *tag){
	sqlite3_stmt **stmts = pyrosDB->commands;

	if (!pyrosDB->inTransaction){
		sqlStmtGet(stmts[STMT_BEGIN],0);
		pyrosDB->inTransaction = TRUE;
	}


	if (stmts[STMT_REMOVE_TAG_FROM_FILE] == NULL)
		sqlPrepareStmt(pyrosDB,"DELETE FROM tags WHERE hashid="
					   "(SELECT id FROM hashes WHERE truehash=?) AND "
					   "tagid=(SELECT id FROM tag WHERE tag=TRIM(LOWER(?),'\n\t\r '));",
					   &stmts[STMT_REMOVE_TAG_FROM_FILE]);


	sqlBind(stmts[STMT_REMOVE_TAG_FROM_FILE],TRUE,2,
			SQL_CHAR,hash,
			SQL_CHAR,tag);
}

/* rename to clear_tags_from_hash */
void
Pyros_Remove_Tags_From_Hash(PyrosDB *pyrosDB, const char *hash){
	sqlite3_stmt **stmts = pyrosDB->commands;

	if (!pyrosDB->inTransaction){
		sqlStmtGet(stmts[STMT_BEGIN],0);
		pyrosDB->inTransaction = TRUE;
	}


	if (stmts[STMT_REMOVE_TAGS_FROM_FILE] == NULL)
		sqlPrepareStmt(pyrosDB,"DELETE FROM tags WHERE hashid="
					   "(SELECT id FROM hashes WHERE truehash=TRIM(LOWER(?),'\n\t\r '));",
					   &stmts[STMT_REMOVE_TAGS_FROM_FILE]);


	sqlBind(stmts[STMT_REMOVE_TAGS_FROM_FILE],TRUE,1,
			SQL_CHAR,hash);
}

void
Pyros_Remove_File(PyrosDB *pyrosDB, PyrosFile *pFile){
	sqlite3_stmt **stmts = pyrosDB->commands;


	if (!pyrosDB->inTransaction){
		sqlStmtGet(stmts[STMT_BEGIN],0);
		pyrosDB->inTransaction = TRUE;
	}

	if (stmts[STMT_REMOVE_FILE] == NULL)
		sqlPrepareStmt(pyrosDB,"DELETE FROM hashes WHERE hash=TRIM(LOWER(?),'\n\t\r ');",
					   &stmts[STMT_REMOVE_FILE]);

	Pyros_Remove_Tags_From_Hash(pyrosDB, pFile->hash);

	sqlBind(stmts[STMT_REMOVE_FILE],TRUE,1,
			SQL_CHAR,pFile->hash);

	addHook(pyrosDB,&removeFile,pFile->path,NULL,NULL);
}

void
Pyros_Remove_Ext_Tag(PyrosDB *pyrosDB, const char *tag1, const char *tag2){
	sqlite3_stmt **stmts = pyrosDB->commands;
	int cmp;


	if (!pyrosDB->inTransaction){
		sqlStmtGet(stmts[STMT_BEGIN],0);
		pyrosDB->inTransaction = TRUE;
	}

	if (stmts[STMT_REMOVE_EXT] == NULL)
		sqlPrepareStmt(pyrosDB,"DELETE FROM tagrelations WHERE tag="
					     "(SELECT id FROM tag WHERE tag=?) AND tag2="
					     "(SELECT id FROM tag WHERE tag=?);",
					   &stmts[STMT_REMOVE_EXT]);

	cmp = strcmp(tag2, tag1);
	if(tag1[0] != '\0' && tag2[0] != '\0' && cmp != 0){
		if (cmp > 0){
			sqlBind(stmts[STMT_REMOVE_EXT],TRUE,2,
					SQL_CHAR,tag1,
					SQL_CHAR,tag2);
		} else{
			sqlBind(stmts[STMT_REMOVE_EXT],TRUE,2,
					SQL_CHAR,tag2,
					SQL_CHAR,tag1);
		}
	}
}

void
Pyros_Remove_Dead_Tags(PyrosDB *pyrosDB){
	sqlite3_stmt **stmts = pyrosDB->commands;

	if (!pyrosDB->inTransaction){
		sqlStmtGet(stmts[STMT_BEGIN],0);
		pyrosDB->inTransaction = TRUE;
	}

	/* could be good, could be bad :FeelsDankMan: */
	if (stmts[STMT_REMOVE_DEAD_TAG] == NULL)
		sqlPrepareStmt(pyrosDB,
					   "DELETE FROM tag WHERE"
					   " id NOT IN (SELECT tag FROM tagrelations)"
					   " AND id NOT IN (SELECT tag2 FROM tagrelations)"
					   " AND id NOT IN (SELECT tagid FROM tags)",
					   &stmts[STMT_REMOVE_DEAD_TAG]);

	sqlStmtGet(stmts[STMT_REMOVE_DEAD_TAG], 0);

}

void
Pyros_Merge_Hashes(PyrosDB *pyrosDB, const char *masterHash, const char *hash2){
	sqlite3_stmt **stmts = pyrosDB->commands;

	if (!pyrosDB->inTransaction){
		sqlStmtGet(stmts[STMT_BEGIN],0);
		pyrosDB->inTransaction = TRUE;
	}

	Pyros_Copy_Tags(pyrosDB,hash2,masterHash);

	Pyros_Remove_Tags_From_Hash(pyrosDB, hash2);

	if (stmts[STMT_MERGE_HASH] == NULL)
		sqlPrepareStmt(pyrosDB,"UPDATE hashes SET hash=? WHERE hash=?",
					   &stmts[STMT_MERGE_HASH]);

	sqlBind(stmts[STMT_MERGE_HASH],TRUE,2,
			SQL_CHAR,masterHash,
			SQL_CHAR,hash2);
}

void
Pyros_Copy_Tags(PyrosDB *pyrosDB, const char *hash1, const char *hash2){
	PyrosList *tags;

	tags = Pyros_Get_Tags_From_Hash_Simple(pyrosDB, hash1, FALSE);
	if (tags != NULL){
		Pyros_Add_Tag(pyrosDB, hash2,(char**)tags->list, tags->length);
	}

}
