#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <magic.h>

#include "pyros.h"
#include "sqlite.h"
#include "hash.h"
#include "database.h"
#include "str.h"
#include "libpyros.h"

#define FILEBUFSIZE 1024

static void importFile( char *file,char *path);
static void removeFile(char *path);
static char *getHash(const char *file,PyrosDB *pyrosDB);
static void getFileExt(char fileext[],const char *file);
static char *getMime(const char *file);
static size_t getFileSize(const char *file);
static int isFile(const char *path);
static enum PYROS_ERROR importTagsFromTagFile(PyrosDB *pyrosDB,char *filepath, PyrosList *tagFileTags);
static int isTagFile(char *filePaths[], size_t filec, size_t p);

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
getFileExt(char fileext[],const char *file){
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


char *
Pyros_Add(PyrosDB *pyrosDB, const char *filePath){
	char *file;
	char *is_merged = NULL;
	size_t filetime;
	size_t filesize;
	char fileext[strlen(filePath)+1];
	char *filehash;
	char *filepath;
	char *filemime;

	sqlite3_stmt **stmts = pyrosDB->commands;

	if (!isFile(filePath)){
		return NULL;
	}


	file = malloc(sizeof(*file)*(strlen(filePath)+1));
	if (file == NULL){
		return NULL;
	}
	strcpy(file,filePath);

	filehash = getHash(file,pyrosDB);
	if (filehash == NULL){
		free(file);
		return NULL;
	}

	is_merged = Pyros_Check_If_Merged(pyrosDB,filehash);
	if (is_merged != NULL){
		free(file);
		return is_merged;
	}

	filemime = getMime(file);
	getFileExt(fileext,file);
	filepath = getFilePath(pyrosDB,filehash,fileext);
	filetime = time(NULL);
	filesize = getFileSize(file);


	sqlStartTransaction(pyrosDB);

	sqlCompileStmt(pyrosDB,STMT_ADD_FILE,
				   "INSERT OR IGNORE INTO hashes "
				   "(hash,import_time,mimetype,ext,filesize) "
				   "VALUES(?,?,?,?,?);");

	sqlBind(stmts[STMT_ADD_FILE],TRUE,5,
			SQL_CHAR,filehash,
			SQL_INT64,filetime,
			SQL_CHAR,filemime,
			SQL_CHAR,fileext,
			SQL_INT64,filesize);

	addHook(pyrosDB,&importFile,file,filepath,&free);

	free(filemime);
	return filehash;
}

static enum PYROS_ERROR
importTagsFromTagFile(PyrosDB *pyrosDB,char *filepath,
					  PyrosList *tagFileTags){
	size_t buf_index = 0;
	size_t buffersize = 20;
	char *tagbuffer = NULL;
	char filebuf[FILEBUFSIZE];
	FILE *tagFile = NULL;
	char lastchar = '\0';

	char *tagFilePath = NULL;

	tagFilePath = malloc(strlen(filepath)+4+1);

	if (tagFilePath == NULL)
		goto error;

	sprintf(tagFilePath,"%s.txt",filepath);

	if (!isFile(tagFilePath)){
		free(tagFilePath);
		return PYROS_OK;
	}


	tagFile = fopen(tagFilePath, "r");
	if (tagFile == NULL){
		perror("Error reading tag file");
		goto error;
	}


	tagbuffer = malloc(buffersize);
	if (tagbuffer == NULL)
		goto error;

	while(fgets(filebuf, FILEBUFSIZE, tagFile) != NULL){
		for (size_t i = 0; i < strlen(filebuf); i++) {
			lastchar = filebuf[i];

			if (filebuf[i] == '\n'){
				tagbuffer[buf_index] = '\0';
				Pyros_List_Append(tagFileTags,tagbuffer);
				tagbuffer = malloc(buffersize);

				buf_index = 0;
				if (tagbuffer == NULL)
					goto error;

			} else {
				tagbuffer[buf_index] = filebuf[i];
				buf_index++;
				if (buf_index+1 >= buffersize){
					buffersize *= 2;
					tagbuffer = realloc(tagbuffer,buffersize);
					if (tagbuffer == NULL)
						goto error;
				}
			}
		}
	}

	if (lastchar != '\n'){
		tagbuffer[buf_index] = '\0';
		Pyros_List_Append(tagFileTags,tagbuffer);
	}else{
		free(tagbuffer);
	}

	fclose(tagFile);

	addHook(pyrosDB,&removeFile,tagFilePath,NULL,free);

	return PYROS_OK;

error:
	free(tagbuffer);
	free(tagFilePath);
	Pyros_List_Free(tagFileTags,free);
	return PYROS_ALLOCATION_ERROR;
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
	PyrosList *files = NULL;
	PyrosList *hashes = NULL;
	PyrosList *tagFileTags = NULL;
	size_t i;
	char *hash;

	files = Pyros_Create_List(filec,sizeof(char*));
	if (files == NULL)
		goto error;

	for (i = 0; i < filec; i++) {
		if (!(useTagfile && isTagFile(filePaths,filec,i))){
			Pyros_List_Append(files,filePaths[i]);
		}
	}

	if (returnHashes){
		hashes = Pyros_Create_List(files->length, sizeof(char*));
		if (hashes == NULL)
			goto error;
	}

	if (useTagfile &&
		(tagFileTags = Pyros_Create_List(1,sizeof(char*))) == NULL)
		goto error;

	for (i = 0; i < files->length; i++) {
		if (useTagfile &&
				importTagsFromTagFile(pyrosDB,files->list[i],
									  tagFileTags) != PYROS_OK){
			continue;
		}

		hash = Pyros_Add(pyrosDB,files->list[i]);
		if (hash != NULL){
			Pyros_Add_Tag(pyrosDB,hash,(char**)tagFileTags->list,
						  tagFileTags->length);

			Pyros_Add_Tag(pyrosDB,hash, (char**)tags, tagc);

			if (callback != NULL)
				(*callback)(hash,files->list[i],i,callback_data);

			if (returnHashes && !PyrosListContainsStr(hashes,hash,NULL))
				Pyros_List_Append(hashes, hash);
			else
				free(hash);
		}
		Pyros_List_Clear(tagFileTags,&free);
	}

	Pyros_List_Free(tagFileTags,&free);
	Pyros_List_Free(files, NULL);

	return hashes;
error:
	Pyros_List_Free(tagFileTags,&free);
	Pyros_List_Free(files, NULL);
	Pyros_List_Free(hashes, NULL);
	return NULL;
}


PyrosList*
Pyros_Get_All_Hashes(PyrosDB *pyrosDB){
	sqlite3_stmt **stmts = pyrosDB->commands;

	sqlCompileStmt(pyrosDB,STMT_QUERY_ALL_HASH,
				   "SELECT hash FROM hashes;");

	return sqlStmtGetAll(stmts[STMT_QUERY_ALL_HASH],SQL_CHAR);
}

PyrosFile *
Pyros_Get_File_From_Hash(PyrosDB *pyrosDB, const char *hash){
	int result;
	sqlite3_stmt **stmts = pyrosDB->commands;
	PyrosFile *pFile;

	if (hash == NULL)
		return NULL;

	pFile = malloc(sizeof(*pFile));
	if (pFile == NULL){
		return NULL;
	}

	sqlCompileStmt(pyrosDB,STMT_QUERY_FILE_FROM_HASH,
				   "SELECT hash,mimetype,ext,import_time,filesize "
				   "FROM hashes WHERE hash=LOWER(?);");



	sqlBind(stmts[STMT_QUERY_FILE_FROM_HASH],FALSE,1,
			SQL_CHAR,hash);

	result = sqlStmtGet(stmts[STMT_QUERY_FILE_FROM_HASH],5,
						SQL_CHAR,&pFile->hash,
						SQL_CHAR,&pFile->mime,
						SQL_CHAR,&pFile->ext,
						SQL_INT64,&pFile->import_time,
						SQL_INT64,&pFile->file_size);

	if (pFile->hash == NULL){
		free(pFile);
		return NULL;
	}

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

	sqlCompileStmt(pyrosDB,STMT_QUERY_HASH_COUNT,"SELECT COUNT(1) FROM hashes");

	sqlStmtGet(stmts[STMT_QUERY_HASH_COUNT],1,SQL_INT,&filecount);

	return filecount;
}

void
Pyros_Remove_File(PyrosDB *pyrosDB, PyrosFile *pFile){
	sqlite3_stmt **stmts = pyrosDB->commands;
	char *file_path;

	if (pFile == NULL)
		return;

	sqlStartTransaction(pyrosDB);

	sqlCompileStmt(pyrosDB,STMT_REMOVE_FILE,
				   "DELETE FROM hashes WHERE hash=LOWER(?);");

	Pyros_Remove_All_Tags_From_Hash(pyrosDB, pFile->hash);

	sqlBind(stmts[STMT_REMOVE_FILE],TRUE,1,
			SQL_CHAR,pFile->hash);

	file_path = malloc(strlen(pFile->path)+1);
	strcpy(file_path,pFile->path);

	addHook(pyrosDB,&removeFile,file_path,NULL,free);
}

void
Pyros_Merge_Hashes(PyrosDB *pyrosDB, const char *masterHash, const char *hash2,int copytags){
	sqlite3_stmt **stmts = pyrosDB->commands;

	if (!strcmp(masterHash,hash2))
		return;

	sqlStartTransaction(pyrosDB);

	if (copytags)
		Pyros_Copy_Tags(pyrosDB,hash2,masterHash);

	sqlCompileStmt(pyrosDB,STMT_MERGE_HASH,
					"INSERT OR IGNORE INTO merged_hashes VALUES(?,?)");

	sqlBind(stmts[STMT_MERGE_HASH],TRUE,2,
			SQL_CHAR,masterHash,
			SQL_CHAR,hash2);

	Pyros_Remove_File(pyrosDB,
					  Pyros_Get_File_From_Hash(pyrosDB, hash2));

	/* if hash2 is a masterhash update all files merged with it to new masterhash*/

	sqlCompileStmt(pyrosDB,STMT_UPDATE_MERGED,
					"UPDATE merged_hashes SET masterfile_hash=? WHERE masterfile_hash=?");

	sqlBind(stmts[STMT_UPDATE_MERGED],TRUE,2,
			SQL_CHAR,masterHash,
			SQL_CHAR,hash2);

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

	*newFile = *pFile;/* for non pointers */
	newFile->ext = NULL;
	newFile->hash = NULL;
	newFile->path = NULL;

	if ((newFile->path = malloc(strlen(pFile->path)+1)) == NULL)
		goto error;

	if ((newFile->hash = malloc(strlen(pFile->hash)+1)) == NULL)
		goto error;

	if ((newFile->ext = malloc(strlen(pFile->ext)+1)) == NULL)
		goto error;

	if ((newFile->mime = malloc(strlen(pFile->mime)+1)) == NULL)
		goto error;

	strcpy(newFile->path,pFile->path);
	strcpy(newFile->hash,pFile->hash);
	strcpy(newFile->ext ,pFile->ext);
	strcpy(newFile->mime,pFile->mime);
	return newFile;
error:
	free(newFile->ext);
	free(newFile->hash);
	free(newFile->path);
	free(newFile);
	return NULL;
}

char*
Pyros_Check_If_Merged(PyrosDB *pyrosDB, const char *filehash){
	sqlite3_stmt **stmts = pyrosDB->commands;
	char *masterhash = NULL;

	sqlCompileStmt(pyrosDB,STMT_QUERY_MERGE_MASTER,
				   "SELECT masterfile_hash FROM merged_hashes WHERE hash=?");

	sqlBind(stmts[STMT_QUERY_MERGE_MASTER], FALSE, 1, SQL_CHAR,filehash);

	sqlStmtGet(stmts[STMT_QUERY_MERGE_MASTER],1,SQL_CHAR,&masterhash);

	return masterhash;
}
