#include <assert.h>
#include <fcntl.h>
#include <magic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "database.h"
#include "hash.h"
#include "libpyros.h"
#include "pyros.h"
#include "sqlite.h"
#include "str.h"

#define FILEBUFSIZE 1024

static void importFile(char *file, char *path);
static void removeFile(char *path);
static const char *getFileExt(const char *file);
static char *getMime(const char *file);
static size_t getFileSize(const char *file);
static int isFile(const char *path);
static enum PYROS_ERROR importTagsFromTagFile(PyrosDB *pyrosDB,
                                              const char *filepath,
                                              PyrosList *tagFileTags);
static int isTagFile(const char *filePaths[], size_t filec, size_t p);

static void
importFile(char *file, char *path) {
	if (access(path, F_OK) != 0 && access(file, R_OK) == 0) {
		rename(file, path);
	}
}

static void
removeFile(char *path) {
	if (access(path, W_OK) == 0)
		remove(path);
}

static const char *
getFileExt(const char *file) {
	size_t i;
	int len = strlen(file);

	for (i = len; i > 0; i--) {
		if (file[i] == '/' || file[i - 1] == '/' || i == 1)
			return &file[len];
		else if (file[i] == '.')
			return &file[i + 1];
	}

	return &file[len];
}

static char *
getMime(const char *file) {
	const char *filemime;
	char *returnMime;
	magic_t magic_cookie;

	magic_cookie = magic_open(MAGIC_MIME_TYPE);
	magic_load(magic_cookie, NULL);

	filemime = magic_file(magic_cookie, file);
	returnMime = duplicate_str(filemime);

	magic_close(magic_cookie);
	return returnMime;
}

static size_t
getFileSize(const char *file) {
	struct stat st;
	stat(file, &st);
	return st.st_size;
}

static int
isFile(const char *path) {
	struct stat statbuf;
	if (stat(path, &statbuf) != 0)
		return 0;
	return S_ISREG(statbuf.st_mode);
}

char *
Pyros_Add(PyrosDB *pyrosDB, const char *filePath) {
	char *file = NULL;
	char *is_merged = NULL;
	size_t filetime;
	size_t filesize;
	const char *fileext;
	char *filehash;
	char *filepath = NULL;
	char *filemime = NULL;

	assert(pyrosDB != NULL);
	assert(pyrosDB->hashtype != PYROS_UNKOWNHASH);
	assert(filePath != NULL);

	RETURN_IF_ERR_WRET(pyrosDB, NULL);

	if (!isFile(filePath)) {
		setError(pyrosDB, PYROS_ERROR_INVALID_ARGUMENT,
		         "File does not exist");
		goto error;
	}

	file = duplicate_str(filePath);
	if (file == NULL)
		goto error_oom;

	filehash = getHash(pyrosDB->hashtype, file);
	if (filehash == NULL)
		goto error_oom;

	is_merged = Pyros_Check_If_Merged(pyrosDB, filehash);
	if (is_merged != NULL) {
		free(file);
		free(filehash);
		return is_merged;
	} else if (pyrosDB->error != PYROS_OK) {
		goto error;
	}

	filemime = getMime(file);
	if (filemime == NULL)
		goto error_oom;

	fileext = getFileExt(file);
	filepath = getFilePath(pyrosDB, filehash, fileext);
	if (filepath == NULL)
		goto error_oom;

	filetime = time(NULL);
	filesize = getFileSize(file);

	if (sqlStartTransaction(pyrosDB) != PYROS_OK)
		goto error;

	if (sqlBind(pyrosDB, sqlGetStmt(pyrosDB, STMT_ADD_FILE), TRUE, SQL_CHAR,
	            filehash, SQL_INT64, filetime, SQL_CHAR, filemime, SQL_CHAR,
	            fileext, SQL_INT64, filesize) != PYROS_OK)
		goto error;

	if (addHook(pyrosDB, &importFile, file, filepath, &free) != PYROS_OK)
		goto error;

	free(filemime);
	return filehash;

error_oom:
	setError(pyrosDB, PYROS_ERROR_OOM, "Out of memory");
error:
	free(filepath);
	free(filehash);
	free(filemime);
	return NULL;
}

static enum PYROS_ERROR
importTagsFromTagFile(PyrosDB *pyrosDB, const char *filepath,
                      PyrosList *tagFileTags) {
	size_t buf_index = 0;
	size_t buffersize = 20;
	char *tagbuffer = NULL;
	char filebuf[FILEBUFSIZE];
	FILE *tagFile = NULL;
	char lastchar = '\0';

	char *tagFilePath = NULL;

	tagFilePath = malloc(strlen(filepath) + 4 + 1);

	if (tagFilePath == NULL)
		goto error;

	strcpy(tagFilePath, filepath);
	strcat(tagFilePath, ".txt");

	tagFile = fopen(tagFilePath, "r");
	if (tagFile == NULL) {
		free(tagFilePath);
		return PYROS_OK;
	}

	tagbuffer = malloc(buffersize);
	if (tagbuffer == NULL)
		goto error;

	while (fgets(filebuf, FILEBUFSIZE, tagFile) != NULL) {
		for (size_t i = 0; i < strlen(filebuf); i++) {
			lastchar = filebuf[i];

			if (filebuf[i] == '\n') {
				tagbuffer[buf_index] = '\0';
				if (Pyros_List_Append(tagFileTags, tagbuffer) !=
				    PYROS_OK)
					goto error;
				tagbuffer = malloc(buffersize);

				buf_index = 0;
				if (tagbuffer == NULL)
					goto error;

			} else {
				tagbuffer[buf_index] = filebuf[i];
				buf_index++;
				if (buf_index + 1 >= buffersize) {
					buffersize *= 2;
					tagbuffer =
					    realloc(tagbuffer, buffersize);
					if (tagbuffer == NULL)
						goto error;
				}
			}
		}
	}

	if (lastchar != '\n') {
		tagbuffer[buf_index] = '\0';
		if (Pyros_List_Append(tagFileTags, tagbuffer) != PYROS_OK)
			goto error;
	} else {
		free(tagbuffer);
	}

	fclose(tagFile);

	if (addHook(pyrosDB, &removeFile, tagFilePath, NULL, free) !=
	    PYROS_OK) {
		free(tagbuffer);
		free(tagFilePath);
		Pyros_List_Free(tagFileTags, free);
		return pyrosDB->error;
	}

	return PYROS_OK;

error:
	fclose(tagFile);
	free(tagbuffer);
	free(tagFilePath);
	Pyros_List_Free(tagFileTags, free);
	return setError(pyrosDB, PYROS_ERROR_OOM, "Out of memory");
}

static int
isTagFile(const char *filePaths[], size_t filec, size_t p) {
	size_t i;
	size_t filelen = strlen(filePaths[p]) - 4;

	/* check if filename ends in .txt*/
	if (filelen < 1 || strcmp(&filePaths[p][filelen], ".txt"))
		return FALSE;

	/* check if another file exists without the '.txt' */
	for (i = 0; i < filec; i++)
		if (p != i && !strncmp(filePaths[p], filePaths[i], filelen))
			return TRUE;

	return FALSE;
}

PyrosList *
Pyros_Add_Full(PyrosDB *pyrosDB, const char *filePaths[], size_t filec,
               const char *tags[], size_t tagc, int useTagfile,
               int returnHashes, Pyros_Add_Full_Callback callback,
               void *callback_data) {
	PyrosList *files = NULL;
	PyrosList *hashes = NULL;
	PyrosList *tagFileTags = NULL;
	size_t i;
	char *hash;

	assert(pyrosDB != NULL);
	RETURN_IF_ERR_WRET(pyrosDB, NULL);

	files = Pyros_Create_List(filec);
	if (files == NULL)
		goto error_oom;

	for (i = 0; i < filec; i++) {
		assert(filePaths[i] != NULL);
		if (!(useTagfile && isTagFile(filePaths, filec, i))) {
			if (Pyros_List_Append(files, filePaths[i]) != PYROS_OK)
				goto error_oom;
		}
	}

	if (returnHashes) {
		hashes = Pyros_Create_List(files->length);
		if (hashes == NULL)
			goto error_oom;
	}

	if (useTagfile && (tagFileTags = Pyros_Create_List(1)) == NULL)
		goto error_oom;

	for (i = 0; i < files->length; i++) {
		if (useTagfile &&
		    importTagsFromTagFile(pyrosDB, files->list[i],
		                          tagFileTags) != PYROS_OK) {
			goto error;
		}

		hash = Pyros_Add(pyrosDB, files->list[i]);
		if (hash != NULL) {
			if (Pyros_Add_Tag(pyrosDB, hash,
			                  (const char **)tagFileTags->list,
			                  tagFileTags->length) != PYROS_OK)
				goto error;

			if (Pyros_Add_Tag(pyrosDB, hash, tags, tagc) !=
			    PYROS_OK)
				goto error;

			if (callback != NULL)
				(*callback)(hash, files->list[i], i,
				            callback_data);

			if (returnHashes &&
			    !PyrosListContainsStr(hashes, hash, NULL)) {
				if (Pyros_List_Append(hashes, hash) != PYROS_OK)
					goto error_oom;
			} else {
				free(hash);
			}
		} else if (pyrosDB->error != PYROS_OK) {
			goto error;
		}

		Pyros_List_Clear(tagFileTags, &free);
	}

	Pyros_List_Free(tagFileTags, &free);
	Pyros_List_Free(files, NULL);

	return hashes;

error_oom:
	setError(pyrosDB, PYROS_ERROR_OOM, "Out of memory");
error:
	Pyros_List_Free(tagFileTags, &free);
	Pyros_List_Free(files, NULL);
	Pyros_List_Free(hashes, NULL);
	return NULL;
}

PyrosList *
Pyros_Get_All_Hashes(PyrosDB *pyrosDB) {
	assert(pyrosDB != NULL);
	RETURN_IF_ERR_WRET(pyrosDB, NULL);

	return sqlStmtGetAll(pyrosDB, sqlGetStmt(pyrosDB, STMT_QUERY_ALL_HASH));
}

PyrosFile *
Pyros_Get_File_From_Hash(PyrosDB *pyrosDB, const char *hash) {
	PyrosFile *pFile;

	assert(pyrosDB != NULL);
	assert(hash != NULL);
	RETURN_IF_ERR_WRET(pyrosDB, NULL);

	pFile = malloc(sizeof(*pFile));
	if (pFile == NULL) {
		setError(pyrosDB, PYROS_ERROR_OOM, "Out of memory");
		goto error;
	}

	if (sqlBind(pyrosDB, sqlGetStmt(pyrosDB, STMT_QUERY_FILE_FROM_HASH),
	            FALSE, SQL_CHAR, hash) != PYROS_OK)
		goto error;

	if (sqlStmtGetResults(
	        pyrosDB, sqlGetStmt(pyrosDB, STMT_QUERY_FILE_FROM_HASH),
	        &pFile->hash, &pFile->mime, &pFile->ext, &pFile->import_time,
	        &pFile->file_size) != PYROS_OK)
		goto error;

	if (pFile->hash == NULL) {
		free(pFile);
		return NULL;
	}

	pFile->path = getFilePath(pyrosDB, pFile->hash, pFile->ext);
	if (pFile->path == NULL)
		goto error;

	return pFile;
error:
	free(pFile);
	return NULL;
}

int64_t
Pyros_Get_File_Count(PyrosDB *pyrosDB) {
	int64_t filecount = -1;

	assert(pyrosDB != NULL);
	RETURN_IF_ERR_WRET(pyrosDB, -1);

	if (sqlStmtGetResults(pyrosDB,
	                      sqlGetStmt(pyrosDB, STMT_QUERY_HASH_COUNT),
	                      &filecount) != PYROS_OK)
		return -1;

	return filecount;
}

enum PYROS_ERROR
Pyros_Remove_File(PyrosDB *pyrosDB, PyrosFile *pFile) {
	char *file_path;

	assert(pyrosDB != NULL);
	assert(pFile != NULL);
	RETURN_IF_ERR(pyrosDB);

	if (sqlStartTransaction(pyrosDB) != PYROS_OK)
		return pyrosDB->error;

	if (Pyros_Remove_All_Tags_From_Hash(pyrosDB, pFile->hash) != PYROS_OK)
		return pyrosDB->error;

	if (sqlBind(pyrosDB, sqlGetStmt(pyrosDB, STMT_REMOVE_FILE), TRUE,
	            SQL_CHAR, pFile->hash) != PYROS_OK)
		return pyrosDB->error;

	file_path = duplicate_str(pFile->path);
	if (file_path == NULL)
		return setError(pyrosDB, PYROS_ERROR_OOM, "Out of memory");

	return addHook(pyrosDB, &removeFile, file_path, NULL, free);
}

enum PYROS_ERROR
Pyros_Merge_Hashes(PyrosDB *pyrosDB, const char *masterHash, const char *hash2,
                   int copytags) {
	PyrosFile *master_file = NULL;
	PyrosFile *file2 = NULL;

	assert(pyrosDB != NULL);
	assert(masterHash != NULL);
	assert(hash2 != NULL);
	RETURN_IF_ERR(pyrosDB);

	file2 = Pyros_Get_File_From_Hash(pyrosDB, hash2);
	if (file2 == NULL)
		goto error;

	master_file = Pyros_Get_File_From_Hash(pyrosDB, hash2);
	if (master_file == NULL)
		goto error;

	if (!strcmp(master_file->hash, file2->hash))
		goto error; /* should return PYROS_OK */

	if (sqlStartTransaction(pyrosDB) != PYROS_OK)
		goto error;

	if (copytags && Pyros_Copy_Tags(pyrosDB, file2->hash,
	                                master_file->hash) != PYROS_OK)
		goto error;

	if (sqlBind(pyrosDB, sqlGetStmt(pyrosDB, STMT_MERGE_HASH), TRUE,
	            SQL_CHAR, master_file->hash, SQL_CHAR,
	            file2->hash) != PYROS_OK)
		goto error;

	Pyros_Free_File(master_file);

	/* if hash2 is a masterhash update all files merged with it to new
	 * masterhash*/

	if (sqlBind(pyrosDB, sqlGetStmt(pyrosDB, STMT_UPDATE_MERGED), TRUE,
	            SQL_CHAR, masterHash, SQL_CHAR, file2->hash) != PYROS_OK) {
		Pyros_Free_File(file2);
		return pyrosDB->error;
	}
	if (Pyros_Remove_File(pyrosDB, file2) != PYROS_OK)
		return pyrosDB->error;

	return PYROS_OK;
error:
	Pyros_Free_File(file2);
	Pyros_Free_File(master_file);
	return pyrosDB->error;
}

void
Pyros_Free_File(PyrosFile *pFile) {
	if (pFile == NULL)
		return;
	free(pFile->hash);
	free(pFile->mime);
	free(pFile->ext);
	free(pFile->path);
	free(pFile);
}

PyrosFile *
Pyros_Duplicate_File(const PyrosFile *pFile) {
	PyrosFile *newFile;

	assert(pFile != NULL);

	newFile = malloc(sizeof(*newFile));
	if (newFile == NULL)
		return NULL;

	*newFile = *pFile; /* copy non-pointer values */
	newFile->ext = duplicate_str(pFile->ext);
	newFile->mime = duplicate_str(pFile->mime);
	newFile->hash = duplicate_str(pFile->hash);
	newFile->path = duplicate_str(pFile->path);

	if (newFile->path == NULL || newFile->hash == NULL ||
	    newFile->ext == NULL || newFile->mime == NULL) {
		Pyros_Free_File(newFile);
		return NULL;
	}

	return newFile;
}

char *
Pyros_Check_If_Merged(PyrosDB *pyrosDB, const char *filehash) {
	char *masterhash = NULL;

	assert(pyrosDB != NULL);
	assert(filehash != NULL);
	RETURN_IF_ERR_WRET(pyrosDB, NULL);

	if (sqlBind(pyrosDB, sqlGetStmt(pyrosDB, STMT_QUERY_MERGE_MASTER),
	            FALSE, SQL_CHAR, filehash) != PYROS_OK)
		return NULL;

	if (sqlStmtGetResults(pyrosDB,
	                      sqlGetStmt(pyrosDB, STMT_QUERY_MERGE_MASTER),
	                      &masterhash) != PYROS_OK)
		return NULL;

	return masterhash;
}
