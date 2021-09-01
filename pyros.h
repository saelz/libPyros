#ifndef PYROS_H
#define PYROS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "stddef.h"


#define PYROS_VERSION 0
#define PYROS_VERSION_MINOR 1

enum PYROS_ERROR{
	PYROS_OK,
	PYROS_ERR,
	PYROS_DB_ERR,
	PYROS_NOT_FOUND,
	PYROS_ALLOCATION_ERROR
};

enum PYROS_HASHTYPE{
	PYROS_MD5HASH,
	PYROS_SHA1HASH,
	PYROS_SHA256HASH,
	PYROS_SHA512HASH,
	PYROS_BLAKE2BHASH,
	PYROS_BLAKE2SHASH
};

enum PYROS_TAG_RELATION_FLAGS{
	PYROS_CHILD    = 0x1,
	PYROS_PARENT   = 0x2,
	PYROS_ALIAS    = 0x4,
	PYROS_GLOB     = 0x8,
	PYROS_FILE_RELATIONSHIP   = PYROS_ALIAS|PYROS_PARENT,
	PYROS_SEARCH_RELATIONSHIP = PYROS_ALIAS|PYROS_CHILD|PYROS_GLOB,
};

typedef struct PyrosList{
	void **list;
	size_t length;
	size_t size;
	size_t offset;
	int is_unique;
	void (*free_func)();
} PyrosList;

typedef struct PyrosTag{
	int isAlias;
	char *tag;
	size_t par;
}PyrosTag;

typedef struct PyrosDB{
	void *database;
	char *path;
	void *commands;
	PyrosList *hook;
	int is_ext_case_sensitive;/* UNUSED */
	int is_tag_case_sensitive;/* UNUSED */
	int preserve_ext;/* UNUSED */
	int inTransaction;
	int version;
	enum PYROS_HASHTYPE hashtype;
} PyrosDB;

typedef struct PyrosFile{
	char *path;
	char *hash;
	char *ext;
	char *mime;
	size_t file_size;
	size_t import_time;
} PyrosFile;

typedef void (*Pyros_Add_Full_Callback)(char*,char*,size_t,void*);
typedef void (*Pyros_Free_Callback)(void*);

/* PyrosDB functions */
PyrosDB *Pyros_Create_Database(char *path,enum PYROS_HASHTYPE hashtype);
PyrosDB *Pyros_Open_Database(const char *path);
void Pyros_Close_Database(PyrosDB *pyrosDB);
int Pyros_Database_Exists(const char *path);
int Pyros_Commit(PyrosDB *pyrosDB);

/* PyrosFile functions */
void Pyros_Close_File(PyrosFile *pFile);
PyrosFile* Pyros_Duplicate_File(PyrosFile *pFile);

/* returns hash of file */
char *Pyros_Add(PyrosDB *pyrosDB, const char *file);
/* returns list of file hashes  */
PyrosList * Pyros_Add_Full(PyrosDB *pyrosDB, char *filePaths[], size_t filec,char *tags[], size_t tagc, int useTagfile,int returnHashes, Pyros_Add_Full_Callback,void *callback_data);
int Pyros_Add_Tag(PyrosDB *pyrosDB, const char *hash, char *tags[], size_t tagc);

/* PyrosTag functions */
void Pyros_Free_Tag(PyrosTag* tag);

/* query functions*/
PyrosList *Pyros_Search(PyrosDB *pyrosDB, char **tags, size_t tagc);
PyrosList *Pyros_Get_All_Hashes(PyrosDB *pyrosDB);
PyrosList *Pyros_Get_All_Tags(PyrosDB *pyrosDB);

PyrosList *Pyros_Get_Tags_From_Hash(PyrosDB *pyrosDB, const char *hash);
PyrosList *Pyros_Get_Tags_From_Hash_Simple(PyrosDB *pyrosDB, const char *hash,int showRelated);
PyrosList *Pyros_Get_Aliases(PyrosDB *pyrosDB, const char *tag);
PyrosList *Pyros_Get_Parents(PyrosDB *pyrosDB, const char *tag);
PyrosList *Pyros_Get_Children(PyrosDB *pyrosDB,const char *tag);
PyrosFile *Pyros_Get_File_From_Hash(PyrosDB *pyrosDB, const char *hash);

int Pyros_Get_File_Count(PyrosDB *pyrosDB);
int Pyros_Get_Tag_Count(PyrosDB *pyrosDB);

/* tag relationship functions*/

PyrosList *Pyros_Get_Related_Tags(PyrosDB *pyrosDB, const char *tag,
										 unsigned int flags);
PyrosList *Pyros_Get_Related_Tags_Simple(PyrosDB *pyrosDB,const char *tag,
										 int getChildren,int ignoreGlobs);
void Pyros_Add_Alias(PyrosDB *pyrosDB, const char *tag, const char *alias);
void Pyros_Add_Parent(PyrosDB *pyrosDB, const char *child, const char *parent);
void Pyros_Add_Child(PyrosDB *pyrosDB, const char *parent, const char *child);

/* remove functions */
void Pyros_Remove_Tag_From_Hash(PyrosDB *pyrosDB, const char *hash,
								const char *tag);
void Pyros_Remove_All_Tags_From_Hash(PyrosDB *pyrosDB,
									 const char *hash);
void Pyros_Remove_File(PyrosDB *pyrosDB, PyrosFile *pFile);
void Pyros_Remove_Tag_Relationship(PyrosDB *pyrosDB, const char *tag1,
								   const char *tag2);
void Pyros_Remove_Dead_Tags(PyrosDB *pyrosDB);

void Pyros_Merge_Hashes(PyrosDB *pyrosDB, const char *masterHash, const char *hash2, int copy_tags_to_maser_file);

char* Pyros_Check_If_Merged(PyrosDB *pyrosDB, const char *filehash);

void Pyros_Copy_Tags(PyrosDB *pyrosDB, const char *hash1, const char *hash2);

/* pyroslist.c */

PyrosList *Pyros_Create_List(int elements, size_t element_size);

void Pyros_List_Free(PyrosList *pList, Pyros_Free_Callback);

void Pyros_List_Clear(PyrosList *pList, Pyros_Free_Callback cb);

void Pyros_List_Shrink(PyrosList *pList);

enum PYROS_ERROR Pyros_List_Append(PyrosList *pList, void *ptr);

void Pyros_List_RShift(PyrosList **pList, size_t shift);

#ifdef __cplusplus
}
#endif

#endif
