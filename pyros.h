#ifndef PYROS_H
#define PYROS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "stddef.h"
#include <stdint.h>

#define PYROS_VERSION 0
#define PYROS_VERSION_MINOR 1

enum PYROS_ERROR {
	PYROS_OK,
	PYROS_ERROR_OOM,
	PYROS_ERROR_DATABASE,
	PYROS_ERROR_INVALID_ARGUMENT,
};

enum PYROS_HASHTYPE {
	PYROS_UNKOWNHASH = -1,
	PYROS_MD5HASH,
	PYROS_SHA1HASH,
	PYROS_SHA256HASH,
	PYROS_SHA512HASH,
	PYROS_BLAKE2BHASH,
	PYROS_BLAKE2SHASH,
};

enum PYROS_TAG_RELATION_FLAGS {
	PYROS_CHILD = 0x1,
	PYROS_PARENT = 0x2,
	PYROS_ALIAS = 0x4,
	PYROS_GLOB = 0x8,
	PYROS_FILE_RELATIONSHIP = PYROS_ALIAS | PYROS_PARENT,
	PYROS_SEARCH_RELATIONSHIP = PYROS_ALIAS | PYROS_CHILD | PYROS_GLOB,
};

typedef struct PyrosList {
	void **list;
	size_t length;
	size_t size;
	size_t offset;
} PyrosList;

typedef struct PyrosTag {
	int isAlias;
	char *tag;
	size_t par;
} PyrosTag;

typedef struct PyrosDB PyrosDB;

typedef struct PyrosFile {
	char *path;
	char *hash;
	char *ext;
	char *mime;
	int64_t file_size;
	int64_t import_time;
} PyrosFile;

typedef void (*Pyros_Add_Full_Callback)(const char *, const char *, size_t,
                                        void *);
typedef void (*Pyros_Free_Callback)(void *);

static const char PYROS_SEARCH_KEYWORDS[][9] = {
    "limit", "page", "explicit", "ext", "tagcount", "mime", "hash", "order"};

/* Database functions */
PyrosDB *Pyros_Alloc_Database(const char *path);
enum PYROS_ERROR Pyros_Create_Database(PyrosDB *pyrosDB,
                                       enum PYROS_HASHTYPE hashtype);
enum PYROS_ERROR Pyros_Open_Database(PyrosDB *pyrosDB);
enum PYROS_ERROR Pyros_Close_Database(PyrosDB *pyrosDB);
int Pyros_Database_Exists(const char *path);
enum PYROS_ERROR Pyros_Commit(PyrosDB *pyrosDB);
enum PYROS_ERROR Pyros_Rollback(PyrosDB *pyrosDB);
enum PYROS_ERROR Pyros_Vacuum_Database(PyrosDB *pyrosDB);
const char *Pyros_Get_Database_Path(PyrosDB *pyrosDB);
enum PYROS_HASHTYPE Pyros_Get_Hash_Type(PyrosDB *pyrosDB);
enum PYROS_ERROR Pyros_Get_Error_Type(PyrosDB *pyrosDB);
const char *Pyros_Get_Error_Message(PyrosDB *pyrosDB);
void Pyros_Clear_Error(PyrosDB *pyrosDB);

/* PyrosFile functions */
void Pyros_Free_File(PyrosFile *pFile);
PyrosFile *Pyros_Duplicate_File(const PyrosFile *pFile);

/* returns hash of file */
char *Pyros_Add(PyrosDB *pyrosDB, const char *file);
/* returns list of file hashes  */
PyrosList *Pyros_Add_Full(PyrosDB *pyrosDB, const char *filePaths[],
                          size_t filec, const char *tags[], size_t tagc,
                          int useTagfile, int returnHashes,
                          Pyros_Add_Full_Callback, void *callback_data);
enum PYROS_ERROR Pyros_Add_Tag(PyrosDB *pyrosDB, const char *hash,
                               const char *tags[], size_t tagc);

/* PyrosTag functions */
void Pyros_Free_Tag(PyrosTag *tag);

/* query functions*/
PyrosList *Pyros_Search(PyrosDB *pyrosDB, const char **tags, size_t tagc);
PyrosList *Pyros_Get_All_Hashes(PyrosDB *pyrosDB);
PyrosList *Pyros_Get_All_Tags(PyrosDB *pyrosDB);

PyrosList *Pyros_Get_Tags_From_Hash(PyrosDB *pyrosDB, const char *hash);
PyrosList *Pyros_Get_Tags_From_Hash_Simple(PyrosDB *pyrosDB, const char *hash,
                                           int showRelated);
PyrosList *Pyros_Get_Aliases(PyrosDB *pyrosDB, const char *tag);
PyrosList *Pyros_Get_Parents(PyrosDB *pyrosDB, const char *tag);
PyrosList *Pyros_Get_Children(PyrosDB *pyrosDB, const char *tag);
PyrosFile *Pyros_Get_File_From_Hash(PyrosDB *pyrosDB, const char *hash);

int64_t Pyros_Get_File_Count(PyrosDB *pyrosDB);
int64_t Pyros_Get_Tag_Count(PyrosDB *pyrosDB);

/* tag relationship functions*/

PyrosList *Pyros_Get_Related_Tags(PyrosDB *pyrosDB, const char *tag,
                                  unsigned int flags);
PyrosList *Pyros_Get_Related_Tags_Simple(PyrosDB *pyrosDB, const char *tag,
                                         int getChildren, int ignoreGlobs);
enum PYROS_ERROR Pyros_Add_Alias(PyrosDB *pyrosDB, const char *tag,
                                 const char *alias);
enum PYROS_ERROR Pyros_Add_Parent(PyrosDB *pyrosDB, const char *child,
                                  const char *parent);
enum PYROS_ERROR Pyros_Add_Child(PyrosDB *pyrosDB, const char *parent,
                                 const char *child);

/* remove functions */
enum PYROS_ERROR Pyros_Remove_Tag_From_Hash(PyrosDB *pyrosDB, const char *hash,
                                            const char *tag);
enum PYROS_ERROR Pyros_Remove_All_Tags_From_Hash(PyrosDB *pyrosDB,
                                                 const char *hash);
enum PYROS_ERROR Pyros_Remove_File(PyrosDB *pyrosDB, PyrosFile *pFile);
enum PYROS_ERROR Pyros_Remove_Tag_Relationship(PyrosDB *pyrosDB,
                                               const char *tag1,
                                               const char *tag2);
enum PYROS_ERROR Pyros_Remove_Dead_Tags(PyrosDB *pyrosDB);

enum PYROS_ERROR Pyros_Merge_Hashes(PyrosDB *pyrosDB, const char *masterHash,
                                    const char *hash2,
                                    int copy_tags_to_maser_file);

char *Pyros_Check_If_Merged(PyrosDB *pyrosDB, const char *filehash);

enum PYROS_ERROR Pyros_Copy_Tags(PyrosDB *pyrosDB, const char *hash1,
                                 const char *hash2);

/* pyroslist.c */

PyrosList *Pyros_Create_List(int elements);

void Pyros_List_Free(PyrosList *pList, Pyros_Free_Callback);

void Pyros_List_Clear(PyrosList *pList, Pyros_Free_Callback cb);

enum PYROS_ERROR Pyros_List_Shrink(PyrosList *pList);

enum PYROS_ERROR Pyros_List_Grow(PyrosList *pList, size_t requested_len);

enum PYROS_ERROR Pyros_List_Append(PyrosList *pList, const void *ptr);

enum PYROS_ERROR Pyros_List_RShift(PyrosList **pList, size_t shift,
                                   Pyros_Free_Callback cb);

#ifdef __cplusplus
}
#endif

#endif
