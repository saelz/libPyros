#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

#include "pyros.h"
#include "str.h"
#include "sqlite.h"
#include "libpyros.h"

enum Tag_Relation_Type{
	TAG_TYPE_ALIAS,
	TAG_TYPE_PARENT,
	TAG_TYPE_CHILD,
};

typedef struct PyrosMeta{
	int id;
	char *check1;
	char *check2;
} PyrosMeta;

struct PyrosTagRaw{
	int isAlias;
	sqlite3_int64 id;
	size_t par;
};


static PyrosTag* newPyrosTag(int isAlias,int parent);
static void mergeTagidsIntoPyrosTagList(PyrosDB *pyrosDB,PyrosList *tagids,
							PyrosList *ptaglist,const char *glob);
static PyrosList * getStructuredTags(PyrosDB *pyrosDB,PyrosList *tagids,
									 unsigned int flags);
static void createTag(PyrosDB *pyrosDB, const char* tag);
static void addTagRelation(PyrosDB *pyrosDB,int type,
						   const char *tag1, const char *tag2);

int
Pyros_Get_Tag_Count(PyrosDB *pyrosDB){
	int filecount = -1;
	sqlite3_stmt **stmts = pyrosDB->commands;

	sqlCompileStmt(pyrosDB, STMT_QUERY_FILE_COUNT,
				   "SELECT COUNT(1) FROM tag");

	sqlStmtGet(stmts[STMT_QUERY_FILE_COUNT],1,SQL_INT,&filecount);

	return filecount;
}

void
Pyros_Free_Tag(PyrosTag* tag){
	free(tag->tag);
	free(tag);
}

static PyrosTag*
newPyrosTag(int isAlias,int parent){
	PyrosTag *newTag;

	newTag = malloc(sizeof(*newTag));
	newTag->isAlias = isAlias;
	newTag->par = parent;

	return newTag;
}

static void
mergeTagidsIntoPyrosTagList(PyrosDB *pyrosDB,PyrosList *tagids,
							PyrosList *ptaglist,const char *glob){
	sqlite3_stmt *Get_Relation_Tags;
	PyrosTag *currentTag;

	if (tagids->length == 0)
		return;

	sqlPrepareStmt(pyrosDB,"SELECT tag FROM tag WHERE id=?;",&Get_Relation_Tags);

	for (size_t i = 0; i < tagids->length; i++){
		currentTag = ((PyrosTag*)ptaglist->list[i]);
		if (i == 0 && glob != NULL){
			char *copy;
			copy = malloc(strlen(glob)+1);
			strcpy(copy, glob);
			currentTag->tag = copy;
		} else {
			sqlBind(Get_Relation_Tags,FALSE,1,SQL_INT64P,tagids->list[i]);
			sqlStmtGet(Get_Relation_Tags,1,SQL_CHAR,&currentTag->tag);
		}
	}

	sqlite3_finalize(Get_Relation_Tags);

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
Pyros_Get_Related_Tags(PyrosDB *pyrosDB, const char *tag,unsigned int flags){
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
Pyros_Get_Related_Tags_Simple(PyrosDB *pyrosDB,const char *tag, int showChildren,
				   int ignoreGlobs){
	PyrosList *tagids;
	sqlite3_int64 *tagid = NULL;
	size_t i;
	PyrosList *tags;
	char *cmd;
	sqlite3_stmt *Get_Relation_Tags;

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
	sqlPrepareStmt(pyrosDB,cmd,&Get_Relation_Tags);

	sqlBindList(Get_Relation_Tags,tagids,SQL_INT64P);
	tags = sqlStmtGetAll(Get_Relation_Tags,SQL_CHAR);

	free(cmd);
	Pyros_List_Free(tagids,free);
	sqlite3_finalize(Get_Relation_Tags);

	return tags;
}

void
Pyros_Add_Relation(PyrosDB *pyrosDB,const char *tag1, const char *tag2, int type){
	sqlite3_stmt **stmts = pyrosDB->commands;

	sqlStartTransaction(pyrosDB);

	sqlCompileStmt(pyrosDB, STMT_ADD_RELATION,
				   "INSERT OR IGNORE INTO tagrelations "
				   "VALUES((SELECT id FROM tag WHERE tag=?),"
				    "(SELECT id FROM tag WHERE tag=?),?);");


	sqlBind(stmts[STMT_ADD_RELATION],TRUE,3,
			SQL_CHAR,tag1,
			SQL_CHAR,tag2,
			SQL_INT,type);

}

static void
createTag(PyrosDB *pyrosDB, const char* tag){
	sqlite3_stmt **stmts = pyrosDB->commands;

	sqlCompileStmt(pyrosDB, STMT_ADD_TAG,
				   "INSERT OR IGNORE INTO tag(tag) VALUES(TRIM(LOWER(?),'\n\t\r '));");

	sqlBind(stmts[STMT_ADD_TAG],TRUE,1,SQL_CHAR,tag);
}

static void
addTagRelation(PyrosDB *pyrosDB,int type, const char *tag1, const char *tag2){
	int cmp;

	cmp = strcmp(tag2, tag1);
	if(tag1[0] != '\0' && tag2[0] != '\0' && cmp != 0){
		createTag(pyrosDB,tag1);
		createTag(pyrosDB,tag2);
		if (cmp > 0){
			Pyros_Add_Relation(pyrosDB,tag1,tag2,type);
		} else{
			switch (type){
			case TAG_TYPE_CHILD:
				Pyros_Add_Relation(pyrosDB,tag2,tag1,TAG_TYPE_PARENT);
				break;
			case TAG_TYPE_PARENT:
				Pyros_Add_Relation(pyrosDB,tag2,tag1,TAG_TYPE_CHILD);
				break;
			case TAG_TYPE_ALIAS:
				Pyros_Add_Relation(pyrosDB,tag2,tag1,TAG_TYPE_ALIAS);
			}
		}
	}
}

void
Pyros_Add_Alias(PyrosDB *pyrosDB, const char *tag1,const char *tag2){
	addTagRelation(pyrosDB,TAG_TYPE_ALIAS,tag1,tag2);
}
void
Pyros_Add_Parent(PyrosDB *pyrosDB, const char *child, const char *parent){
	addTagRelation(pyrosDB,TAG_TYPE_PARENT,child,parent);
}
void
Pyros_Add_Child(PyrosDB *pyrosDB, const char *parent, const char *child){
	addTagRelation(pyrosDB,TAG_TYPE_CHILD,parent,child);
}

void
Pyros_Remove_Tag_From_Hash(PyrosDB *pyrosDB, const char *hash, const char *tag){
	sqlite3_stmt **stmts = pyrosDB->commands;

	sqlStartTransaction(pyrosDB);

	sqlCompileStmt(pyrosDB, STMT_REMOVE_TAG_FROM_FILE,
				   "DELETE FROM tags WHERE hashid="
				   "(SELECT id FROM hashes WHERE truehash=?) AND "
				   "tagid=(SELECT id FROM tag WHERE tag=TRIM(LOWER(?),'\n\t\r '));");


	sqlBind(stmts[STMT_REMOVE_TAG_FROM_FILE],TRUE,2,
			SQL_CHAR,hash,
			SQL_CHAR,tag);
}

void
Pyros_Remove_All_Tags_From_Hash(PyrosDB *pyrosDB, const char *hash){
	sqlite3_stmt **stmts = pyrosDB->commands;

	sqlStartTransaction(pyrosDB);

	sqlCompileStmt(pyrosDB, STMT_REMOVE_TAGS_FROM_FILE,
				   "DELETE FROM tags WHERE hashid="
				   "(SELECT id FROM hashes WHERE truehash=TRIM(LOWER(?),'\n\t\r '));");


	sqlBind(stmts[STMT_REMOVE_TAGS_FROM_FILE],TRUE,1,
			SQL_CHAR,hash);
}

int
Pyros_Add_Tag(PyrosDB *pyrosDB, const char *hash, char *tags[], size_t tagc){
	size_t i;

	sqlite3_stmt **stmts = pyrosDB->commands;

	if (tagc == 0)
		return PYROS_OK;

	sqlStartTransaction(pyrosDB);

	sqlCompileStmt(pyrosDB,STMT_ADD_TAG_TO_FILE,
				   "INSERT OR IGNORE INTO tags VALUES("
				   "(SELECT id FROM hashes WHERE truehash=LOWER(?)),"
				   "(SELECT id FROM tag WHERE tag=TRIM(LOWER(?),'\n\t\r ')),?);");

	for (i = 0;i < tagc;i++){
		if (tags[i][0] != '\0'){
			if (tags[i][0] == '-'){
				createTag(pyrosDB,&tags[i][1]);
				sqlBind(stmts[STMT_ADD_TAG_TO_FILE],TRUE,3,
						SQL_CHAR,hash,
						SQL_CHAR,&tags[i][1],
						SQL_INT, TRUE);

			} else{
				createTag(pyrosDB,tags[i]);
				sqlBind(stmts[STMT_ADD_TAG_TO_FILE],TRUE,3,
						SQL_CHAR,hash,
						SQL_CHAR,tags[i],
						SQL_INT, FALSE);
			}
		}
	}
	return PYROS_OK;
}

PyrosList*
Pyros_Get_All_Tags(PyrosDB *pyrosDB){
	sqlite3_stmt **stmts = pyrosDB->commands;
	sqlCompileStmt(pyrosDB,STMT_QUERY_ALL_TAGS,"SELECT tag FROM tag;");

	return sqlStmtGetAll(stmts[STMT_QUERY_ALL_TAGS],SQL_CHAR);
}

PyrosList *
Pyros_Get_Tags_From_Hash_Simple(PyrosDB *pyrosDB, const char *hash,
								int showRelated){
	PyrosList *tags;
	PyrosList *final_tags;
	size_t i;
	char *cmd;
	int cmdlength;

	sqlite3_stmt **stmts = pyrosDB->commands;
	sqlite3_stmt *Query_Tag_By_Id;

	sqlCompileStmt(pyrosDB,STMT_QUERY_TAG_BY_HASH,
				   "SELECT tagid FROM tags WHERE hashid="
				    "(SELECT id FROM hashes WHERE hash=?) AND isantitag=0;");

	sqlBind(stmts[STMT_QUERY_TAG_BY_HASH],FALSE,1,SQL_CHAR,hash);


	tags = sqlStmtGetAll(stmts[STMT_QUERY_TAG_BY_HASH],SQL_INT64P);

	if (tags == NULL)
		return NULL;

	cmdlength = strlen("SELECT tag FROM tag WHERE id IN () ORDER BY tag")+1;
	for (i = 0; i < tags->length; i++) {
		if (showRelated){
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

	sqlCompileStmt(pyrosDB,STMT_QUERY_TAG_BY_HASH,
				   "SELECT tagid FROM tags WHERE hashid="
				   "(SELECT id FROM hashes WHERE truehash=?) AND isantitag=0;");

	sqlBind(stmts[STMT_QUERY_TAG_BY_HASH],FALSE,1,SQL_CHAR,hash);


	tags = sqlStmtGetAll(stmts[STMT_QUERY_TAG_BY_HASH],SQL_INT64P);

	if (tags == NULL)
		return NULL;

	structured_tags = getStructuredTags(pyrosDB,tags,PYROS_FILE_RELATIONSHIP);
	mergeTagidsIntoPyrosTagList(pyrosDB,tags,structured_tags,NULL);
	Pyros_List_Free(tags,free);
	return structured_tags;
}

PyrosList *
getRelatedTagIds(PyrosDB *pyrosDB, sqlite3_int64 *tag, int type1, int type2){
	sqlite3_stmt **stmts = pyrosDB->commands;
	PyrosList *pList;

	sqlCompileStmt(pyrosDB,STMT_QUERY_RELATION1,
				   "SELECT tag2 FROM tagrelations "
				   "WHERE type=? AND tag=?;");
	sqlCompileStmt(pyrosDB,STMT_QUERY_RELATION2,
				   "SELECT tag FROM tagrelations "
				   "WHERE type=? AND tag2=?;");

	sqlBind(stmts[STMT_QUERY_RELATION1],FALSE,2,
			SQL_INT ,type1,
			SQL_INT64P,tag);

	pList = sqlStmtGetAll(stmts[STMT_QUERY_RELATION1],SQL_INT64P);
	sqlBind(stmts[STMT_QUERY_RELATION2],FALSE,2,
			SQL_INT ,type2,
			SQL_INT64P,tag);

	PyrosListMerge(pList,sqlStmtGetAll(stmts[STMT_QUERY_RELATION2],SQL_INT64P));

	return pList;
}

PyrosList *
Get_Aliased_Ids(PyrosDB *pyrosDB, sqlite3_int64 *tag){
	return getRelatedTagIds(pyrosDB,tag,TAG_TYPE_ALIAS,TAG_TYPE_ALIAS);

}

PyrosList *
Get_Children_Ids(PyrosDB *pyrosDB, sqlite3_int64 *tag){
	return getRelatedTagIds(pyrosDB,tag,TAG_TYPE_CHILD,TAG_TYPE_PARENT);
}

PyrosList *
Get_Parent_Ids(PyrosDB *pyrosDB, sqlite3_int64 *tag){
	return getRelatedTagIds(pyrosDB,tag,TAG_TYPE_PARENT,TAG_TYPE_CHILD);
}

PyrosList *
getTagIdByGlob(PyrosDB *pyrosDB,const char *tag){
	sqlite3_stmt **stmts = pyrosDB->commands;

	sqlCompileStmt(pyrosDB,STMT_QUERY_TAG_ID_BY_GLOB,
				   "SELECT id FROM tag WHERE tag GLOB TRIM(LOWER(?),'\n\t\r ');");

	sqlBind(stmts[STMT_QUERY_TAG_ID_BY_GLOB],FALSE,1,
			SQL_CHAR,tag);


	return sqlStmtGetAll(stmts[STMT_QUERY_TAG_ID_BY_GLOB],SQL_INT64P);
}

sqlite3_int64*
getTagId(PyrosDB *pyrosDB,const char *tag){
	sqlite3_int64 *id = NULL;
	sqlite3_stmt **stmts = pyrosDB->commands;

	sqlCompileStmt(pyrosDB,STMT_QUERY_TAG_ID,
				   "SELECT id FROM tag WHERE tag=TRIM(LOWER(?),'\n\t\r ');");

	sqlBind(stmts[STMT_QUERY_TAG_ID],FALSE,1,
			SQL_CHAR,tag);

	sqlStmtGet(stmts[STMT_QUERY_TAG_ID],1,SQL_INT64P,&id);

	return id;
}

PyrosList *
GetRelatedTags(PyrosDB *pyrosDB, const char *tag,PyrosList *(*getRelatedIds)()){
	PyrosList *relatedTags = Pyros_Create_List(1,sizeof(char*));
	PyrosList *foundTags;
	char *cmd;
	int cmdlength;
	sqlite3_int64 *id;

	size_t i;
	sqlite3_stmt *Get_Tags_From_Ids;

	id = getTagId(pyrosDB,tag);
	if (id == NULL)
		return relatedTags;

	Pyros_List_Append(relatedTags,id);

	cmdlength = strlen("SELECT tag FROM tag WHERE id IN ()")+1;
	for (i = 0; i < relatedTags->length; i++){
		PyrosStrListMerge(relatedTags,
						  (*getRelatedIds)(pyrosDB,relatedTags->list[i]));
		cmdlength += 2;
	}

	Pyros_List_RShift(&relatedTags,1);
	if (relatedTags->length == 0)
		return relatedTags;

	/* BAD MALLOC */
	cmd = malloc(sizeof(*cmd)*cmdlength);
	strcpy(cmd,"SELECT tag FROM tag WHERE id IN (");

	for (i = 0; i < relatedTags->length; i++){
		strcat(cmd,"?");
		if (i+1 < relatedTags->length)
			strcat(cmd,",");
	}
	strcat(cmd,")");
	sqlPrepareStmt(pyrosDB,cmd,&Get_Tags_From_Ids);


	sqlBindList(Get_Tags_From_Ids,relatedTags,SQL_INT64P);
	foundTags = sqlStmtGetAll(Get_Tags_From_Ids,SQL_CHAR);

	free(cmd);
	Pyros_List_Free(relatedTags,free);
	sqlite3_finalize(Get_Tags_From_Ids);


	return foundTags;
}

PyrosList *
Pyros_Get_Aliases(PyrosDB *pyrosDB, const char *tag){
	return GetRelatedTags(pyrosDB,tag,&Get_Aliased_Ids);
}
PyrosList *
Pyros_Get_Parents(PyrosDB *pyrosDB, const char *tag){
	return GetRelatedTags(pyrosDB,tag,&Get_Parent_Ids);
}
PyrosList *
Pyros_Get_Children(PyrosDB *pyrosDB, const char *tag){
	return GetRelatedTags(pyrosDB,tag,&Get_Children_Ids);
}

void
Pyros_Remove_Tag_Relationship(PyrosDB *pyrosDB, const char *tag1, const char *tag2){
	sqlite3_stmt **stmts = pyrosDB->commands;
	int cmp;


	sqlStartTransaction(pyrosDB);

	sqlCompileStmt(pyrosDB,STMT_REMOVE_RELATION,
				   "DELETE FROM tagrelations WHERE tag="
				   "(SELECT id FROM tag WHERE tag=?) AND tag2="
				   "(SELECT id FROM tag WHERE tag=?);");

	cmp = strcmp(tag2, tag1);
	if(tag1[0] != '\0' && tag2[0] != '\0' && cmp != 0){
		if (cmp > 0){
			sqlBind(stmts[STMT_REMOVE_RELATION],TRUE,2,
					SQL_CHAR,tag1,
					SQL_CHAR,tag2);
		} else{
			sqlBind(stmts[STMT_REMOVE_RELATION],TRUE,2,
					SQL_CHAR,tag2,
					SQL_CHAR,tag1);
		}
	}
}

void
Pyros_Remove_Dead_Tags(PyrosDB *pyrosDB){
	sqlite3_stmt **stmts = pyrosDB->commands;

	sqlStartTransaction(pyrosDB);

	sqlCompileStmt(pyrosDB,STMT_REMOVE_DEAD_TAG,
				   "DELETE FROM tag WHERE"
				   " id NOT IN (SELECT tag FROM tagrelations)"
				   " AND id NOT IN (SELECT tag2 FROM tagrelations)"
				   " AND id NOT IN (SELECT tagid FROM tags)");

	sqlStmtGet(stmts[STMT_REMOVE_DEAD_TAG], 0);

}

void
Pyros_Copy_Tags(PyrosDB *pyrosDB, const char *hash1, const char *hash2){
	PyrosList *tags = Pyros_Get_Tags_From_Hash_Simple(pyrosDB, hash1, FALSE);

	if (tags != NULL)
		Pyros_Add_Tag(pyrosDB, hash2,(char**)tags->list, tags->length);
}
