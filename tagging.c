#include <assert.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "libpyros.h"
#include "pyros.h"
#include "sqlite.h"
#include "str.h"

enum Tag_Relation_Type {
	TAG_TYPE_ALIAS,
	TAG_TYPE_PARENT,
	TAG_TYPE_CHILD,
};

typedef struct PyrosMeta {
	int id;
	char *check1;
	char *check2;
} PyrosMeta;

struct PyrosTagRaw {
	int isAlias;
	int64_t id;
	size_t par;
};

static PyrosTag *newPyrosTag(int isAlias, int parent);
static enum PYROS_ERROR mergeTagidsIntoPyrosTagList(PyrosDB *pyrosDB,
                                                    PyrosList *tagids,
                                                    PyrosList *ptaglist,
                                                    const char *glob);
static PyrosList *getStructuredTags(PyrosDB *pyrosDB, PyrosList *tagids,
                                    unsigned int flags);
static enum PYROS_ERROR createTag(PyrosDB *pyrosDB, const char *tag);
static enum PYROS_ERROR addTagRelation(PyrosDB *pyrosDB, int type,
                                       const char *tag1, const char *tag2);
static enum PYROS_ERROR Pyros_Add_Relation(PyrosDB *pyrosDB, const char *tag1,
                                           const char *tag2, int type);

static PyrosList *getTagsFromTagIdList(PyrosDB *pyrosDB, PyrosList *tagids);
static enum PYROS_ERROR appendStructuredTags(PyrosDB *pyrosDB,
                                             PyrosList *structured_tags,
                                             PyrosList *tagids,
                                             size_t *last_len, int current,
                                             int relation_type, int parent_pos);

static PyrosList *getRelatedTagIds(PyrosDB *pyrosDB, int64_t *tag, int type1,
                                   int type2);
static PyrosList *GetRelatedTags(PyrosDB *pyrosDB, const char *tag,
                                 PyrosList *(*getRelatedIds)());

int64_t
Pyros_Get_Tag_Count(PyrosDB *pyrosDB) {
	int64_t filecount = -1;

	assert(pyrosDB != NULL);
	RETURN_IF_ERR_WRET(pyrosDB, -1);

	if (sqlStmtGetResults(pyrosDB,
	                      sqlGetStmt(pyrosDB, STMT_QUERY_FILE_COUNT),
	                      &filecount) != PYROS_OK)
		return -1;

	return filecount;
}

void
Pyros_Free_Tag(PyrosTag *tag) {
	if (tag == NULL)
		return;
	free(tag->tag);
	free(tag);
}

static PyrosTag *
newPyrosTag(int isAlias, int parent) {
	PyrosTag *newTag;

	newTag = malloc(sizeof(*newTag));
	if (newTag == NULL)
		return NULL;

	newTag->isAlias = isAlias;
	newTag->par = parent;
	newTag->tag = NULL;

	return newTag;
}

static enum PYROS_ERROR
mergeTagidsIntoPyrosTagList(PyrosDB *pyrosDB, PyrosList *tagids,
                            PyrosList *ptaglist, const char *glob) {
	sqlite3_stmt *Get_Relation_Tags;
	PyrosTag *currentTag;
	int has_glob = (glob != NULL);

	if (tagids->length == 0)
		return PYROS_OK;

	if (sqlPrepareStmt(pyrosDB, "SELECT tag FROM tag WHERE id=?;",
	                   &Get_Relation_Tags) != PYROS_OK)
		return pyrosDB->error;

	if (has_glob) {
		currentTag = ((PyrosTag *)ptaglist->list[0]);
		currentTag->tag = duplicate_str(glob);
		if (currentTag->tag == NULL)
			return setError(pyrosDB, PYROS_ERROR_OOM,
			                "Out of memory");
	}

	for (size_t i = 0; i < tagids->length; i++) {
		if (has_glob)
			currentTag = ((PyrosTag *)ptaglist->list[i + 1]);
		else
			currentTag = ((PyrosTag *)ptaglist->list[i]);

		if (sqlBind(pyrosDB, Get_Relation_Tags, FALSE, SQL_INT64P,
		            tagids->list[i]) != PYROS_OK)
			goto error;

		if (sqlStmtGetResults(pyrosDB, Get_Relation_Tags,
		                      &currentTag->tag) != PYROS_OK)
			goto error;
	}

	sqlite3_finalize(Get_Relation_Tags);
	return PYROS_OK;

error:
	return pyrosDB->error;
}

static enum PYROS_ERROR
appendStructuredTags(PyrosDB *pyrosDB, PyrosList *structured_tags,
                     PyrosList *tagids, size_t *last_len, int current,
                     int relation_type, int parent_pos) {
	PyrosTag *tag;
	PyrosList *related_tags;

	switch (relation_type) {
	case PYROS_CHILD:
		related_tags = Get_Children_Ids(pyrosDB, tagids->list[current]);
		break;
	case PYROS_ALIAS:
		related_tags = Get_Aliased_Ids(pyrosDB, tagids->list[current]);
		break;
	case PYROS_PARENT:
		related_tags = Get_Parent_Ids(pyrosDB, tagids->list[current]);
		break;
	default:
		return PYROS_OK;
	}

	if (related_tags == NULL)
		goto error;

	if (PyrosListMerge(tagids, related_tags) != PYROS_OK) {
		Pyros_List_Free(related_tags,
		                (Pyros_Free_Callback)Pyros_Free_Tag);
		goto error_oom;
	}
	for (; *last_len < tagids->length; (*last_len)++) {
		tag = newPyrosTag(relation_type == PYROS_ALIAS, parent_pos);
		if (tag == NULL)
			goto error_oom;

		if (Pyros_List_Append(structured_tags, tag) != PYROS_OK) {
			free(tag);
			goto error_oom;
		}
	}

	return PYROS_OK;
error_oom:
	return setError(pyrosDB, PYROS_ERROR_OOM, "Out of memory");
error:
	return pyrosDB->error;
}

static PyrosList *
getStructuredTags(PyrosDB *pyrosDB, PyrosList *tagids, unsigned int flags) {
	PyrosList *structured_tags;
	PyrosTag *tag;
	size_t i;
	size_t lastlength;
	size_t parent_pos;

	structured_tags = Pyros_Create_List(tagids->length + 1);
	if (structured_tags == NULL)
		goto error_oom;

	if (tagids->length < 1)
		return structured_tags;

	if (flags & PYROS_GLOB) {
		tag = newPyrosTag(FALSE, -1);
		if (tag == NULL)
			goto error_oom;
		Pyros_List_Append(structured_tags, tag);
	}

	for (i = 0; i < tagids->length; i++) {
		tag = newPyrosTag(FALSE, (flags & PYROS_GLOB) ? 0 : -1);
		if (tag == NULL)
			goto error_oom;
		Pyros_List_Append(structured_tags, tag);
	}

	lastlength = tagids->length;

	for (i = 0; i < tagids->length; i++) {

		if (flags & PYROS_GLOB)
			parent_pos = i + 1;
		else
			parent_pos = i;

		if (flags & PYROS_ALIAS)
			if (appendStructuredTags(
			        pyrosDB, structured_tags, tagids, &lastlength,
			        i, PYROS_ALIAS, parent_pos) != PYROS_OK)
				goto error;

		if (flags & PYROS_CHILD)
			if (appendStructuredTags(
			        pyrosDB, structured_tags, tagids, &lastlength,
			        i, PYROS_CHILD, parent_pos) != PYROS_OK)
				goto error;

		if (flags & PYROS_PARENT)
			if (appendStructuredTags(
			        pyrosDB, structured_tags, tagids, &lastlength,
			        i, PYROS_PARENT, parent_pos) != PYROS_OK)
				goto error;
	}
	return structured_tags;

error_oom:
	setError(pyrosDB, PYROS_ERROR_OOM, "Out of memory");
error:
	Pyros_List_Free(structured_tags, (Pyros_Free_Callback)Pyros_Free_Tag);
	return NULL;
}

PyrosList *
Pyros_Get_Related_Tags(PyrosDB *pyrosDB, const char *orig_tag,
                       unsigned int flags) {
	PyrosList *tagids = NULL;
	PyrosList *structured_tags = NULL;
	int64_t *tagid = NULL;
	char *tag;

	assert(pyrosDB != NULL);
	assert(orig_tag != NULL);
	RETURN_IF_ERR_WRET(pyrosDB, NULL);

	tag = str_remove_whitespace(orig_tag);

	if (tag == NULL) {
		setError(pyrosDB, PYROS_ERROR_OOM, "Out of memory");
		return NULL;
	}

	if ((flags & PYROS_GLOB) && containsGlobChar(tag)) {
		tagids = getTagIdByGlob(pyrosDB, tag);

		if (tagids == NULL)
			goto error;
	} else {
		tagids = Pyros_Create_List(1);
		if (tagids == NULL)
			goto error;

		tagid = getTagId(pyrosDB, tag);
		if (tagid == NULL)
			goto error;

		free(tag);
		tag = NULL;

		flags &= ~PYROS_GLOB;
		if (tagid != NULL) {
			if (Pyros_List_Append(tagids, tagid) != PYROS_OK) {
				setError(pyrosDB, PYROS_ERROR_OOM,
				         "Out of memory");
				goto error;
			}
		} else {
			return tagids; /* return empty list */
		}
	}

	structured_tags = getStructuredTags(pyrosDB, tagids, flags);
	if (structured_tags == NULL)
		goto error;

	if (mergeTagidsIntoPyrosTagList(pyrosDB, tagids, structured_tags,
	                                tag) != PYROS_OK)
		goto error;

	Pyros_List_Free(tagids, free);
	free(tag);
	return structured_tags;

error:
	Pyros_List_Free(structured_tags, (Pyros_Free_Callback)Pyros_Free_Tag);
	Pyros_List_Free(tagids, free);
	free(tag);
	return NULL;
}

enum PYROS_ERROR
mergeRelatedTagIds(PyrosDB *pyrosDB, PyrosList *tagids,
                   enum PYROS_TAG_RELATION_FLAGS type) {
	PyrosList *related_tags;
	size_t i;

	for (i = 0; i < tagids->length; i++) {
		if (type & PYROS_ALIAS) {
			related_tags =
			    Get_Aliased_Ids(pyrosDB, tagids->list[i]);
			if (related_tags == NULL)
				goto error;
			if (PyrosListMerge(tagids, related_tags) != PYROS_OK) {
				Pyros_List_Free(related_tags, free);
				return setError(pyrosDB, PYROS_ERROR_OOM,
				                "Out of memory");
			}
		}

		if (type & PYROS_CHILD) {
			related_tags =
			    Get_Children_Ids(pyrosDB, tagids->list[i]);
			if (related_tags == NULL)
				goto error;
			if (PyrosListMerge(tagids, related_tags) != PYROS_OK) {
				Pyros_List_Free(related_tags, free);
				return setError(pyrosDB, PYROS_ERROR_OOM,
				                "Out of memory");
			}
		}

		if (type & PYROS_PARENT) {
			related_tags = Get_Parent_Ids(pyrosDB, tagids->list[i]);
			if (related_tags == NULL)
				goto error;
			if (PyrosListMerge(tagids, related_tags) != PYROS_OK) {
				Pyros_List_Free(related_tags, free);
				return setError(pyrosDB, PYROS_ERROR_OOM,
				                "Out of memory");
			}
		}
	}
	return PYROS_OK;
error:
	return pyrosDB->error;
}

PyrosList *
Pyros_Get_Related_Tags_Simple(PyrosDB *pyrosDB, const char *orig_tag,
                              int showChildren, int ignoreGlobs) {
	PyrosList *tagids = NULL;
	int64_t *tagid = NULL;
	PyrosList *tags;
	char *tag;

	assert(pyrosDB != NULL);
	assert(orig_tag != NULL);
	RETURN_IF_ERR_WRET(pyrosDB, NULL);

	tag = str_remove_whitespace(orig_tag);
	if (tag == NULL) {
		setError(pyrosDB, PYROS_ERROR_OOM, "Out of memory");
		return NULL;
	}

	if (!ignoreGlobs && containsGlobChar(tag)) {
		tagids = getTagIdByGlob(pyrosDB, tag);
		if (tagids == NULL)
			goto error;
	} else {
		tagids = Pyros_Create_List(1);
		if (tagids == NULL)
			goto error;

		tagid = getTagId(pyrosDB, tag);
		if (tagid == NULL) {
			if (pyrosDB->error != PYROS_OK) {
				goto error;
			} else if (Pyros_List_Append(tagids, tagid) !=
			           PYROS_OK) {
				free(tagid);
				goto error;
			}
		}
	}

	if (mergeRelatedTagIds(
	        pyrosDB, tagids,
	        PYROS_ALIAS | (showChildren ? PYROS_CHILD : PYROS_PARENT)) !=
	    PYROS_OK)
		goto error;

	tags = getTagsFromTagIdList(pyrosDB, tagids);
	free(tag);
	Pyros_List_Free(tagids, free);
	return tags;

error:
	free(tag);
	Pyros_List_Free(tagids, free);
	return NULL;
}

static enum PYROS_ERROR
Pyros_Add_Relation(PyrosDB *pyrosDB, const char *tag1, const char *tag2,
                   int type) {
	if (sqlStartTransaction(pyrosDB) != PYROS_OK)
		return pyrosDB->error;

	return sqlBind(pyrosDB, sqlGetStmt(pyrosDB, STMT_ADD_RELATION), TRUE,
	               SQL_CHAR, tag1, SQL_CHAR, tag2, SQL_INT, type);
}

static enum PYROS_ERROR
createTag(PyrosDB *pyrosDB, const char *tag) {
	return sqlBind(pyrosDB, sqlGetStmt(pyrosDB, STMT_ADD_TAG), TRUE,
	               SQL_CHAR, tag);
}

static enum PYROS_ERROR
addTagRelation(PyrosDB *pyrosDB, int type, const char *orig_tag1,
               const char *orig_tag2) {
	int cmp;
	char *tag1;
	char *tag2;

	assert(pyrosDB != NULL);
	assert(orig_tag1 != NULL);
	assert(orig_tag2 != NULL);

	tag1 = str_remove_whitespace(orig_tag1);
	tag2 = str_remove_whitespace(orig_tag2);

	if (tag1 == NULL || tag2 == NULL) {
		setError(pyrosDB, PYROS_ERROR_OOM, "Out of memory");
		goto error;
	}

	cmp = strcmp(tag2, tag1);
	if (tag1[0] != '\0' && tag2[0] != '\0' && cmp != 0) {
		if (createTag(pyrosDB, tag1) != PYROS_OK)
			goto error;
		if (createTag(pyrosDB, tag2) != PYROS_OK)
			goto error;

		if (cmp > 0) {
			if (Pyros_Add_Relation(pyrosDB, tag1, tag2, type) !=
			    PYROS_OK)
				goto error;
		} else {
			if (type == TAG_TYPE_CHILD)
				type = TAG_TYPE_PARENT;
			else if (type == TAG_TYPE_PARENT)
				type = TAG_TYPE_CHILD;

			if (Pyros_Add_Relation(pyrosDB, tag2, tag1, type) !=
			    PYROS_OK)
				goto error;
		}
	}

	free(tag1);
	free(tag2);
	return PYROS_OK;

error:
	free(tag1);
	free(tag2);
	return pyrosDB->error;
}

enum PYROS_ERROR
Pyros_Add_Alias(PyrosDB *pyrosDB, const char *tag1, const char *tag2) {
	return addTagRelation(pyrosDB, TAG_TYPE_ALIAS, tag1, tag2);
}
enum PYROS_ERROR
Pyros_Add_Parent(PyrosDB *pyrosDB, const char *child, const char *parent) {
	return addTagRelation(pyrosDB, TAG_TYPE_PARENT, child, parent);
}
enum PYROS_ERROR
Pyros_Add_Child(PyrosDB *pyrosDB, const char *parent, const char *child) {
	return addTagRelation(pyrosDB, TAG_TYPE_CHILD, parent, child);
}

enum PYROS_ERROR
Pyros_Remove_Tag_From_Hash(PyrosDB *pyrosDB, const char *hash,
                           const char *orig_tag) {
	char *tag;
	int res;

	assert(pyrosDB != NULL);
	assert(hash != NULL);
	assert(orig_tag != NULL);

	tag = str_remove_whitespace(orig_tag);
	if (tag == NULL)
		return setError(pyrosDB, PYROS_ERROR_OOM, "Out of memory");

	if (sqlStartTransaction(pyrosDB) != PYROS_OK)
		return pyrosDB->error;

	res = sqlBind(pyrosDB, sqlGetStmt(pyrosDB, STMT_REMOVE_TAG_FROM_FILE),
	              TRUE, SQL_CHAR, hash, SQL_CHAR, tag);

	free(tag);
	return res;
}

enum PYROS_ERROR
Pyros_Remove_All_Tags_From_Hash(PyrosDB *pyrosDB, const char *hash) {
	assert(hash != NULL);
	assert(pyrosDB != NULL);

	if (sqlStartTransaction(pyrosDB) != PYROS_OK)
		return pyrosDB->error;

	return sqlBind(pyrosDB,
	               sqlGetStmt(pyrosDB, STMT_REMOVE_ALL_TAGS_FROM_FILE),
	               TRUE, SQL_CHAR, hash);
}

enum PYROS_ERROR
Pyros_Add_Tag(PyrosDB *pyrosDB, const char *hash, const char *tags[],
              size_t tagc) {
	size_t i;
	char *tag = NULL;
	int is_anti_tag = FALSE;

	assert(pyrosDB != NULL);

	if (tagc == 0)
		return PYROS_OK;

	assert(tags != NULL);
	assert(hash != NULL);

	if (sqlStartTransaction(pyrosDB) != PYROS_OK)
		goto error;

	for (i = 0; i < tagc; i++) {
		if (tags[i] == NULL)
			continue;
		tag = str_remove_whitespace(tags[i]);
		if (tag == NULL)
			return setError(pyrosDB, PYROS_ERROR_OOM,
			                "Out of memory");
		if (tag[0] != '\0') {
			if (tag[0] == '-')
				is_anti_tag = TRUE;

			if (createTag(pyrosDB, tag + is_anti_tag) != PYROS_OK)
				goto error;

			if (sqlBind(pyrosDB,
			            sqlGetStmt(pyrosDB, STMT_ADD_TAG_TO_FILE),
			            TRUE, SQL_CHAR, hash, SQL_CHAR,
			            tag + is_anti_tag, SQL_INT,
			            is_anti_tag) != PYROS_OK)
				goto error;
		}
		free(tag);
	}

	return PYROS_OK;

error:
	free(tag);
	return pyrosDB->error;
}

PyrosList *
Pyros_Get_All_Tags(PyrosDB *pyrosDB) {
	assert(pyrosDB != NULL);
	RETURN_IF_ERR_WRET(pyrosDB, NULL);
	return sqlStmtGetAll(pyrosDB, sqlGetStmt(pyrosDB, STMT_QUERY_ALL_TAGS));
}

static PyrosList *
getTagsFromTagIdList(PyrosDB *pyrosDB, PyrosList *tagids) {
	PyrosList *tags;
	sqlite3_stmt *Get_Relation_Tags = NULL;
	char *cmd = NULL;
	size_t i;

	cmd = malloc(sizeof(*cmd) *
	             (strlen("SELECT tag FROM tag WHERE id IN ();") +
	              (tagids->length * 2) + 1));
	if (cmd == NULL) {
		setError(pyrosDB, PYROS_ERROR_OOM, "Out of memory");
		goto error;
	}

	strcpy(cmd, "SELECT tag FROM tag WHERE id IN (");
	for (i = 0; i < tagids->length; i++) {
		if (i != 0)
			strcat(cmd, ",?");
		else
			strcat(cmd, "?");
	}
	strcat(cmd, ");");

	if (sqlPrepareStmt(pyrosDB, cmd, &Get_Relation_Tags) != PYROS_OK)
		goto error;

	sqlBindList(Get_Relation_Tags, tagids, SQL_INT64P);

	tags = sqlStmtGetAll(pyrosDB, Get_Relation_Tags);
	if (tags == NULL)
		goto error;

	free(cmd);
	sqlite3_finalize(Get_Relation_Tags);
	return tags;
error:
	free(cmd);
	sqlite3_finalize(Get_Relation_Tags);
	return NULL;
}

PyrosList *
Pyros_Get_Tags_From_Hash_Simple(PyrosDB *pyrosDB, const char *hash,
                                int showRelated) {
	PyrosList *tagids = NULL, *related_tags, *tags;
	size_t i;

	assert(pyrosDB != NULL);
	assert(hash != NULL);
	RETURN_IF_ERR_WRET(pyrosDB, NULL);

	if (sqlBind(pyrosDB, sqlGetStmt(pyrosDB, STMT_QUERY_TAG_BY_HASH), FALSE,
	            SQL_CHAR, hash) != PYROS_OK)
		goto error;

	tagids =
	    sqlStmtGetAll(pyrosDB, sqlGetStmt(pyrosDB, STMT_QUERY_TAG_BY_HASH));

	if (tagids == NULL)
		goto error;

	if (showRelated) {
		for (i = 0; i < tagids->length; i++) {
			related_tags =
			    Get_Aliased_Ids(pyrosDB, tagids->list[i]);
			if (related_tags == NULL)
				goto error;

			if (PyrosStrListMerge(tagids, related_tags) !=
			    PYROS_OK) {
				Pyros_List_Free(related_tags, free);
				goto error;
			}

			related_tags = Get_Parent_Ids(pyrosDB, tagids->list[i]);
			if (related_tags == NULL)
				goto error;

			if (PyrosStrListMerge(tagids, related_tags) !=
			    PYROS_OK) {
				Pyros_List_Free(related_tags, free);
				goto error;
			}
		}
	}

	tags = getTagsFromTagIdList(pyrosDB, tagids);
	Pyros_List_Free(tagids, free);
	return tags;
error:
	Pyros_List_Free(tagids, free);
	return NULL;
}

PyrosList *
Pyros_Get_Tags_From_Hash(PyrosDB *pyrosDB, const char *hash) {
	PyrosList *tags;
	PyrosList *structured_tags;

	assert(pyrosDB != NULL);
	assert(hash != NULL);
	RETURN_IF_ERR_WRET(pyrosDB, NULL);

	if (sqlBind(pyrosDB, sqlGetStmt(pyrosDB, STMT_QUERY_TAG_BY_HASH), FALSE,
	            SQL_CHAR, hash) != PYROS_OK)
		return NULL;

	tags =
	    sqlStmtGetAll(pyrosDB, sqlGetStmt(pyrosDB, STMT_QUERY_TAG_BY_HASH));

	if (tags == NULL)
		return NULL;

	structured_tags =
	    getStructuredTags(pyrosDB, tags, PYROS_FILE_RELATIONSHIP);
	if (structured_tags == NULL) {
		Pyros_List_Free(tags, free);
		return NULL;
	}

	if (mergeTagidsIntoPyrosTagList(pyrosDB, tags, structured_tags, NULL) !=
	    PYROS_OK) {
		Pyros_List_Free(tags, free);
		Pyros_List_Free(structured_tags,
		                (Pyros_Free_Callback)Pyros_Free_Tag);
		return NULL;
	}

	Pyros_List_Free(tags, free);
	return structured_tags;
}

static PyrosList *
getRelatedTagIds(PyrosDB *pyrosDB, int64_t *tag, int type1, int type2) {
	PyrosList *pList = NULL, *pList2;

	if (sqlBind(pyrosDB, sqlGetStmt(pyrosDB, STMT_QUERY_RELATION1), FALSE,
	            SQL_INT, type1, SQL_INT64P, tag) != PYROS_OK)
		goto error;

	pList =
	    sqlStmtGetAll(pyrosDB, sqlGetStmt(pyrosDB, STMT_QUERY_RELATION1));
	if (pList == NULL)
		goto error;

	if (sqlBind(pyrosDB, sqlGetStmt(pyrosDB, STMT_QUERY_RELATION2), FALSE,
	            SQL_INT, type2, SQL_INT64P, tag) != PYROS_OK)
		goto error;

	pList2 =
	    sqlStmtGetAll(pyrosDB, sqlGetStmt(pyrosDB, STMT_QUERY_RELATION2));
	if (pList2 == NULL)
		goto error;

	if (PyrosListMerge(pList, pList2) != PYROS_OK) {
		setError(pyrosDB, PYROS_ERROR_OOM, "Out of memory");
		Pyros_List_Free(pList2, free);
		goto error;
	}

	return pList;

error:
	Pyros_List_Free(pList, free);
	return NULL;
}

PyrosList *
Get_Aliased_Ids(PyrosDB *pyrosDB, int64_t *tag) {
	return getRelatedTagIds(pyrosDB, tag, TAG_TYPE_ALIAS, TAG_TYPE_ALIAS);
}

PyrosList *
Get_Children_Ids(PyrosDB *pyrosDB, int64_t *tag) {
	return getRelatedTagIds(pyrosDB, tag, TAG_TYPE_CHILD, TAG_TYPE_PARENT);
}

PyrosList *
Get_Parent_Ids(PyrosDB *pyrosDB, int64_t *tag) {
	return getRelatedTagIds(pyrosDB, tag, TAG_TYPE_PARENT, TAG_TYPE_CHILD);
}

PyrosList *
getTagIdByGlob(PyrosDB *pyrosDB, const char *tag) {
	if (sqlBind(pyrosDB, sqlGetStmt(pyrosDB, STMT_QUERY_TAG_ID_BY_GLOB),
	            FALSE, SQL_CHAR, tag) != PYROS_OK)
		return NULL;

	return sqlStmtGetAll(pyrosDB,
	                     sqlGetStmt(pyrosDB, STMT_QUERY_TAG_ID_BY_GLOB));
}

int64_t *
getTagId(PyrosDB *pyrosDB, const char *tag) {
	int64_t *ptr_id = NULL;
	int64_t id = -1;

	if (sqlBind(pyrosDB, sqlGetStmt(pyrosDB, STMT_QUERY_TAG_ID), FALSE,
	            SQL_CHAR, tag) != PYROS_OK)
		goto error;

	if (sqlStmtGetResults(pyrosDB, sqlGetStmt(pyrosDB, STMT_QUERY_TAG_ID),
	                      &id) != PYROS_OK)
		goto error;

	if (id == -1)
		return NULL;

	ptr_id = malloc(sizeof(*ptr_id));
	if (ptr_id == NULL) {
		setError(pyrosDB, PYROS_ERROR_OOM, "Out of memory");
		goto error;
	}

	*ptr_id = id;

	return ptr_id;

error:
	return NULL;
}

static PyrosList *
GetRelatedTags(PyrosDB *pyrosDB, const char *tag,
               PyrosList *(*getRelatedIds)()) {
	PyrosList *relatedTags = Pyros_Create_List(1);
	PyrosList *foundTags = NULL;
	char *cmd = NULL;
	int cmdlength;
	int64_t *id;

	size_t i;
	sqlite3_stmt *Get_Tags_From_Ids = NULL;

	assert(tag != NULL);
	assert(pyrosDB != NULL);
	RETURN_IF_ERR_WRET(pyrosDB, NULL);

	id = getTagId(pyrosDB, tag);
	if (id == NULL) {
		if (pyrosDB->error != PYROS_OK)
			return relatedTags;
		else
			goto error;
	}

	if (Pyros_List_Append(relatedTags, id) != PYROS_OK) {
		free(id);
		goto error;
	}

	for (i = 0; i < relatedTags->length; i++) {
		if (PyrosStrListMerge(
		        relatedTags,
		        (*getRelatedIds)(pyrosDB, relatedTags->list[i])) !=
		    PYROS_OK) {
			setError(pyrosDB, PYROS_ERROR_OOM, "Out of memory");
			goto error;
		}
	}

	if (relatedTags->length == 0)
		return relatedTags;

	cmdlength = strlen("SELECT tag FROM tag WHERE id IN ()") + 1 +
	            (relatedTags->length * 2);

	Pyros_List_RShift(&relatedTags, 1, free);

	cmd = malloc(sizeof(*cmd) * cmdlength);

	if (cmd == NULL) {
		setError(pyrosDB, PYROS_ERROR_OOM, "Out of memory");
		goto error;
	}

	strcpy(cmd, "SELECT tag FROM tag WHERE id IN (");

	for (i = 0; i < relatedTags->length; i++) {
		strcat(cmd, "?");
		if (i + 1 < relatedTags->length)
			strcat(cmd, ",");
	}
	strcat(cmd, ")");

	if (sqlPrepareStmt(pyrosDB, cmd, &Get_Tags_From_Ids) != PYROS_OK)
		goto error;

	sqlBindList(Get_Tags_From_Ids, relatedTags, SQL_INT64P);
	foundTags = sqlStmtGetAll(pyrosDB, Get_Tags_From_Ids);

	if (foundTags == NULL) {
		sqlite3_finalize(Get_Tags_From_Ids);
		goto error;
	}

	free(cmd);
	Pyros_List_Free(relatedTags, free);
	sqlite3_finalize(Get_Tags_From_Ids);

	return foundTags;

error:
	free(cmd);
	Pyros_List_Free(relatedTags, free);
	Pyros_List_Free(foundTags, free);
	return NULL;
}

PyrosList *
Pyros_Get_Aliases(PyrosDB *pyrosDB, const char *tag) {
	return GetRelatedTags(pyrosDB, tag, &Get_Aliased_Ids);
}
PyrosList *
Pyros_Get_Parents(PyrosDB *pyrosDB, const char *tag) {
	return GetRelatedTags(pyrosDB, tag, &Get_Parent_Ids);
}
PyrosList *
Pyros_Get_Children(PyrosDB *pyrosDB, const char *tag) {
	return GetRelatedTags(pyrosDB, tag, &Get_Children_Ids);
}

enum PYROS_ERROR
Pyros_Remove_Tag_Relationship(PyrosDB *pyrosDB, const char *tag1,
                              const char *tag2) {
	int cmp;

	assert(pyrosDB != NULL);
	assert(tag1 != NULL);
	assert(tag2 != NULL);
	RETURN_IF_ERR(pyrosDB);

	if (sqlStartTransaction(pyrosDB) != PYROS_OK)
		return pyrosDB->error;

	cmp = strcmp(tag2, tag1);
	if (tag1[0] != '\0' && tag2[0] != '\0' && cmp == 0)
		return PYROS_OK;

	if (cmp > 0)
		return sqlBind(pyrosDB,
		               sqlGetStmt(pyrosDB, STMT_REMOVE_RELATION), TRUE,
		               SQL_CHAR, tag1, SQL_CHAR, tag2);
	else
		return sqlBind(pyrosDB,
		               sqlGetStmt(pyrosDB, STMT_REMOVE_RELATION), TRUE,
		               SQL_CHAR, tag2, SQL_CHAR, tag1);
}

enum PYROS_ERROR
Pyros_Remove_Dead_Tags(PyrosDB *pyrosDB) {
	assert(pyrosDB != NULL);
	RETURN_IF_ERR(pyrosDB);

	if (sqlStartTransaction(pyrosDB) != PYROS_OK)
		return pyrosDB->error;

	return sqlStmtGetResults(pyrosDB,
	                         sqlGetStmt(pyrosDB, STMT_REMOVE_DEAD_TAG));
}

enum PYROS_ERROR
Pyros_Copy_Tags(PyrosDB *pyrosDB, const char *hash1, const char *hash2) {
	PyrosList *tags;

	assert(pyrosDB != NULL);
	assert(hash1 != NULL);
	assert(hash2 != NULL);
	RETURN_IF_ERR(pyrosDB);

	tags = Pyros_Get_Tags_From_Hash_Simple(pyrosDB, hash1, FALSE);

	if (tags == NULL)
		return pyrosDB->error;

	Pyros_Add_Tag(pyrosDB, hash2, (const char **)tags->list, tags->length);
	Pyros_List_Free(tags, free);
	return pyrosDB->error;
}
