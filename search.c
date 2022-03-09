#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "libpyros.h"
#include "pyros.h"
#include "search.h"
#include "sqlite.h"
#include "str.h"

static int create_minmax(const char *str, struct minmax *stat);

static PrcsTags *ProcessTags(PyrosDB *pyrosDB, PyrosList *tags,
                             querySettings *qSet);

static enum PYROS_ERROR catTagGroup(char **str, PrcsTags prcsTags,
                                    querySettings *qSet);
static enum PYROS_ERROR catStatGroup(char **str, PrcsTags prcsTags);
static enum PYROS_ERROR catMetaGroup(char **str, PrcsTags prcsTags,
                                     char *label);
static enum PYROS_ERROR catMetaQuery(char **str, PrcsTags prcsTags,
                                     char *src_query_column,
                                     char *return_column, char *table,
                                     char *query_column);
static void reorderProcessedTags(PrcsTags **prcsTags, size_t tag_count,
                                 querySettings *qSet);

static int
create_minmax(const char *str, struct minmax *stat) {
	switch (str[0]) {
	case '\0':
		return FALSE;
	case '<':
		stat->max = atoi(&str[1]);
		stat->min = -1;
		break;
	case '>':
		stat->max = -1;
		stat->min = atoi(&str[1]);
		break;
	case '=':
		stat->min = atoi(&str[1]);
		stat->max = atoi(&str[1]);
		break;
	default:
		stat->min = atoi(str);
		stat->max = atoi(str);
		break;
	}
	return TRUE;
}

static PrcsTags *
ProcessTags(PyrosDB *pyrosDB, PyrosList *tags, querySettings *qSet) {
	size_t i, j;
	int64_t *tagid;
	char *tag;

	PrcsTags *prcsTags = malloc(sizeof(*prcsTags) * (tags->length));

	if (prcsTags == NULL) {
		setError(pyrosDB, PYROS_ERROR_OOM, "Out of memory");
		return NULL;
	}

	for (i = 0; i < tags->length; i++) {
		prcsTags[i].type = TT_NORMAL;

		if (((char *)tags->list[i])[0] == '-') {
			prcsTags[i].filtered = TRUE;
			tag = &((char *)tags->list[i])[1];
		} else {
			prcsTags[i].filtered = FALSE;
			tag = tags->list[i];
		}

		/* skip empty string */
		if (tag[0] == '\0') {
			prcsTags[i].type = TT_IGNORE;
			continue;
		}

		/* skips duplicate tags */
		for (j = 0; j < i; j++) {
			if (strcmp(tag, tags->list[j]) == 0) {
				prcsTags[i].type = TT_IGNORE;
				break;
			}
		}

		if (prcsTags[i].type == TT_IGNORE) {
			continue;
		} else if (strcmp("*", tag) == 0) {
			prcsTags[i].type = TT_ALL;

			if (prcsTags[i].filtered) /* if tag == -* */
				goto noresults;

		} else if (strncmp("hash:", tag, 5) == 0) {
			prcsTags[i].type = TT_HASH;
			prcsTags[i].meta.text = &tag[5];
			qSet->meta_group_count++;

		} else if (strncmp("mime:", tag, 5) == 0) {
			prcsTags[i].type = TT_MIME;
			prcsTags[i].meta.text = &tag[5];
			qSet->meta_group_count++;

		} else if (strncmp("ext:", tag, 4) == 0) {
			prcsTags[i].type = TT_EXT;
			prcsTags[i].meta.text = &tag[4];
			qSet->meta_group_count++;

		} else if (strncmp("tagcount:", tag, 9) == 0) {
			prcsTags[i].type = TT_TAGCOUNT;
			if (!create_minmax(&tag[9], &prcsTags[i].meta.stat))
				goto noresults;
			qSet->meta_group_count++;

		} else if (strncmp("order:", tag, 6) == 0) {
			char *ordertype = &tag[6];

			(*qSet).reversed = prcsTags[i].filtered;
			prcsTags[i].type = TT_IGNORE;

			if (strcmp("ext", ordertype) == 0)
				(*qSet).order = OT_EXT;
			else if (strcmp("hash", ordertype) == 0)
				(*qSet).order = OT_HASH;
			else if (strcmp("mime", ordertype) == 0)
				(*qSet).order = OT_MIME;
			else if (strcmp("time", ordertype) == 0)
				(*qSet).order = OT_TIME;
			else if (strcmp("size", ordertype) == 0)
				(*qSet).order = OT_SIZE;
			else if (strcmp("random", ordertype) == 0)
				(*qSet).order = OT_RANDOM;

		} else if (strncmp("limit:", tag, 6) == 0) {
			prcsTags[i].type = TT_IGNORE;

			(*qSet).pageSize = atoi(&tag[6]);

		} else if (strncmp("explicit:", tag, 9) == 0) {
			prcsTags[i].meta.tags = Pyros_Create_List(1);
			if (prcsTags[i].meta.tags == NULL)
				goto error_oom;

			tagid = getTagId(pyrosDB, &tag[9]);
			if (tagid != NULL) {
				if (Pyros_List_Append(prcsTags[i].meta.tags,
				                      tagid) != PYROS_OK) {
					free(tagid);
					goto error_oom;
				}
				qSet->normal_group_count++;
			} else if (pyrosDB->error != PYROS_OK) {
				goto error;
			} else if (!prcsTags[i].filtered) {
				/* if tag does not exist*/
				goto noresults;
			}
		} else if (strncmp("page:", tag, 5) == 0) {
			prcsTags[i].type = TT_IGNORE;

			(*qSet).page = atoi(&tag[5]) - 1;

		} else {
			qSet->normal_group_count++;
			if (containsGlobChar(tag)) {
				prcsTags[i].meta.tags =
				    getTagIdByGlob(pyrosDB, tag);
				if (prcsTags[i].meta.tags == NULL)
					goto error;
			} else {
				prcsTags[i].meta.tags = Pyros_Create_List(1);
				if (prcsTags[i].meta.tags == NULL)
					goto error_oom;

				tagid = getTagId(pyrosDB, tag);

				if (tagid != NULL) {
					if (Pyros_List_Append(
					        prcsTags[i].meta.tags, tagid) !=
					    PYROS_OK) {
						free(tagid);
						goto error_oom;
					}
				} else if (pyrosDB->error != PYROS_OK) {
					goto error;
				} else if (!prcsTags[i].filtered) {
					/* if tag does not exist */
					goto noresults;
				}
			}

			/* get ext tags */
			if (mergeRelatedTagIds(pyrosDB, prcsTags[i].meta.tags,
			                       PYROS_SEARCH_RELATIONSHIP) !=
			    PYROS_OK)
				goto error;
		}
	}

	return prcsTags;

error_oom:
	setError(pyrosDB, PYROS_ERROR_OOM, "Out of memory");
error:
noresults:
	for (j = 0; j <= i; j++)
		if (prcsTags[j].type == TT_NORMAL)
			Pyros_List_Free(prcsTags[j].meta.tags, free);

	free(prcsTags);

	return NULL;
}

static enum PYROS_ERROR
catTagGroup(char **str, PrcsTags prcsTags, querySettings *qSet) {

	if (prcsTags.filtered)
		if (str_append(str, " NOT ") != PYROS_OK)
			return PYROS_ERROR_OOM;

	if (qSet->normal_group_count == 1 && !prcsTags.filtered) {
		if (str_append(str, " (tagid IN (") != PYROS_OK)
			return PYROS_ERROR_OOM;
	} else {
		if (str_append(str, " EXISTS (SELECT * FROM tags WHERE hashid "
		                    "= hashes.id AND tagid IN (") != PYROS_OK)
			return PYROS_ERROR_OOM;
	}

	for (size_t i = 0; i < prcsTags.meta.tags->length; i++)
		if (str_append(str, "?,") != PYROS_OK)
			return PYROS_ERROR_OOM;

	if (str_append(str, "NULL) AND isantitag=0) ") != PYROS_OK)
		return PYROS_ERROR_OOM;

	return PYROS_OK;
}

static enum PYROS_ERROR
catStatGroup(char **str, PrcsTags prcsTags) {
	if (prcsTags.meta.stat.max == 0) {
		if (str_append(str, "NOT EXISTS (SELECT * "
		                    "FROM tags WHERE "
		                    "hashid=hashes.id)") != PYROS_OK)
			return PYROS_ERROR_OOM;
		return PYROS_OK;
	}

	if (str_append(str,
	               " id IN (SELECT hashid FROM tags GROUP BY hashid HAVING "
	               "COUNT(*)") != PYROS_OK)
		return PYROS_ERROR_OOM;

	if (prcsTags.meta.stat.min == prcsTags.meta.stat.max) {
		if (str_append(str, " = ? ") != PYROS_OK)
			return PYROS_ERROR_OOM;
	} else if (prcsTags.meta.stat.min > 0 && prcsTags.meta.stat.max > 0) {
		if (str_append(str, " > ? AND COUNT(*) < ? ") != PYROS_OK)
			return PYROS_ERROR_OOM;
	} else if (prcsTags.meta.stat.min > 0) {
		if (str_append(str, " > ? ") != PYROS_OK)
			return PYROS_ERROR_OOM;
	} else if (prcsTags.meta.stat.max > 0) {
		if (str_append(str, " < ? ") != PYROS_OK)
			return PYROS_ERROR_OOM;
	}

	if (prcsTags.meta.stat.min == 0) {
		if (str_append(str, "UNION NOT EXISTS "
		                    "(SELECT * "
		                    "FROM tags WHERE "
		                    "hashid=hashes.id )) ") != PYROS_OK)
			return PYROS_ERROR_OOM;
	} else {
		if (str_append(str, " ) ") != PYROS_OK)
			return PYROS_ERROR_OOM;
	}

	return PYROS_OK;
}

static enum PYROS_ERROR
catMetaGroup(char **str, PrcsTags prcsTags, char *label) {
	if (str_append(str, label) != PYROS_OK)
		return PYROS_ERROR_OOM;

	if (containsGlobChar(prcsTags.meta.text)) {
		if (str_append(str, " GLOB ? ") != PYROS_OK)
			return PYROS_ERROR_OOM;
	} else {
		if (str_append(str, "=? ") != PYROS_OK)
			return PYROS_ERROR_OOM;
	}

	return PYROS_OK;
}

static enum PYROS_ERROR
catMetaQuery(char **str, PrcsTags prcsTags, char *src_query_column,
             char *return_column, char *table, char *query_column) {
	if (str_append(str, src_query_column) != PYROS_OK)
		return PYROS_ERROR_OOM;

	if (containsGlobChar(prcsTags.meta.text)) {
		if (str_append(str, " GLOB  ") != PYROS_OK)
			return PYROS_ERROR_OOM;
	} else {
		if (str_append(str, "= ") != PYROS_OK)
			return PYROS_ERROR_OOM;
	}

	if (str_append(str, "(SELECT ") != PYROS_OK)
		return PYROS_ERROR_OOM;
	if (str_append(str, return_column) != PYROS_OK)
		return PYROS_ERROR_OOM;
	if (str_append(str, " FROM ") != PYROS_OK)
		return PYROS_ERROR_OOM;
	if (str_append(str, table) != PYROS_OK)
		return PYROS_ERROR_OOM;
	if (str_append(str, " WHERE ? IN (") != PYROS_OK)
		return PYROS_ERROR_OOM;
	if (str_append(str, query_column) != PYROS_OK)
		return PYROS_ERROR_OOM;
	if (str_append(str, "))") != PYROS_OK)
		return PYROS_ERROR_OOM;

	return PYROS_OK;
}

static char *
createSqlSearchCommand(PrcsTags *prcsTags, size_t tag_count,
                       querySettings *qSet) {
	char *cmd = NULL;
	int firstGroup = TRUE;
	size_t i;
	int useinnerjoin =
	    (qSet->normal_group_count == 1 && !prcsTags[0].filtered);

	if (str_append(&cmd, "SELECT hash,mimetype,ext,import_time,filesize "
	                     "FROM hashes ") != PYROS_OK)
		goto error;

	/* normal tags */
	for (i = 0; i < (size_t)qSet->normal_group_count; i++) {
		if (prcsTags[i].type == TT_NORMAL) {
			if (useinnerjoin) {
				if (str_append(&cmd, "INNER JOIN tags on "
				                     "hashid = hashes.id ") !=
				    PYROS_OK)
					goto error;
			}

			if (firstGroup && !useinnerjoin) {
				if (str_append(&cmd, " WHERE ") != PYROS_OK)
					goto error;
				firstGroup = FALSE;
			} else {
				if (str_append(&cmd, " AND ") != PYROS_OK)
					goto error;
			}

			if (catTagGroup(&cmd, prcsTags[i], qSet) != PYROS_OK)
				goto error;
		}
	}

	/* other tags */
	for (; i < tag_count; i++) {
		if (prcsTags[i].type != TT_IGNORE &&
		    prcsTags[i].type != TT_NORMAL) {
			if (prcsTags[i].type == TT_ALL) {
				prcsTags[i].type = TT_IGNORE;
				continue;
			}

			if (firstGroup) {
				if (qSet->meta_group_count > 0) {
					if (str_append(&cmd, " WHERE ") !=
					    PYROS_OK)
						goto error;
				}
				firstGroup = FALSE;
			} else {
				if (str_append(&cmd, " AND ") != PYROS_OK)
					goto error;
			}

			if (prcsTags[i].filtered) {
				if (str_append(&cmd, " NOT ") != PYROS_OK)
					goto error;
			}

			switch (prcsTags[i].type) {
			case TT_TAGCOUNT:
				if (catStatGroup(&cmd, prcsTags[i]) != PYROS_OK)
					goto error;

				break;

			case TT_HASH:
				if (catMetaQuery(
				        &cmd, prcsTags[i], "hash",
				        "masterfile_hash", "merged_hashes",
				        "masterfile_hash,hash") != PYROS_OK)
					goto error;
				break;

			case TT_MIME:
				if (catMetaGroup(&cmd, prcsTags[i],
				                 "mimetype") != PYROS_OK)
					goto error;
				break;

			case TT_EXT:
				if (catMetaGroup(&cmd, prcsTags[i], "ext") !=
				    PYROS_OK)
					goto error;
				break;

			case TT_IMPORTTIME:
			default:
				break;
			}
		}
	}

	if (str_append(&cmd, " GROUP BY HASH ") != PYROS_OK)
		goto error;

	if (qSet->order != OT_NONE) {

		if (str_append(&cmd, " ORDER BY ") != PYROS_OK)
			goto error;
		switch (qSet->order) {
		case OT_EXT:
			if (str_append(&cmd, "ext") != PYROS_OK)
				goto error;
			break;
		case OT_HASH:
			if (str_append(&cmd, "hash") != PYROS_OK)
				goto error;
			break;
		case OT_MIME:
			if (str_append(&cmd, "mimetype") != PYROS_OK)
				goto error;
			break;
		case OT_TIME:
			if (str_append(&cmd, "import_time") != PYROS_OK)
				goto error;
			break;
		case OT_SIZE:
			if (str_append(&cmd, "filesize") != PYROS_OK)
				goto error;
			break;
		case OT_RANDOM:
			if (str_append(&cmd, "RANDOM()") != PYROS_OK)
				goto error;
			break;
		case OT_NONE:
			break;
		}

		if (qSet->reversed) {
			if (str_append(&cmd, " ASC") != PYROS_OK)
				goto error;
		} else {
			if (str_append(&cmd, " DESC") != PYROS_OK)
				goto error;
		}
	}

	if (qSet->pageSize > 0)
		if (str_append(&cmd, " LIMIT ?") != PYROS_OK)
			goto error;

	if (qSet->page >= 0) {
		if (qSet->pageSize <= 0) {
			qSet->pageSize = 1000;
			if (str_append(&cmd, " LIMIT ? OFFSET ?") != PYROS_OK)
				goto error;
		} else {
			if (str_append(&cmd, " OFFSET ?") != PYROS_OK)
				goto error;
		}
	}

	return cmd;

error:
	free(cmd);
	return NULL;
}
static void
reorderProcessedTags(PrcsTags **prcsTags, size_t tagc, querySettings *qSet) {
	size_t i, j = 0;
	PrcsTags temp_tag;
	int normal_tag_encountered = 0;

	if (qSet->normal_group_count < 1)
		return;

	for (i = 0; i < tagc; i++) {
		if ((*prcsTags)[i].type != TT_NORMAL) {
			if (i >= j)
				j = i + 1;
			for (; j < tagc; j++) {
				if ((*prcsTags)[j].type == TT_NORMAL) {
					temp_tag = (*prcsTags)[i];
					(*prcsTags)[i] = (*prcsTags)[j];
					(*prcsTags)[j] = temp_tag;
					break;
				}
			}
		}

		normal_tag_encountered++;

		if (normal_tag_encountered == qSet->normal_group_count)
			break;
	}
}

PyrosList *
Pyros_Search(PyrosDB *pyrosDB, const char **rawTags, size_t tagc) {
	char *cmd = NULL;
	char *tag;

	querySettings qSet;
	PrcsTags *prcsTags;

	PyrosList *files;
	sqlite3_stmt *Query_Hash_By_Tags;
	PyrosList *tags = NULL;

	assert(pyrosDB != NULL);
	RETURN_IF_ERR_WRET(pyrosDB, NULL);

	qSet.reversed = FALSE;
	qSet.order = OT_NONE;
	qSet.page = -1;
	qSet.pageSize = -1;
	qSet.normal_group_count = 0;
	qSet.meta_group_count = 0;

	tags = Pyros_Create_List(tagc);
	if (tags == NULL)
		goto error_oom;

	if (tagc == 0)
		return tags; /* return empty list */

	assert(rawTags != NULL);

	for (size_t i = 0; i < tagc; i++) {
		assert(rawTags[i] != NULL);
		tag = str_remove_whitespace(rawTags[i]);
		if (tag == NULL)
			goto error_oom;
		if (Pyros_List_Append(tags, tag) != PYROS_OK) {
			free(tag);
			goto error_oom;
		}
	}

	prcsTags = ProcessTags(pyrosDB, tags, &qSet);

	if (prcsTags == NULL) {
		if (pyrosDB->error != PYROS_OK)
			goto error;
		Pyros_List_Clear(tags, &free);
		return tags; /* return empty list */
	}

	reorderProcessedTags(&prcsTags, tags->length, &qSet);
	cmd = createSqlSearchCommand(prcsTags, tags->length, &qSet);
	if (cmd == NULL)
		goto error_oom;

	if (sqlPrepareStmt(pyrosDB, cmd, &Query_Hash_By_Tags) != PYROS_OK)
		goto error;

	sqlBindTags(Query_Hash_By_Tags, prcsTags, tagc, qSet);
	files = sqlStmtGetAllFiles(pyrosDB, Query_Hash_By_Tags);
	sqlite3_finalize(Query_Hash_By_Tags);

	if (files == NULL)
		goto error;

	/* clean up */
	for (size_t i = 0; i < tagc; i++)
		if (prcsTags[i].type == TT_NORMAL)
			Pyros_List_Free(prcsTags[i].meta.tags, free);

	free(cmd);
	free(prcsTags);
	Pyros_List_Free(tags, &free);
	return files;

error_oom:
	setError(pyrosDB, PYROS_ERROR_OOM, "Out of memory");
error:
	free(cmd);
	if (prcsTags != NULL)
		for (size_t i = 0; i < tagc; i++)
			if (prcsTags[i].type == TT_NORMAL)
				Pyros_List_Free(prcsTags[i].meta.tags, free);
	Pyros_List_Free(tags, &free);
	return NULL;
}
