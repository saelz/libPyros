#include <string.h>
#include <stdlib.h>

#include "pyros.h"
#include "libpyros.h"
#include "sqlite.h"
#include "str.h"
#include "search.h"

static int create_minmax(const char *str,struct minmax *stat);

static PrcsTags* ProcessTags(PyrosDB *pyrosDB, PyrosList *tags, querySettings *qSet);

static void catTagGroup(char **str, PrcsTags prcsTags);
static void catStatGroup(char **str, PrcsTags prcsTags);
static void catMetaGroup(char **str, PrcsTags prcsTags, char *label);


static int
create_minmax(const char *str,struct minmax *stat){
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
		stat->min = atoi(&str[1])-1;
		stat->max = atoi(&str[1])+1;
		break;
	default:
		stat->min = atoi(str)-1;
		stat->max = atoi(str)+1;
		break;
	}
	return TRUE;

}

static PrcsTags*
ProcessTags(PyrosDB *pyrosDB, PyrosList *tags, querySettings *qSet){
	size_t i,j;
	sqlite3_int64 *tagid;
	char *tag;

	PrcsTags *prcsTags = malloc(sizeof(*prcsTags)*(tags->length));
	if (prcsTags == NULL)
		return NULL;

	for (i = 0; i < tags->length; i++){
		prcsTags[i].type = TT_NORMAL;

		if(((char*)tags->list[i])[0] == '-'){
			prcsTags[i].filtered = TRUE;
			tag = &((char*)tags->list[i])[1];
		} else{
			prcsTags[i].filtered = FALSE;
			tag = tags->list[i];
		}

		/* skip empty string */
		if (tag[0] == '\0'){
			prcsTags[i].type = TT_IGNORE;
			continue;
		}

		/* skips duplicate tags */
		for (j = 0; j < i; j++) {
			if (strcmp(tag,tags->list[j]) == 0){
				prcsTags[i].type = TT_IGNORE;
				break;
			}
		}


		if (prcsTags[i].type == TT_IGNORE){
			continue;
		} else if(strcmp("*",tag) == 0){
			prcsTags[i].type = TT_ALL;

			if (prcsTags[i].filtered) /* if tag == -* */
					goto noresults;

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
			if (!create_minmax(&tag[9],&prcsTags[i].meta.stat))
				goto noresults;

		} else if(strncmp("order:",tag,6) == 0){
			char *ordertype = &tag[6];

			(*qSet).reversed = prcsTags[i].filtered;
			prcsTags[i].type = TT_IGNORE;

			if (strcmp("ext",ordertype) == 0)
				(*qSet).order = OT_EXT;
			else if (strcmp("hash",ordertype) == 0)
				 (*qSet).order = OT_HASH;
			else if (strcmp("mime",ordertype) == 0)
				 (*qSet).order = OT_MIME;
			else if (strcmp("time",ordertype) == 0)
				 (*qSet).order = OT_TIME;
			else if (strcmp("size",ordertype) == 0)
				(*qSet).order = OT_SIZE;
			else if (strcmp("random",ordertype) == 0)
				(*qSet).order = OT_RANDOM;

		} else if(strncmp("limit:",tag,6) == 0){
			prcsTags[i].type = TT_IGNORE;

			(*qSet).pageSize = atoi(&tag[6]);

		} else if(strncmp("page:",tag,5) == 0){
			prcsTags[i].type = TT_IGNORE;

			(*qSet).page = atoi(&tag[5])-1;

		} else {
			if (containsGlobChar(tag)){
				prcsTags[i].meta.tags = getTagIdByGlob(pyrosDB,tag);
			} else{
				prcsTags[i].meta.tags = Pyros_Create_List(1,sizeof(sqlite3_int64*));
				tagid = getTagId(pyrosDB,tag);

				if (tagid != NULL){
					Pyros_List_Append(prcsTags[i].meta.tags,tagid);
				} else if (!prcsTags[i].filtered){
					/* if tag does not exist */
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
catTagGroup(char **str, PrcsTags prcsTags){

	str_append(str," SELECT hashid FROM tags WHERE tagid IN (");
	for (size_t i = 0; i < prcsTags.meta.tags->length; i++)
		str_append(str,"?,");

	str_append(str,"NULL) AND isantitag=0 ");
}

static void
catStatGroup(char **str, PrcsTags prcsTags){
	str_append(str," SELECT hashid FROM tags GROUP BY hashid HAVING COUNT(hashid)");

	if (prcsTags.meta.stat.min >= 0 && prcsTags.meta.stat.max >= 0 )
		str_append(str," > ? AND COUNT(hashid) < ? ");
	else if (prcsTags.meta.stat.min >= 0)
		str_append(str," > ? ");
	else if (prcsTags.meta.stat.max >= 0)
		str_append(str," < ? ");

}

static void
catMetaGroup(char **str, PrcsTags prcsTags, char *label){
	str_append(str," SELECT id FROM hashes WHERE ");
	str_append(str,label);
	if (containsGlobChar(prcsTags.meta.text)){
		str_append(str," GLOB ? ");
	} else{
		str_append(str,"=? ");
	}
}

static char *
createSqlSearchCommand(PrcsTags *prcsTags,size_t tag_count,querySettings *qSet){
	char *cmd = NULL;
	int firstGroup = TRUE;

	str_append(&cmd,
			   "SELECT truehash,mimetype,ext,import_time,filesize "
			   "FROM hashes WHERE id IN (");


	for (size_t i = 0; i < tag_count; i++){
		if (prcsTags[i].type != TT_IGNORE){

			if (firstGroup && prcsTags[i].filtered){
				str_append(&cmd,"SELECT hashid FROM tags EXCEPT");
				firstGroup = FALSE;
			} else if (firstGroup){
				firstGroup = FALSE;
			} else if (prcsTags[i].filtered){
				str_append(&cmd,"EXCEPT");
			} else{
				str_append(&cmd,"INTERSECT");
			}

			switch (prcsTags[i].type){
			case TT_NORMAL:
				catTagGroup(&cmd,prcsTags[i]);
				break;

			case TT_TAGCOUNT:
				if (prcsTags[i].meta.stat.max == 0){
					str_append(&cmd,"SELECT id FROM hashes WHERE id NOT IN ( SELECT hashid FROM tags) AND hash=truehash ");
				} else {
					catStatGroup(&cmd, prcsTags[i]);
					if (prcsTags[i].meta.stat.min <= 0)
						str_append(&cmd,"UNION SELECT id FROM hashes WHERE id NOT IN ( SELECT hashid FROM tags) AND hash=truehash ");
				}
				break;

			case TT_ALL:
				str_append(&cmd," SELECT id FROM hashes ");
				prcsTags[i].type = TT_IGNORE;
				break;

			case TT_HASH:
				catMetaGroup(&cmd,prcsTags[i],"hash");
				break;

			case TT_MIME:
				catMetaGroup(&cmd,prcsTags[i],"mimetype");
				break;

			case TT_EXT:
				catMetaGroup(&cmd,prcsTags[i],"ext");
				break;

			case TT_IMPORTTIME:
			case TT_IGNORE:
				break;
			}
		}
	}

	str_append(&cmd,") GROUP BY hash");

	if (qSet->order != OT_NONE){

		str_append(&cmd," ORDER BY ");
		switch (qSet->order){
		case OT_EXT:
			str_append(&cmd,"ext");
			break;
		case OT_HASH:
			str_append(&cmd,"hash");
			break;
		case OT_MIME:
			str_append(&cmd,"mimetype");
			break;
		case OT_TIME:
			str_append(&cmd,"import_time");
			break;
		case OT_SIZE:
			str_append(&cmd,"filesize");
			break;
		case OT_RANDOM:
			str_append(&cmd,"RANDOM()");
			break;
		case OT_NONE:
			break;
		}

		if (qSet->reversed)
			str_append(&cmd," ASC");
		else
			str_append(&cmd," DESC");
	}

	if (qSet->pageSize > 0)
		str_append(&cmd," LIMIT ?");
	if (qSet->page >= 0){
		if (qSet->pageSize <= 0){
			qSet->pageSize = 1000;
			str_append(&cmd," LIMIT ? OFFSET ?");
		} else{
			str_append(&cmd," OFFSET ?");
		}
	}

	return cmd;
}

PyrosList *
Pyros_Search(PyrosDB *pyrosDB, char **rawTags, size_t tagc){
	char *cmd = NULL;

	querySettings qSet;
	PrcsTags *prcsTags;

	PyrosList *files;
	sqlite3_stmt *Query_Hash_By_Tags;
	PyrosList *tags;

	qSet.reversed = FALSE;
	qSet.order = OT_NONE;
	qSet.page = -1;
	qSet.pageSize = -1;


	tags = Pyros_Create_List(tagc, sizeof(char*));
	for (size_t i = 0; i < tagc; i++)
		Pyros_List_Append(tags, str_remove_whitespace(rawTags[i]));

	prcsTags = ProcessTags(pyrosDB,tags,&qSet);

	if (prcsTags == NULL){
		Pyros_List_Free(tags, &free);
		return Pyros_Create_List(1,sizeof(char*));/* return empty list */
	}

	cmd = createSqlSearchCommand(prcsTags, tags->length, &qSet);


	sqlPrepareStmt(pyrosDB,cmd,&Query_Hash_By_Tags);
	sqlBindTags(Query_Hash_By_Tags,prcsTags,tagc,qSet);
	files = sqlStmtGetAllFiles(pyrosDB, Query_Hash_By_Tags);

	/* clean up */
	for (size_t i = 0; i < tagc; i++)
		if (prcsTags[i].type == TT_NORMAL)
				Pyros_List_Free(prcsTags[i].meta.tags,free);

	free(cmd);
	free(prcsTags);
	sqlite3_finalize(Query_Hash_By_Tags);
	Pyros_List_Free(tags, &free);
	return files;
}
