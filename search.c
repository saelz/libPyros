#include <string.h>
#include <stdlib.h>

#include "pyros.h"
#include "libpyros.h"
#include "sqlite.h"
#include "str.h"
#include "search.h"


static PrcsTags* ProcessTags(PyrosDB *pyrosDB, char **tags,
							 size_t tagc, querySettings *qSet);

static void catTagGroup(char *str, PrcsTags prcsTags);
static void catStatGroup(char *str, PrcsTags prcsTags);
static void catMetaGroup(char *str, PrcsTags prcsTags, char *label);

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
