#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <limits.h>

#include "pyros.h"
#include "libpyros.h"
#include "str.h"

int
PyrosListContainsStr(PyrosList *pList,char *str, int *index){
	size_t i;
	for (i = 0; i < pList->length; i++) {
		if (!strcmp(pList->list[i],str)){
			if (index != NULL)
				*index = i;
			return TRUE;
		}
	}
	return FALSE;
}

void
PyrosStrListMergeStr(PyrosList *pList, char *str){
	size_t i;
	for (i = 0; i < pList->length; i++) {
		if (!strcmp(pList->list[i],str)){
			free(str);
			return;
		}
	}
	Pyros_List_Append(pList,str);
}

void
PyrosStrListMerge(PyrosList *pList1,PyrosList *pList2){
	size_t i;
	for (i = 0; i < pList2->length; i++)
		PyrosStrListMergeStr(pList1,pList2->list[i]);
	Pyros_List_Free(pList2,NULL);
}

void
PyrosListMerge(PyrosList *pList1,PyrosList *pList2){
	size_t i,j;
	for (i = 0; i < pList2->length; i++){
		for (j = 0; j < pList1->length; j++) {

			if (*((sqlite_int64*)pList1->list[j]) == *((sqlite_int64*)pList2->list[i])){
				free(pList2->list[i]);
				goto found;
			}
		}
		Pyros_List_Append(pList1,pList2->list[i]);
	found:;
	}
	Pyros_List_Free(pList2,NULL);
}

void
hexToChar(unsigned char *str,int length, char *newstr){
	int i;
	for (i = 0; i < length; ++i) {
		*newstr = HEX[str[i]/16%16];
		newstr++;
		*newstr = HEX[str[i]%16];
		newstr++;
	}
	*newstr = '\0';
}


char *
getFilePath(PyrosDB *pyrosDB, const char *hash,const char *ext){
	char dbPath[] = {'/','d','b','/',hash[0],hash[1],'/', '\0'};
	char *path;

	if (pyrosDB->preserve_ext && ext != NULL && ext[0] != '\0'){
		path = malloc(sizeof(*path)*(strlen(pyrosDB->path)+strlen(dbPath)
									 +strlen(hash)+strlen(ext)+2));
		if (path == NULL)
			exit(1);
		strcpy(path,pyrosDB->path);
		strcat(path,dbPath);
		strcat(path,hash);
		strcat(path,".");
		strcat(path,ext);

		return path;
	}

	path = malloc(sizeof(*path)*(strlen(pyrosDB->path)+strlen(dbPath)+strlen(hash)+1));
	if (path == NULL)
		exit(1);
	strcpy(path,pyrosDB->path);
	strcat(path,dbPath);
	strcat(path,hash);


	return path;
}

int
containsGlobChar(const char *str){
	size_t i;
	for (i = 0; i < strlen(str);i++){
		switch (str[i]){
		case '^':
		case ']':
		case '[':
		case '*':
		case '?':
			return TRUE;
		}
	}
	return FALSE;
}

int
str_append(char **str,char *appended){
	if (*str == NULL){
		*str = malloc(strlen(appended)+1);
		*str[0] = '\0';
	} else{
		*str = realloc(*str, strlen(*str)+strlen(appended)+1);
	}

	if (*str == NULL)
		return FALSE;

	strcat(*str,appended);

	return TRUE;
}

char *
str_remove_whitespace(const char *orig_str){
	size_t length;
	size_t last_char = 0;
	size_t spaces_encountered = FALSE;
	char *str;

	if (orig_str == NULL)
		return NULL;

	length = strlen(orig_str);
	str = malloc(length+1);

	for (; *orig_str == ' '; orig_str++);

	for (; *orig_str != '\0'; orig_str++){
		if (*str == ' '){
			if (!spaces_encountered){
				str[last_char] = *orig_str;
				last_char++;
			}
			spaces_encountered = TRUE;

		} else if (!isspace(*str) && !isblank(*str)){
			str[last_char] = *orig_str;
			last_char++;
			spaces_encountered = FALSE;
		}
	}

	if (spaces_encountered)
		str[last_char-1] = '\0';
	else
		str[last_char] = '\0';

	return str;
}
