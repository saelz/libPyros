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


/*void
EscapeChar(char *str,char *newstr,char c,char escape){
	int charFound = 0;
	size_t i;

	for (i = 0; i < strlen(str);i++){
		if (str[i] == c){
			newstr[i+charFound] = escape;
			charFound++;
		}
		newstr[i+charFound] = str[i];
	}
	newstr[strlen(str)+charFound] = '\0';
}*/

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
