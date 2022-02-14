#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libpyros.h"
#include "pyros.h"
#include "str.h"

int
PyrosListContainsStr(PyrosList *pList, char *str, int *index) {
	size_t i;
	for (i = 0; i < pList->length; i++) {
		if (!strcmp(pList->list[i], str)) {
			if (index != NULL)
				*index = i;
			return TRUE;
		}
	}
	return FALSE;
}

enum PYROS_ERROR
PyrosStrListMergeStr(PyrosList *pList, char *str) {
	size_t i;
	for (i = 0; i < pList->length; i++) {
		if (!strcmp(pList->list[i], str)) {
			free(str);
			return PYROS_OK;
		}
	}

	return Pyros_List_Append(pList, str);
}

enum PYROS_ERROR
PyrosStrListMerge(PyrosList *pList1, PyrosList *pList2) {
	size_t i;

	if (Pyros_List_Grow(pList1, (pList1->length * sizeof(*pList1->list)) +
	                                (pList2->length *
	                                 sizeof(*pList2->list))) != PYROS_OK)
		return PYROS_ERROR_OOM;

	for (i = 0; i < pList2->length; i++)
		PyrosStrListMergeStr(pList1, pList2->list[i]);

	Pyros_List_Free(pList2, NULL);

	return PYROS_OK;
}

enum PYROS_ERROR
PyrosListMerge(PyrosList *pList1, PyrosList *pList2) {
	size_t i, j;

	if (Pyros_List_Grow(pList1, (pList1->length * sizeof(*pList1->list)) +
	                                (pList2->length *
	                                 sizeof(*pList2->list))) != PYROS_OK)
		return PYROS_ERROR_OOM;

	for (i = 0; i < pList2->length; i++) {
		for (j = 0; j < pList1->length; j++) {

			if (*((int64_t *)pList1->list[j]) ==
			    *((int64_t *)pList2->list[i])) {
				free(pList2->list[i]);
				goto found;
			}
		}
		Pyros_List_Append(pList1, pList2->list[i]);
	found:;
	}
	Pyros_List_Free(pList2, NULL);

	return PYROS_OK;
}

void
hexToChar(unsigned char *str, int length, char *newstr) {
	int i;
	for (i = 0; i < length; ++i) {
		*newstr = HEX[str[i] / 16 % 16];
		newstr++;
		*newstr = HEX[str[i] % 16];
		newstr++;
	}
	*newstr = '\0';
}

char *
getFilePath(PyrosDB *pyrosDB, const char *hash, const char *ext) {
	char dbPath[] = {'/', 'd', 'b', '/', hash[0], hash[1], '/', '\0'};
	size_t len;
	char *path;

	if (pyrosDB->preserve_ext && ext != NULL && ext[0] != '\0') {
		len = strlen(pyrosDB->path) + strlen(dbPath) + strlen(hash) +
		      strlen(ext) + 2;
	} else {
		len = strlen(pyrosDB->path) + strlen(dbPath) + strlen(hash) + 1;
	}

	path = malloc(len);
	if (path == NULL)
		return NULL;

	strcpy(path, pyrosDB->path);
	strcat(path, dbPath);
	strcat(path, hash);
	strcat(path, ".");
	strcat(path, ext);

	return path;
}

int
containsGlobChar(const char *str) {
	while (*str != '\0') {
		switch (*str) {
		case '^':
		case ']':
		case '[':
		case '*':
		case '?':
			return TRUE;
		}
		str++;
	}
	return FALSE;
}

enum PYROS_ERROR
str_append(char **str, char *appended) {
	char *tmp_str;

	assert(appended != NULL);

	if (*str == NULL) {
		*str = malloc(strlen(appended) + 1);
		if (*str == NULL)
			return PYROS_ERROR_OOM;
		*str[0] = '\0';
	} else {
		tmp_str = realloc(*str, strlen(*str) + strlen(appended) + 1);
		if (tmp_str == NULL)
			return PYROS_ERROR_OOM;
		*str = tmp_str;
	}

	strcat(*str, appended);

	return PYROS_OK;
}

char *
str_remove_whitespace(const char *orig_str) {
	size_t length;
	size_t last_char = 0;
	size_t spaces_encountered = FALSE;
	char *str;

	if (orig_str == NULL)
		return NULL;

	length = strlen(orig_str);
	str = malloc(length + 1);

	if (str == NULL)
		return NULL;

	for (; *orig_str == ' '; orig_str++)
		/* pass */;

	for (; *orig_str != '\0'; orig_str++) {
		if (*orig_str == ' ') {
			if (!spaces_encountered) {
				str[last_char] = *orig_str;
				last_char++;
			}
			spaces_encountered = TRUE;

		} else if (!isspace(*orig_str) && !isblank(*orig_str)) {
			str[last_char] = *orig_str;
			last_char++;
			spaces_encountered = FALSE;
		}
	}

	if (spaces_encountered)
		str[last_char - 1] = '\0';
	else
		str[last_char] = '\0';

	return str;
}

char *
duplicate_str(const char *str) {
	char *new_str;
	new_str = malloc(strlen(str) + 1);

	if (new_str == NULL)
		return NULL;

	strcpy(new_str, str);
	return new_str;
}
