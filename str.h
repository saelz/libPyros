#ifndef PYROS_STR_H
#define PYROS_STR_H

#include "pyros.h"

int PyrosListContainsStr(PyrosList *pList, char *str, int *index);

enum PYROS_ERROR PyrosStrListMergeStr(PyrosList *pList, char *str);

enum PYROS_ERROR PyrosStrListMerge(PyrosList *pList1, PyrosList *pList2);

enum PYROS_ERROR PyrosListMerge(PyrosList *pList1, PyrosList *pList2);

void hexToChar(unsigned char *str, int length, char *newstr);

char *getFilePath(PyrosDB *pyrosDB, const char *hash, const char *ext);

int containsGlobChar(const char *str);

enum PYROS_ERROR str_append(char **str, char *appended);

char *str_remove_whitespace(const char *str);

char *duplicate_str(const char *str);
#endif
