#ifndef PYROS_STR_H
#define PYROS_STR_H

#include "pyros.h"

int PyrosListContainsStr(PyrosList *pList,char *str, int *index);

void PyrosStrListMergeStr(PyrosList *pList, char *str);

void PyrosStrListMerge(PyrosList *pList1,PyrosList *pList2);

void PyrosListMerge(PyrosList *pList1,PyrosList *pList2);

void hexToChar(unsigned char *str,int length, char *newstr);

char *getFilePath(PyrosDB *pyrosDB, const char *hash, const char *ext);

int containsGlobChar(const char *str);

int str_append(char **str,char *appended);
#endif
