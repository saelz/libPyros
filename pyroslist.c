#include <stdio.h>
#include <stdlib.h>

#include "pyros.h"

PyrosList *
Pyros_Create_List(int elements,size_t element_size){
	PyrosList *pList;
	pList = malloc(sizeof(*pList));
	if (pList == NULL){
		printf("error allocating memory");
		exit(1);
	}

	if (elements < 1)
		elements = 1;

	pList->list = malloc(sizeof(element_size)*elements);
	if (pList->list == NULL){
		printf("error allocating memory");
		exit(1);
	}
	pList->length = 0;
	pList->size = elements*element_size;
	pList->offset = 0;
	pList->list[0] = NULL;
	return pList;
}
void
Pyros_List_Free(PyrosList *pList, Pyros_Free_Callback cb){
	size_t i;
	if (pList != NULL){

		if (cb != NULL){
			for (i = 0; i < pList->length; i++)
				cb(pList->list[i]);
		}

		free(pList->list-pList->offset);
		free(pList);
	}
}

enum PYROS_ERROR
Pyros_List_Append(PyrosList *pList,void *ptr){
	void *tmpptr;
	pList->length++;
	if (pList->size < sizeof(ptr)*pList->length+1){
		pList->size *= 2;
		tmpptr = realloc(pList->list,pList->size);
		if (tmpptr == NULL){
			exit(1);
		}
		pList->list = tmpptr;
	}
	pList->list[pList->length-1] = ptr;
	pList->list[pList->length] = NULL;
	return PYROS_OK;
}

void
Pyros_List_RShift(PyrosList **pList, size_t shift){
	size_t i;
	for (i = 0; i < shift; i++)
		free((*pList)->list[i]);

	(*pList)->list++;
	(*pList)->length--;
	(*pList)->offset++;
}
