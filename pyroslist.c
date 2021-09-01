#include <stdio.h>
#include <stdlib.h>

#include "pyros.h"

PyrosList *
Pyros_Create_List(int elements,size_t element_size){
	PyrosList *pList;

	pList = malloc(sizeof(*pList));
	if (pList == NULL){
		goto error;
	}

	if (elements < 1)
		elements = 1;

	pList->list = malloc(sizeof(element_size)*elements);
	if (pList->list == NULL){
		free(pList);
		goto error;
	}

	pList->length = 0;
	pList->size = elements*element_size;
	pList->offset = 0;
	pList->list[0] = NULL;
	return pList;

error:
	fprintf(stderr,"Error allocating memory");
	return NULL;
}

void
Pyros_List_Free(PyrosList *pList, Pyros_Free_Callback cb){
	size_t i;
	if (pList != NULL){

		if (cb != NULL)
			for (i = 0; i < pList->length; i++)
				cb(pList->list[i]);

		free(pList->list-pList->offset);
		free(pList);
	}
}

void
Pyros_List_Clear(PyrosList *pList, Pyros_Free_Callback cb){
	size_t i;
	if (pList != NULL){

		for (i = 0; i < pList->length; i++){
			if (cb != NULL)
				cb(pList->list[i]);
			pList->list[i] = NULL;
		}

		pList->length = 0;
		pList->offset = 0;
	}

}

void
Pyros_List_Shrink(PyrosList *pList){
	void *tmpptr;
	size_t tmpsize;

	if (pList != NULL &&
		pList->length*sizeof(pList->list[0]) < pList->size){

		tmpsize = pList->length*sizeof(pList->list[0]);
		tmpptr = realloc(pList->list,tmpsize);
		if (tmpptr == NULL)
			return;

		pList->list = tmpptr;
		pList->size = tmpsize;
	}
}

enum PYROS_ERROR
Pyros_List_Append(PyrosList *pList,void *ptr){
	void *tmpptr;

	if (pList == NULL)
		return PYROS_ERR;

	pList->length++;

	if (pList->size < sizeof(ptr)*pList->length+1){
		pList->size *= 2;
		tmpptr = realloc(pList->list,pList->size);
		if (tmpptr == NULL){
			pList->size /= 2;
			pList->length--;
			fprintf(stderr,"Error allocating memory");
			return PYROS_ALLOCATION_ERROR;
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

	if (pList == NULL || *pList == NULL || shift >= (*pList)->length)
		return;

	for (i = 0; i < shift; i++)
		free((*pList)->list[i]);

	(*pList)->list++;
	(*pList)->length--;
	(*pList)->offset++;
}
