#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "pyros.h"

PyrosList *
Pyros_Create_List(int elements) {
	PyrosList *pList;

	pList = malloc(sizeof(*pList));
	if (pList == NULL) {
		goto error;
	}

	if (elements < 1)
		elements = 1;

	pList->list = malloc(sizeof(*pList->list) * elements);
	if (pList->list == NULL) {
		free(pList);
		goto error;
	}

	pList->length = 0;
	pList->size = elements * sizeof(*pList->list);
	pList->offset = 0;
	pList->list[0] = NULL;
	return pList;

error:
	return NULL;
}

void
Pyros_List_Free(PyrosList *pList, Pyros_Free_Callback cb) {
	size_t i;
	if (pList != NULL) {
		if (cb != NULL)
			for (i = 0; i < pList->length; i++)
				cb(pList->list[i]);

		free(pList->list - pList->offset);
		free(pList);
	}
}

void
Pyros_List_Clear(PyrosList *pList, Pyros_Free_Callback cb) {
	size_t i;
	assert(pList != NULL);
	assert(pList->list != NULL);

	for (i = 0; i < pList->length; i++) {
		if (cb != NULL)
			cb(pList->list[i]);
		pList->list[i] = NULL;
	}

	pList->length = 0;
	pList->offset = 0;
}

enum PYROS_ERROR
Pyros_List_Shrink(PyrosList *pList) {
	void *tmpptr;
	size_t tmpsize;

	assert(pList != NULL);
	assert(*pList->list != NULL);

	if (pList->length * sizeof(*pList->list) < pList->size) {

		tmpsize = pList->length * sizeof(*pList->list);
		tmpptr = realloc(pList->list, tmpsize);
		if (tmpptr == NULL)
			return PYROS_ERROR_OOM;

		pList->list = tmpptr;
		pList->size = tmpsize;
	}
	return PYROS_OK;
}

enum PYROS_ERROR
Pyros_List_Grow(PyrosList *pList, size_t requested_len) {
	void *tmpptr;
	size_t new_size;

	assert(pList != NULL);
	assert(pList->list != NULL);

	new_size = sizeof(*pList->list) * requested_len;

	if (pList->size < new_size) {
		tmpptr = realloc(pList->list, new_size);
		if (tmpptr == NULL)
			return PYROS_ERROR_OOM;

		pList->list = tmpptr;
		pList->size = new_size;
	}
	return PYROS_OK;
}

union constlistconvert {
	void **list;
	const void **cons;
};
enum PYROS_ERROR
Pyros_List_Append(PyrosList *pList, const void *ptr) {
	void *tmpptr;
	union constlistconvert const_list;

	assert(pList != NULL);
	assert(pList->list != NULL);

	pList->length++;

	if (pList->size < sizeof(ptr) * pList->length + 1) {
		pList->size *= 2;
		tmpptr = realloc(pList->list, pList->size);
		if (tmpptr == NULL) {
			pList->size /= 2;
			pList->length--;
			return PYROS_ERROR_OOM;
		}
		pList->list = tmpptr;
	}

	const_list.list = pList->list;
	const_list.cons[pList->length - 1] = ptr;
	pList->list[pList->length] = NULL;
	return PYROS_OK;
}

enum PYROS_ERROR
Pyros_List_RShift(PyrosList **pList, size_t shift, Pyros_Free_Callback cb) {
	size_t i;

	assert(pList != NULL);
	assert(*pList != NULL);
	assert((*pList)->list != NULL);

	if (shift >= (*pList)->length)
		return PYROS_ERROR_INVALID_ARGUMENT;

	for (i = 0; i < shift; i++) {
		if (cb != NULL)
			cb((*pList)->list[i]);
		(*pList)->list[i] = NULL;
	}

	(*pList)->list += shift;
	(*pList)->length--;
	(*pList)->offset++;

	return PYROS_OK;
}
