#ifndef PYROS_DATABASE_H
#define PYROS_DATABASE_H
#include "pyros.h"

void addHook(PyrosDB *pyrosDB,void(*callback)(),
			 char *str, char *str2,void(*freecallback)());

#endif
