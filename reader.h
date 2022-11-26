#ifndef __CUSTOM_FILE_READER_H__
#define __CUSTOM_FILE_READER_H__

#include "nodeStructure.h"

linkedList* extractNodes(int*,int*,char*);
char*** createAutomata(linkedList*,char*);

#endif