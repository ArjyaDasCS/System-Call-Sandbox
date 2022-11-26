#ifndef _linkedList_
#define _linkedList_

typedef struct linkedList 
{
    void *name;
    struct linked_list* next;
} linkedList;

linkedList* insert(linkedList**,void*);
linkedList* search(linkedList*,void*,int*);

#endif

