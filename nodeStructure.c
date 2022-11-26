#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include "nodeStructure.h"

// function to create linked list of nodes
linkedList* insert(linkedList** head,void* name)
{
	linkedList* newNode = (linkedList*)malloc(sizeof(linkedList));
	newNode -> name = name;
	if ((*head)==NULL) 
	{
        (*head)=newNode;
    }
    else
    {
        linkedList *ptr = (*head);
        if(strcmp((char*)name,(char*)(ptr->name))==0)
        {
        	free(newNode);
            return ptr;
        }
        else
        {
        	if (strcmp((char*)name,(char*)(ptr->name))<0) 
        	{
                newNode->next = ptr;
                (*head) = newNode;
            }
            else
            {
            	linkedList* t = ptr->next;
            	while (t!= NULL && strcmp((char*)name,(char*)(t->name))>=0) 
            	{
                    ptr = t;
                    t = t->next;
                }
                if(strcmp((char*)name,(char*)(ptr->name))==0)
                {
                	free(newNode);
                	return ptr;
                }
                else
                {
                	newNode->next=ptr->next;
                	ptr->next=newNode;
                }
            }
        }
    }
    return NULL;
}

// function to search in linked list
linkedList* search(linkedList* head,void* name,int* position)
{
	linkedList *ptr = head;
	int iter=-1;
	while(ptr!=NULL)
	{
		iter+=1;
		if(strcmp((char*)(ptr->name),(char*)name)==0)
		{
			*position=iter;
			return ptr;
		}
		ptr=ptr->next;
	}
	(*position)=-1;
	return NULL;
}

void freeLinkedList(linkedList* head)
{
	if(head!=NULL)
	{
		linkedList *temp;
		do{
			temp = head->next;
			free(head->name);
			free(head);
			head=temp;
		}while(head!=NULL);
	}
}