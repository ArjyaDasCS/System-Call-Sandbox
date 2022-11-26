#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include "nodeStructure.h"
#include "graphStructure.h"

// function to extract nodes from nodeInformation.txt
linkedList* extractNodes(int* entryLoc,int* totalNodes,char* fileName)
{
	linkedList *head, *nodeIn;
	char* nodeName;
	char node[128], startNode[128];
	int nodeNameLength, startNodeNameLength, nodes, i;
	FILE *fp;

	fp = fopen(fileName, "r");
    if (fp == NULL) 
    {
        perror(NULL);
        exit(EXIT_FAILURE);
    }
    fscanf(fp,"%s",startNode);
    startNodeNameLength=strlen(startNode);
    fscanf(fp, "%d", &nodes);
    head = NULL;

    for(i=0, *(totalNodes)=0; i<nodes; i++)
    {
    	fscanf(fp,"%s",node);
        nodeNameLength = strlen(node);
        nodeName = (char*)malloc((nodeNameLength+1)* sizeof(char));
        nodeName[nodeNameLength]='\0';
        strncpy(nodeName,node,nodeNameLength);
        nodeIn = insert(&head, (void*)nodeName);
        if (nodeIn == NULL) 
        {
            (*totalNodes) ++;
        }
    }
    fclose(fp);
    search(head,(void*)startNode,entryLoc);
    return head;
}

// function that creates the automata (in tabular format)
char*** createAutomata(linkedList* head,char* fileName)
{
	FILE *fp = fopen(fileName,"r");
	if(fp == NULL) 
	{
        perror(NULL);
        exit(EXIT_FAILURE);
    }
    char ***updatedData;
    int graphNodes, nodeSuccessors, nodeNameLength, nodeIndexSource, nodeIndexDestination;
    int i, j;
    char nodeName[128];
    char *nodeNamePtr;

    fscanf(fp, "%d", &graphNodes);
    updatedData=initialization(graphNodes,graphNodes);

    for(i=0; i<graphNodes; i++)
    {
    	fscanf(fp, "%s", nodeName);
        nodeNameLength = strlen(nodeName);
        search(head,nodeName,&nodeIndexSource);
        fscanf(fp, "%d", &nodeSuccessors);
        for(j=0; j<nodeSuccessors; j++)
        {
        	fscanf(fp, "%s", nodeName);
        	nodeNameLength = strlen(nodeName);
        	search(head,nodeName,&nodeIndexDestination);
        	fscanf(fp, "%s", nodeName);
        	nodeNameLength = strlen(nodeName);
        	nodeNamePtr = (char*)malloc((nodeNameLength+1) * sizeof(char));
            strncpy(nodeNamePtr, nodeName, nodeNameLength);
            nodeNamePtr[nodeNameLength] = '\0';
            updatedData[nodeIndexSource][nodeIndexDestination] = nodeNamePtr;
        }
    }
    fclose(fp);
    return updatedData;
}