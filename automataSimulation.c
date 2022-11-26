#include<stdio.h>
#include<string.h>
#include<stdbool.h>
#include "automataSimulation.h"
#include "graphStructure.h"

// function that simulates the automata according to system calls
int SystemCallProcessing(char* systemCallName,int* currentState,int* nextState,char*** data,int totalNodes)
{
	/*  // To track which system calls are actually happening (without any interruption)
	printf("syscall happend: %s\n", systemCallName); 
    return 1;
    */

	bool valid = false;
	int i, j;
	memset(nextState, 0, totalNodes*sizeof(int));
	for(i=0; i<totalNodes; i++) 
	{
		nextState[i]=0;
	}
	for(i=0; i<totalNodes; i++) 
	{
		if(currentState[i]==1)
		{
			currentState[i]=0;
			for(j=0; j<totalNodes; j++)
			{
				if(data[i][j]!=NULL)
				{
					if (strcmp(systemCallName,data[i][j]) == 0)
					{
						valid=true;
						nextState[j]=1;
					}
				}
			}
		}
	}
	if(valid == false) 
	{
        printf("\n%s System call is illegal ! \n", systemCallName);
    } 
    else 
    {
        printf("\n%s System call is permitted !", systemCallName);
    }
    for(i=0; i<totalNodes; i++) 
	{
		currentState[i] = nextState[i];
	}
	return valid;
}