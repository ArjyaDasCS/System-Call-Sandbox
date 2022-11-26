#include<stdio.h>
#include<stdlib.h>
#include<sys/ptrace.h>
#include <sys/wait.h>
#include<sys/types.h>
#include<unistd.h>
#include "automataSimulation.h"
#include "nodeStructure.h"
#include "graphStructure.h"
#include "systemcallhandler.h"
#include "reader.h"

// function to track child
void callExec(int totalNodes,int entryLoc,char*** data,char* executablePath,char* executableName)
{
	int Status;
	pid_t child;	
	child = fork();
	if(child==0)
	{
		ptrace(PTRACE_TRACEME, 0, 0, 0);			
		/* This request makes the calling thread (child) to act as a tracee */
		execl(executablePath, executableName, NULL); 
		/* This overlays the child (that has been created by a call to the fork function by parent)
		   process image with the executable */
	}
	else
	{
		waitpid(child, &Status, 0); 
		/* It suspends the parent until the system gets status information on the child */
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);
        /* PTRACE_O_TRACESYSGOOD helps to distinguish between normal traps and system calls. It sets bit 7 in the signal 
           number while delivering system call traps (i.e., deliver SIGTRAP|0x80) */
        signalProcessing(child,data,entryLoc,totalNodes); 
        /* This function process the received signal */
	}
}

void main(int argc, char** argv)
{
	// arg[1]: nodeInformation.txt
	// arg[2]: edgeInformation.txt
	// arg[3]: executable
	// arg[4]: path of the executable
	// tackle argument mismatch issue
	if(argc<5)
	{
		printf("Arguments should be like this: <nodeInfo file> <edgeInfoFile> <executable> <path to executable>");
	}
	int totalNodes = 0;			// store total number of nodes
	int entryLoc;				// entry location of the program
	linkedList *head = extractNodes(&entryLoc, &totalNodes, argv[1]); // store the nodes info in the form of linked list
	char ***data = createAutomata(head, argv[2]);					  // represent the automata (NFA) in tabular form
	callExec(totalNodes,entryLoc,data,argv[3],argv[4]);				  // Track the system calls of executable and run automata
	puts("\nExecution complete!");
}
