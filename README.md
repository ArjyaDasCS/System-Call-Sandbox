# System-Call-Sandbox

Steps and information to run the tool:

Tool Name: callgraph.py
Input: victim.out (Executable of test.c)
Output: nodeInformation.txt and edgeInformation.txt

nodeInformation.txt: stores the following:

			* entry point
			
			* number of unique source nodes
			
			* node addresses (in each line)
			

edgeInformation.txt: stores the following:

			* number of unique source nodes
			
			* source node 1
			
			* number of successors of source node 1
			
			* system call name for successor 'a'
			
			* address of successor 'a'
			
			...
			
Steps:
	* gcc --static test.c -o victim.out
	
	* python3 callgraph.py
	
	* make
	
	* ./a.out nodeInformation.txt edgeInformation.txt attack.out /home/fmse/vbox-shared/attack.out
	

make		: runs the script makefile to compile and execute other files for legal system call checking.
main.c		: Accepts 4 arguments: <file containing node info> <file containing edge info> <executable> <path to executable>
reader.c	: reads the input files and creates the automata in tabular form.
nodeStructure.c : creates the linked list of unique nodes of the system call graph.
graphStructure.c: creates the structure (adjacency matrix) to store the automata.
systemcallhandler.c: handles the system calls and make decisions.
automataSimulation.c: simulates the automata based on system calls.

Necessary header files are also there.
