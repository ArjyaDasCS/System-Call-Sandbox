#include <stdio.h>
#include <stdlib.h>

// function that stores the edge information data as adjacency matrix (dynamic)
char*** initialization(int r,int c) 
{
    int i,j;
    char ***data;
    data = (char***)malloc(r*sizeof(char**));
    for (i=0; i<r; i++) 
    {
        data[i] = (char**)malloc(c*sizeof(char*));
        for (j=0; j<c; j++) 
        {
            data[i][j] = NULL;
        }
    }
    return data;
}