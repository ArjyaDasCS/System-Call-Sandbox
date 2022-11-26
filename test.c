#include<stdio.h>
void main()
{
	char *buf;
	FILE *fp = fopen("sample.txt","r");
	if(fp!=NULL)
	{
		fread(buf,sizeof(char),10,fp);
	}
	fclose(fp);
}

