#include <stdio.h>
#include <stdlib.h>

int main (void)
{
		printf ("Shell is at: %p, system is at %p \n", getenv ("SHELL"), &system); 

		return 0;
}
