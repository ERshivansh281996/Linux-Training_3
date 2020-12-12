!/bin/bash
//Fork two children; have the parent wait for both to die; ensure zombies are prevented using the signalling mechanism
------------------------------------------------------------------------------------------------
#include<stdio.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/wait.h>
#include<signal.h>
#include<stdlib.h>

int main()
{
		int ret;
		struct sigaction v;
		v.sa_handler=SIG_IGN;
		sigemptyset(&v.sa_mask);
		v.sa_flags=0;

		if((ret=fork())==0)
    {
				printf("In child process..%d\n",getpid());
				sleep(5);
        printf("child %d exit\n",getpid());
		}
		else if(ret==-1)
    {
				perror("Fork failed\n");
				exit(1);
		}
		else
    {
		if((ret=fork())==0)
				{
						printf("In child process..%d\n",getpid());
						sleep(3);
						printf("child %d exit\n",getpid());
				}
				else if(ret==-1)
				{
						perror("Error in fork\n");
						exit(1);
				}

				else
				{
						sigaction(SIGCHLD,&v,0);		
						while(waitpid(-1,0,0)!=-1);
						printf("Parent %d exit\n",getpid());
				}
		}
}
