#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
//#include <pthread.h>
//#include <dlfcn.h>

int a = 1;
int b = 2;

int test()
{
    int c;
    int d;
    
    c = a;
    d = b;
    
    a = 3;
    b = 4;
    
    return 0;
}

int foo(int a, int b, int c)
{
    if ( a!=42 || b!=666 || c!=1488 )
        return -1;
    else
        return 0;
}

int main(int argc, char *argv[])
{
    unsigned int i=0;
    void *p;
    int a=42, b=666, c=1488;
    void* lib = NULL;
    
    //// pthread test
    //pthread_t thread;
    //if (pthread_create(&thread, NULL, foo, NULL) != 0)
    //{
    //    return EXIT_FAILURE;
    //}
    //wait_thread();
    //// pthread test
    
    printf("Junk- %i : Start\n", getpid());
    //lib = dlopen( "./bin/libinject_fork.so", (RTLD_LAZY | RTLD_GLOBAL) ); 
    //printf("Junk- %i : Lib= %p, Err= %s\n", getpid(), lib, dlerror());
    p=malloc(100);
    free(p);
    sleep(5);
    while(1)
    {
        //if ( foo(a,b,c)==-1 ) 
        //{
        //    printf("Junk- %i : a= %i | b= %i | c= %i\n", getpid(), a, b, c );
        //    return -1;
        //}
        
        //if (i%1000000==0)printf("Junk- %i : Normal work at %i\n", getpid(), i);
        //printf("Junk- %i : Normal work at %i\n", getpid(), i);
        sleep(1);
        i++;
    }
    return 42;
}