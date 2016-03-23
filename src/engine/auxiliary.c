#include "auxiliary.h"
#include <errno.h>

void* find_elem_by_key(single_list** head, unsigned int key)
{
    single_list* pointer;
    
    if ( head == NULL ) return NULL;
    if ( *head == NULL ) return NULL;
    for( pointer = *head; pointer != NULL; pointer = pointer->next )
    {
        if ( pointer->key == key )
            return pointer->data;
    }
    return NULL;
}

void add_elem(single_list** head, unsigned int key, void* data)
{
    single_list* new_elem = (single_list*)malloc( sizeof(single_list) );
    new_elem->key = key;
    new_elem->data = data;
    
    if ( head == NULL ) return;
    if ( *head == NULL ) {
        new_elem->next = NULL;
        *head = new_elem;
    }
    else {
        new_elem->next = *head;
        *head = new_elem;
    }
}

void delete_elem(single_list** head, unsigned int key)
{
    single_list* pointer = NULL;
    single_list* prev_pointer = NULL;
    
    if ( head == NULL ) return;
    if ( *head == NULL ) return;
    
    for( pointer = *head; pointer != NULL; pointer = pointer->next )
    {
        if ( pointer->key == key ) {
            if ( pointer == *head )
                *head = pointer->next;
            if ( prev_pointer != NULL )
                prev_pointer->next = pointer->next;
            
            if ( pointer->data != NULL ) free(pointer->data);
            free(pointer);
            return;
        }
        prev_pointer = pointer;
    }
}

void destroy_list(single_list** head)
{
    single_list* pointer = NULL;
    single_list* to_delete_pointer = NULL;
    
    if ( head == NULL ) return;
    if ( *head == NULL ) return;
    
    pointer = *head;
    while( pointer != NULL )
    {
        to_delete_pointer = pointer;
        pointer = pointer->next;
        
        if ( to_delete_pointer->data != NULL )
            free(to_delete_pointer->data);
        free(to_delete_pointer);
    }
    *head = NULL;
}

int ptrace_attach(pid_t pid)
{
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        int err = errno;
        if (LOGLVL >= ERRLOG) fprintf(stderr, "PTRACE_ATTACH to %d failed: %s\n", pid, strerror(err));
        return -1;
    }
    if (LOGLVL >= ADVLOG) fprintf(stderr, "Attached to %d\n", pid); // --- DEBUG OUTPUT ---
    waitpid_for_any(pid);
    return 0;
}

int ptrace_cont(pid_t pid)
{
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
		int err = errno;
		if (LOGLVL >= ERRLOG) fprintf(stderr, "PTRACE_CONT for PID %d failed: %s\n", pid, strerror(err));
		return -1;
	}
    if (LOGLVL >= ADVLOG) fprintf(stderr, "Continued %d\n", pid); // --- DEBUG OUTPUT ---
    //waitpid_for_any(pid); // DO NOT UNCOMMENT EVER
    return 0;
}

int ptrace_detach(pid_t pid)
{
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
        int err = errno;
        if (LOGLVL >= ERRLOG) fprintf(stderr, "PTRACE_DETACH to %d failed: %s\n", pid, strerror(err));
        return -1;
    }
    if (LOGLVL >= ADVLOG) fprintf(stderr, "Detached from %d\n", pid); // --- DEBUG OUTPUT ---
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
}

int waitpid_for_any(pid_t pid)
{
    int status;
    if ( waitpid(pid, &status, 0) < 0 ) {
        int err = errno;
        if (LOGLVL >= ERRLOG) fprintf(stderr, "Waitpid- %d for any failed: %s\n", pid, strerror(err));
        return -1;
    }
    if (LOGLVL >= ADVLOG) print_waitpid_status(pid, status); // --- DEBUG OUTPUT ---
    
    return 0;
}

int waitpid_for_exit(pid_t pid)
{
    int status;
    while(1){
        if ( waitpid(pid, &status, 0) < 0 ) {
            int err = errno;
            if (LOGLVL >= ERRLOG) fprintf(stderr, "Waitpid- %d for exit failed: %s\n", pid, strerror(err));
            return -1;
        }
        //print_waitpid_status(pid, status); // --- DEBUG OUTPUT ---
        
        if(WIFEXITED(status)) {
            if (LOGLVL >= ADVLOG) print_waitpid_status(pid, status); // --- DEBUG OUTPUT ---
            break;
        }
        if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
            int err = errno;
            if (LOGLVL >= ERRLOG) fprintf(stderr, "PTRACE_CONT for PID %d failed: %s\n", pid, strerror(err));
            //return -1;
        }
    }
    return 0;
}

void print_waitpid_status(pid_t pid, int status)
{
    if (WIFEXITED(status)) {
        fprintf(stderr, "Waitpid- %d : exited, status=%d\n", pid, WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        fprintf(stderr, "Waitpid- %d : killed by signal %d\n", pid, WTERMSIG(status));
    } else if (WIFSTOPPED(status)) {
        fprintf(stderr, "Waitpid- %d : stopped by signal %d\n", pid, WSTOPSIG(status));
    } else if (WIFCONTINUED(status)) {
        fprintf(stderr, "Waitpid- %d : continued\n", pid);
    } else
        fprintf(stderr, "Waitpid- %d : unknown\n", pid);
}

void print_process_regs(pid_t pid)
{
    struct user_regs_struct reg_str;
    ptrace(PTRACE_GETREGS, pid, NULL, &reg_str);
    
    fprintf(stderr, "eip= %lx\n", reg_str.eip );
    fprintf(stderr, "eflags= %lx\n", reg_str.eflags );
    fprintf(stderr, "eax= %lx\n", reg_str.eax );
    fprintf(stderr, "ecx= %lx\n", reg_str.ecx );
    fprintf(stderr, "edx= %lx\n", reg_str.edx );
    fprintf(stderr, "ebx= %lx\n", reg_str.ebx );
    fprintf(stderr, "esp= %lx\n", reg_str.esp );
    fprintf(stderr, "ebp= %lx\n", reg_str.ebp );
    fprintf(stderr, "esi= %lx\n", reg_str.esi );
    fprintf(stderr, "edi= %lx\n", reg_str.edi );
    fprintf(stderr, "xcs= %lx\n", reg_str.xcs );
    fprintf(stderr, "xss= %lx\n", reg_str.xss );
    fprintf(stderr, "xds= %lx\n", reg_str.xds );
    fprintf(stderr, "xes= %lx\n", reg_str.xes );
    fprintf(stderr, "xfs= %lx\n", reg_str.xfs );
    fprintf(stderr, "xgs= %lx\n", reg_str.xgs );
}

void exec_function(char* program_exec)
{
    //char *program_exec = "./bin/junk";
    //char *nargv[ ] = { "./junk", (char *) 0 };
    char *nenv[ ]  = { (char *) 0 };
    
    //if (setgid(65534) != 0)
    //    return -1;
    //if (setuid(65534) != 0)
    //    return -1;
    
    //ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execle(program_exec, program_exec, (char *) 0, nenv);
    
    //execve("./junk", nargv, nenv);
    //execle("newpgm", "newpgm", "parm1", "parm2", "parm3", (char *) 0, nenv);
    perror("execve");
}

void wtime(double *t)
{ 
    static int sec = -1; 
    struct timeval tv; 
    
    gettimeofday(&tv, (void *)0); 
    if (sec < 0) sec = tv.tv_sec; 
    *t = (tv.tv_sec - sec) + 1.0e-6*tv.tv_usec; 
}








