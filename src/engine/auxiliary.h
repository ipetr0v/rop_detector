#ifndef _AUXILIARY_H
#define _AUXILIARY_H

#include "../general_include.h"

typedef struct single_list single_list;
typedef struct single_list{
    unsigned int key;
    void* data;
    struct single_list* next;
} single_list;

void* find_elem_by_key(single_list** head, unsigned int key);
void add_elem(single_list** head, unsigned int key, void* data);
void delete_elem(single_list** head, unsigned int key);
void destroy_list(single_list** head);

int ptrace_attach(pid_t pid);
int ptrace_cont(pid_t pid);
int ptrace_detach(pid_t pid);
int waitpid_for_any(pid_t pid);
int waitpid_for_exit(pid_t pid);

void print_waitpid_status(pid_t pid, int status);
void print_process_regs(pid_t pid);

void exec_function(char* program_exec);
void wtime(double *t);

#endif