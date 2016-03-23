#ifndef _KERNEL_INTERFACE_H
#define _KERNEL_INTERFACE_H

#include "../general_include.h"
#include "../types.h"

#include "client.h"

typedef struct base_array{
    pid_t pid; 
    int num;
    void* array;
} base_array;

typedef struct process_array{
    int proc_num;
    proto_process_array* pids;
} process_array;

base_array* kernel_command(int command, int pid);
process_array* ask_for_process_pids();
vma_array* ask_for_vma_by_pid(pid_t pid);
int fork_process_by_pid(pid_t pid);
int delete_vma(pid_t pid);

#endif