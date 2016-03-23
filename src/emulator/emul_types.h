#ifndef _EMUL_TYPES_H
#define _EMUL_TYPES_H

#include "../general_include.h"

#define CHILD_STACK_SIZE (40000)
#define STACK_BUFFER_SIZE (65536)
//(1048576)
//(200000)
#define SHARED_MEMORY_KEY (0xA3A3)
#define MAX_EMULATOR_STEPS (100)
#define SHARED_GADGET_ARRAY_SIZE (1048576)
#define MAX_RETURN_NUMBER (50000)

typedef struct shared_memory_struct{
    int shmid;
    void *shmaddr;
    size_t real_shared_memory_size;
    size_t shared_memory_size;
    key_t shared_memory_key;
} shared_memory_struct;

typedef struct process_state{
    struct user_regs_struct regs;
    char stack[STACK_BUFFER_SIZE];
} process_state;

typedef struct lib_arguments_struct{
    pid_t main_prog_pid;
    size_t name_len;
    key_t shared_memory_key;
    size_t shared_memory_size;
    void* stack_buffer;
    shared_memory_struct* shmem_st;
} lib_arguments_struct;

typedef struct emulation_results_struct{
    int gadget_number;
    int ret_number;
    int system_call_number;
} emulation_results_struct;

#endif