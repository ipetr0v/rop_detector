#ifndef _SHARED_MEMORY_WRAPPER_H
#define _SHARED_MEMORY_WRAPPER_H

#include "../general_include.h"

#include "emul_types.h"
#include "../engine/process.h"

///typedef struct shared_memory_struct{
///    int shmid;
///    void *shmaddr;
///    size_t real_shared_memory_size;
///    size_t shared_memory_size;
///    key_t shared_memory_key;
///} shared_memory_struct;

typedef struct shared_memory_header{
    pid_t prog_pid;
    struct user_regs_struct regs;
    void* old_heap_pointer;
    size_t old_heap_size_value;
    emulation_results_struct emu_results;
    
    size_t stack_size;
    size_t max_stack_size;
    size_t return_array_size;
    size_t vma_array_size;
    
} shared_memory_header;

typedef struct shared_gadget_array_header{
    pid_t prog_pid;
    
    size_t vma_array_size;
    size_t gadget_array_size;
} shared_gadget_array_header;

void print_shmem(shared_memory_struct* shmem_st);
void print_vma_array(shared_memory_struct* shmem_st);

int correct_shmem(shared_memory_struct* shmem_st);
shared_memory_header* get_shmem_header(shared_memory_struct* shmem_st);
char* get_shmem_stack(shared_memory_struct* shmem_st);
return_address_in_buffer* get_shmem_ret(shared_memory_struct* shmem_st, int ret_number);
proto_vma_array* get_shmem_vma(shared_memory_struct* shmem_st, int vma_number);

shared_memory_struct* create_shared_memory(key_t shared_memory_key);
size_t init_shared_memory( shared_memory_struct* shmem_st,
                          process_struct* process,
                          struct user_regs_struct* reg_str,
                          size_t stack_size,
                          char* stack_pointer, 
                          return_addresses_array* ret_array );
void destroy_shared_memory(shared_memory_struct* shmem_st);
void* attach_shared_memory(shared_memory_struct* shmem_st);
void detach_shared_memory(shared_memory_struct* shmem_st);

#endif