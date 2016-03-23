#ifndef _PROCESS_H
#define _PROCESS_H

#include "../general_include.h"

#include "kernel_interface.h"
#include "memory_analyzer.h"
#include "../rb_tree/red_black_tree.h"
#include "../emulator/hotpatch/hotpatch.h"
#include "../emulator/hotpatch/hotpatch_internal.h"

#define HOTPATCH_LOG 0

#define VM_READ         0x00000001      /* currently active flags */
#define VM_WRITE        0x00000002
#define VM_EXEC         0x00000004

/* mprotect() hardcodes VM_MAYREAD >> 4 == VM_READ, and so for r/w/x bits. */
#define VM_MAYREAD      0x00000010      /* limits for mprotect() etc */
#define VM_MAYWRITE     0x00000020
#define VM_MAYEXEC      0x00000040
#define VM_MAYSHARE     0x00000080

typedef struct vma_struct vma_struct;
typedef struct process_struct process_struct;
typedef rb_red_blk_tree rb_tree;
typedef rb_red_blk_node rb_node;

typedef struct vma_struct{
    unsigned int vm_start;
    unsigned int vm_end;
    unsigned int vm_flags;
    
    rb_tree* gadget_tree;
} vma_struct;

typedef struct prefix_struct{
    unsigned char prefix_value;
    //unsigned char prefix_start;
    //unsigned char prefix_end;
    //unsigned int vm_flags;
} prefix_struct;

typedef struct process_struct{
    pid_t pid;
    
    unsigned int ip;
    unsigned short port;
    // Library injection
    hotpatch_t *hp;
    hotpatch_t *emulator_hp;
    uintptr_t libinject_fork_handle;
    
    //vma_struct* vma;
    rb_tree* vma_tree;
    rb_tree* vma_exec_tree;
    rb_tree* vma_write_mayexec_tree;
    
    vma_array* plain_vma_array;
    
    rb_tree* invert_vma_exec_tree;
    rb_tree* exec_address_prefix_tree;
    
    unsigned int first_vma_start;
    unsigned int last_vma_end;
    
    unsigned long start_brk; /* start address of heap */
    unsigned long brk;       /* final address of heap */
    
    size_t memory_space_size;
    size_t executable_space_size;
    
    process_struct* next;
    process_struct* prev;
} process_struct;

typedef struct process_list{
    int proc_num;
    
    process_struct* process_list_head;
    process_struct* process_list_tail;
} process_list;

typedef struct network_info_struct{
    unsigned int ip;
    unsigned short port;
    
    pid_t pid;
    process_struct* process;
} network_info_struct;



process_list* init_process_list();
int init_process_emulators(process_list* list);
void destroy_process_list(process_list* list);
process_list* create_empty_process_list();
process_struct* create_process();
void destroy_process(process_struct* process);

process_struct* get_process_by_pid(process_list* list, pid_t pid);
process_struct* add_process(process_list* list, pid_t pid);
void delete_process_by_pid(process_list* list, pid_t pid);
void delete_process(process_list* list, process_struct* process);

void init_vma_tree(process_struct* process, pid_t pid);
rb_tree* create_vma_tree();
rb_node* insert_vma(rb_tree* tree, vma_struct* vma);
rb_node* search_vma_by_address(rb_tree* tree, unsigned int address);
void destroy_vma_tree(rb_tree* tree);
int compare_vma(const void* a,const void* b);
void destroy_vma(void* a);

rb_tree* create_prefix_tree();
rb_node* insert_prefix(rb_tree* tree, prefix_struct* prefix);
inline rb_node* search_prefix(rb_tree* tree, unsigned int address);
void destroy_prefix_tree(rb_tree* tree);
int compare_prefix(const void* a,const void* b);
void destroy_prefix(void* a);

rb_tree* network_info_tree_init();
rb_tree* create_network_info_tree();
rb_node* insert_network_info(rb_tree* tree, network_info_struct* network_info);
inline rb_node* search_network_info_ip_port(rb_tree* tree, unsigned int ip, unsigned short port);
inline process_struct* process_by_ip_port(rb_tree* tree, unsigned int ip, unsigned short port);
void destroy_network_info_tree(rb_tree* tree);
int compare_network_info(const void* a,const void* b);
void destroy_network_info(void* a);

//void null_function(void * junk);
//void null_function_const(const void * junk);

#endif