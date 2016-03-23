#ifndef _TYPES_H
#define _TYPES_H

#ifndef __KERNEL__
#include <sys/types.h>
#endif

#define ROP_PROTO_DATASIZE (16384) 
#define RECV_SIZE ROP_PROTO_DATASIZE

// Rop protocol commands
#define GET_PIDS          1
#define GET_VMA           2
#define CLONE_PROC        3
#define DELETE_VMA        4
#define CHANGE_PARENT     5
#define UNKNOWN           255

typedef long pid_count_t;

typedef struct proto_command{
    int command;
    int data_size;
    pid_t pid;
    pid_t parent_pid;
} proto_command;

typedef struct proto_respond{
    int command;
    int success;
    int data_size;
    pid_t pid;
} proto_respond;

typedef struct proto_process_array{
    pid_t pid;
    unsigned long start_brk; /* start address of heap */
    unsigned long brk;       /* final address of heap */
} proto_process_array;

typedef struct proto_vma_array{
    unsigned int vm_start;
    unsigned int vm_end;
    unsigned int vm_flags;
} proto_vma_array;

typedef struct proto_port_array{
    pid_t pid;
} proto_port_array;

typedef struct vma_array{
    int vma_num;
    proto_vma_array* vmas;
} vma_array;

#endif