#include "shared_memory_wrapper.h"

/*  pid_t prog_pid;
    size_t stack_size;
    size_t return_array_size;
    size_t vma_array_size;*/
/*typedef struct return_addresses_array{
    int ret_num;
    unsigned long* ret;
} return_addresses_array;*/
/* typedef struct vma_array{
    int vma_num;
    proto_vma_array* vmas;
} vma_array;*/

extern size_t MAX_ret_num;
extern size_t MAX_vma_num;

void print_shmem(shared_memory_struct* shmem_st)
{
    printf("Inject- %i : Address of shmem-%x\n", getpid(), (unsigned int)get_shmem_header(shmem_st)); // --- DEBUG OUTPUT ---
    
    printf("Inject- %i : prog_pid-%i\n", getpid(), ((shared_memory_header*)shmem_st->shmaddr)->prog_pid );
    
    printf("Inject- %i : eax= %lx\n", getpid(), ((shared_memory_header*)shmem_st->shmaddr)->regs.eax );
    printf("Inject- %i : ecx= %lx\n", getpid(), ((shared_memory_header*)shmem_st->shmaddr)->regs.ecx );
    printf("Inject- %i : edx= %lx\n", getpid(), ((shared_memory_header*)shmem_st->shmaddr)->regs.edx );
    printf("Inject- %i : ebx= %lx\n", getpid(), ((shared_memory_header*)shmem_st->shmaddr)->regs.ebx );
    printf("Inject- %i : esp= %lx\n", getpid(), ((shared_memory_header*)shmem_st->shmaddr)->regs.esp );
    printf("Inject- %i : ebp= %lx\n", getpid(), ((shared_memory_header*)shmem_st->shmaddr)->regs.ebp );
    printf("Inject- %i : esi= %lx\n", getpid(), ((shared_memory_header*)shmem_st->shmaddr)->regs.esi );
    printf("Inject- %i : edi= %lx\n", getpid(), ((shared_memory_header*)shmem_st->shmaddr)->regs.edi );
    printf("Inject- %i : xcs= %lx\n", getpid(), ((shared_memory_header*)shmem_st->shmaddr)->regs.xcs );
    printf("Inject- %i : xss= %lx\n", getpid(), ((shared_memory_header*)shmem_st->shmaddr)->regs.xss );
    printf("Inject- %i : xds= %lx\n", getpid(), ((shared_memory_header*)shmem_st->shmaddr)->regs.xds );
    printf("Inject- %i : xes= %lx\n", getpid(), ((shared_memory_header*)shmem_st->shmaddr)->regs.xes );
    printf("Inject- %i : xfs= %lx\n", getpid(), ((shared_memory_header*)shmem_st->shmaddr)->regs.xfs );
    printf("Inject- %i : xgs= %lx\n", getpid(), ((shared_memory_header*)shmem_st->shmaddr)->regs.xgs );
    
    
    printf("Inject- %i : old_heap_pointer-%x\n", getpid(), (unsigned int)((shared_memory_header*)shmem_st->shmaddr)->old_heap_pointer );
    printf("Inject- %i : old_heap_size_value-%i\n", getpid(), ((shared_memory_header*)shmem_st->shmaddr)->old_heap_size_value );
    printf("Inject- %i : stack_size-%i\n", getpid(), ((shared_memory_header*)shmem_st->shmaddr)->stack_size );
    printf("Inject- %i : return_array_size-%i\n", getpid(), ((shared_memory_header*)shmem_st->shmaddr)->return_array_size );
    printf("Inject- %i : vma_array_size-%i\n", getpid(), ((shared_memory_header*)shmem_st->shmaddr)->vma_array_size );
                       
    printf("Inject- %i : Address of stack-%x\n", getpid(), (unsigned int)get_shmem_stack(shmem_st) );
    printf("Inject- %i : Address of return array-%x\n", getpid(), (unsigned int)get_shmem_ret(shmem_st,0) );
    printf("Inject- %i : Address of vma array-%x\n", getpid(), (unsigned int)get_shmem_vma(shmem_st,0));
}

void print_vma_array(shared_memory_struct* shmem_st)
{
    int i;
    for( i=0; i < (get_shmem_header(shmem_st)->vma_array_size)/sizeof(proto_vma_array); i++)
    {
        printf("Inject- %i : %x-%x\n", getpid(), get_shmem_vma(shmem_st,0)[i].vm_start, 
                                                 get_shmem_vma(shmem_st,0)[i].vm_end ); // --- DEBUG OUTPUT ---
    }
}

int correct_shmem(shared_memory_struct* shmem_st)
{
    return (((shared_memory_header*)shmem_st->shmaddr)->stack_size > 0) && 
           (((shared_memory_header*)shmem_st->shmaddr)->return_array_size > 0) && 
           (((shared_memory_header*)shmem_st->shmaddr)->vma_array_size > 0);
}

shared_memory_header* get_shmem_header(shared_memory_struct* shmem_st)
{
    return (shared_memory_header*)( shmem_st->shmaddr );
}

char* get_shmem_stack(shared_memory_struct* shmem_st)
{
    return (char*)( (shmem_st->shmaddr) + 
                    sizeof(shared_memory_header) );
}

return_address_in_buffer* get_shmem_ret(shared_memory_struct* shmem_st, int ret_number)
{
    if ( ret_number <= ((shared_memory_header*)shmem_st->shmaddr)->return_array_size )
    {
        return (return_address_in_buffer*)( (shmem_st->shmaddr) + 
                                            sizeof(shared_memory_header) + 
                                            ((shared_memory_header*)shmem_st->shmaddr)->stack_size + 
                                            ret_number*sizeof(return_address_in_buffer) );
    }
    else
        return NULL;
}

proto_vma_array* get_shmem_vma(shared_memory_struct* shmem_st, int vma_number)
{
    if ( vma_number <= ((shared_memory_header*)shmem_st->shmaddr)->vma_array_size )
    {
        return (proto_vma_array*)( (shmem_st->shmaddr) + 
                                   sizeof(shared_memory_header) + 
                                   ((shared_memory_header*)shmem_st->shmaddr)->stack_size + 
                                   ((shared_memory_header*)shmem_st->shmaddr)->return_array_size + 
                                   vma_number*sizeof(proto_vma_array) );
    }
    else
        return NULL;
}

shared_memory_struct* create_shared_memory(key_t shared_memory_key)
{
    shared_memory_struct* shmem_st = (shared_memory_struct*)malloc( sizeof(shared_memory_struct) );
    
    size_t stack_size = STACK_BUFFER_SIZE;
    size_t return_array_size = /*ret_array->ret_num*/MAX_ret_num * sizeof(return_address_in_buffer);
    size_t vma_array_size = /*process->plain_vma_array->vma_num*/MAX_vma_num * sizeof(proto_vma_array);
    
    shmem_st->real_shared_memory_size = sizeof(shared_memory_header) + 
                                        stack_size + 
                                        return_array_size + 
                                        vma_array_size;
    shmem_st->shared_memory_size = 0;
    
    shmem_st->shared_memory_key = shared_memory_key;
    
    if (( shmem_st->shmid = shmget(shmem_st->shared_memory_key, shmem_st->real_shared_memory_size, IPC_CREAT | 0666)) < 0 ){
        perror("shmget");
        return NULL;
    }
    
    if (( shmem_st->shmaddr = shmat(shmem_st->shmid, NULL, 0)) == (char *) -1 ){
        perror("shmat");
        return NULL;
    }
    
    ((shared_memory_header*)shmem_st->shmaddr)->prog_pid = 0;
    
    ((shared_memory_header*)shmem_st->shmaddr)->old_heap_pointer = NULL;
    ((shared_memory_header*)shmem_st->shmaddr)->old_heap_size_value = 0;
    
    ((shared_memory_header*)shmem_st->shmaddr)->max_stack_size = stack_size;
    ((shared_memory_header*)shmem_st->shmaddr)->stack_size = 0;
    ((shared_memory_header*)shmem_st->shmaddr)->return_array_size = 0;
    ((shared_memory_header*)shmem_st->shmaddr)->vma_array_size = 0;
    
    return shmem_st;
}

size_t init_shared_memory( shared_memory_struct* shmem_st,
                          process_struct* process,
                          struct user_regs_struct* reg_str,
                          size_t stack_size,
                          char* stack_pointer, 
                          return_addresses_array* ret_array )
{
    size_t return_array_size = ret_array->ret_num * sizeof(return_address_in_buffer);
    size_t vma_array_size = process->plain_vma_array->vma_num * sizeof(proto_vma_array);
    
    //printf("ret_num= %d | return_array_size= %d | MAX_ret_num= %d\n", ret_array->ret_num, return_array_size, MAX_ret_num);
    //printf("real_shared_memory_size= %d | stack= %d + return= %d\n", shmem_st->real_shared_memory_size, stack_size, return_array_size);
    
    void* shmem_stack_pointer     = NULL;
    void* shmem_ret_array_pointer = NULL;
    void* shmem_vma_array_pointer = NULL;
    
    shmem_st->shared_memory_size = sizeof(shared_memory_header) + 
                                   stack_size + 
                                   return_array_size + 
                                   vma_array_size;    
    
    //if (( shmem_st->shmid = shmget(shmem_st->shared_memory_key, shmem_st->shared_memory_size, IPC_CREAT | 0666)) < 0 ){
    //    perror("shmget");
    //    return -1;
    //}
    //
    //if (( shmem_st->shmaddr = shmat(shmem_st->shmid, NULL, 0)) == (char *) -1 ){
    //    perror("shmat");
    //    return -1;
    //}
    
    //((shared_memory_header*)shmaddr)->test_num = 123;
    ((shared_memory_header*)shmem_st->shmaddr)->prog_pid = process->pid;
    
    memcpy( &( ((shared_memory_header*)shmem_st->shmaddr)->regs ), reg_str, sizeof(struct user_regs_struct) );
    
    ((shared_memory_header*)shmem_st->shmaddr)->old_heap_pointer = (void*)process->start_brk;
    ((shared_memory_header*)shmem_st->shmaddr)->old_heap_size_value = process->brk - process->start_brk;
    
    ((shared_memory_header*)shmem_st->shmaddr)->stack_size = stack_size;
    ((shared_memory_header*)shmem_st->shmaddr)->return_array_size = return_array_size;
    ((shared_memory_header*)shmem_st->shmaddr)->vma_array_size = vma_array_size;
    
    //void *memcpy(void *dest, const void *src, size_t n);
    shmem_stack_pointer     = (shmem_st->shmaddr) + sizeof(shared_memory_header);
    shmem_ret_array_pointer = shmem_stack_pointer + stack_size;
    shmem_vma_array_pointer = shmem_ret_array_pointer + return_array_size;
    
    // Stack init at the start of the classifier
    //memcpy( shmem_stack_pointer, stack_pointer, stack_size );
    memcpy( shmem_ret_array_pointer, ret_array->ret_address, return_array_size );
    
    //printf("SHMEM_VMA_ARRAY= %x | process->plain_vma_array->vmas= %x| stack_size= %i\n", (unsigned int)shmem_vma_array_pointer, 
    //                                                                                     (unsigned int)process->plain_vma_array->vmas,
    //                                                                                     stack_size ); // --- DEBUG OUTPUT ---
    //getchar(); // ---
    
    memcpy( shmem_vma_array_pointer, process->plain_vma_array->vmas, vma_array_size );
    
    return shmem_st->shared_memory_size;
}

void destroy_shared_memory(shared_memory_struct* shmem_st)
{
    struct shmid_ds status; 
    if ( shmem_st == NULL ) return;
    
    if ( shmdt(shmem_st->shmaddr) == -1 ){
        perror("shmat");
        return;
    }
    if (( shmctl(shmem_st->shmid, IPC_RMID, &status)) == -1 ){
        perror("shmctl: shmctl failed");
        return;
    }
    free(shmem_st);
}

void* attach_shared_memory(shared_memory_struct* shmem_st)
{
    if (( shmem_st->shmid = shmget(/*SHARED_MEMORY_KEY*/shmem_st->shared_memory_key, shmem_st->real_shared_memory_size, 0666)) < 0 ){
        perror("shmget");
        return NULL;
    }
    
    if (( shmem_st->shmaddr = shmat(shmem_st->shmid, NULL, 0)) == (char *) -1 ){
        perror("shmat");
        return NULL;
    }
    
    ((shared_memory_header*)shmem_st->shmaddr)->prog_pid = getpid();
    
    return shmem_st->shmaddr;
}

void detach_shared_memory(shared_memory_struct* shmem_st)
{
    if ( shmdt(shmem_st->shmaddr) == -1 ){
        perror("shmat");
        return;
    }
}

shared_memory_struct* create_shared_gadget_array( key_t shared_memory_key, 
                                                  process_struct* process,
                                                  return_addresses_array* ret_array )
{
    shared_memory_struct* shmem_st = (shared_memory_struct*)malloc( sizeof(shared_memory_struct) );
    
    size_t gadget_array_size = SHARED_GADGET_ARRAY_SIZE;
    size_t vma_array_size = process->plain_vma_array->vma_num * sizeof(proto_vma_array);
    
    void* shmem_gadget_array_pointer = NULL;
    void* shmem_vma_array_pointer = NULL;
    
    shmem_st->real_shared_memory_size = sizeof(shared_gadget_array_header) + 
                                        gadget_array_size + 
                                        vma_array_size;
    shmem_st->shared_memory_size = shmem_st->real_shared_memory_size;
    shmem_st->shared_memory_key = shared_memory_key;
    
    if (( shmem_st->shmid = shmget(shmem_st->shared_memory_key, shmem_st->real_shared_memory_size, IPC_CREAT | 0666)) < 0 ){
        perror("shmget");
        return NULL;
    }
    
    if (( shmem_st->shmaddr = shmat(shmem_st->shmid, NULL, 0)) == (char *) -1 ){
        perror("shmat");
        return NULL;
    }
    
    ((shared_gadget_array_header*)shmem_st->shmaddr)->prog_pid = process->pid;
    
    ((shared_gadget_array_header*)shmem_st->shmaddr)->gadget_array_size = gadget_array_size;
    ((shared_gadget_array_header*)shmem_st->shmaddr)->vma_array_size = vma_array_size;
    
    //void *memcpy(void *dest, const void *src, size_t n);
    shmem_gadget_array_pointer = (shmem_st->shmaddr) + sizeof(shared_gadget_array_header);
    shmem_vma_array_pointer = shmem_gadget_array_pointer + gadget_array_size;
    
    // Stack init at the start of the classifier
    memcpy( shmem_vma_array_pointer, process->plain_vma_array->vmas, vma_array_size );
    
    return shmem_st;
}







