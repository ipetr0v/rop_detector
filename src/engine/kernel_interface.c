#include "kernel_interface.h"

base_array* kernel_command(int command, int pid)
{
    int command_msg_size = 0;
    int responde_msg_size = 0;
    int data_msg_size = 0;
    proto_command* command_msg = NULL;
    proto_respond* responde_msg = NULL;
    base_array* data_msg = NULL;
    
    // Create command to kernel module
    command_msg_size = sizeof(proto_command);
    command_msg = (proto_command*)malloc( sizeof(proto_command) );
    command_msg->command = command;
    command_msg->pid = pid;
    
    //printf("Sending request, size= %i\n", command_msg_size); // --- DEBUG OUTPUT ---
    if ( send_to_module( (char*)command_msg, command_msg_size ) < 0 ){
		return NULL;
    }
    free(command_msg);
    
    //printf("Receiving info answer\n"); // --- DEBUG OUTPUT ---
    responde_msg_size = sizeof(proto_respond);
    responde_msg = (proto_respond*)malloc( sizeof(proto_respond) );
    if ( (responde_msg_size = recv_from_module( (char*)responde_msg, responde_msg_size )) < 0 ){
		return NULL;
    }
    data_msg_size = responde_msg->data_size; // Buffer malloc size
    
    switch ( responde_msg->command ) 
    {
		/*case CLONE_PROC:
            if ( responde_msg->success )
            {
                data_msg = (base_array*)malloc( sizeof(base_array) );
                data_msg->pid = responde_msg->pid;
            }
            else
                return NULL;
            break;*/
        case DELETE_VMA:
            return NULL;
            break;
		default:
            //printf("Receiving answer\n"); // --- DEBUG OUTPUT ---
            data_msg = (base_array*)malloc( sizeof(base_array) );
            data_msg->array = malloc( data_msg_size );
            if ( (data_msg_size = recv_from_module( (char*)data_msg->array, data_msg_size )) < 0 ){
                return NULL;
            }
            data_msg->num = data_msg_size;
            
            //printf("Incomming message size= %i\n", data_msg_size); // --- DEBUG OUTPUT ---
            break;
    }
    
    free(responde_msg);
    return data_msg;
}

process_array* ask_for_process_pids()
{
    int i;
    
    base_array* base_ar = NULL;
    process_array* proc_array = (process_array*)malloc( sizeof(process_array) );
    
    printf("Ask for process pids\n"); // --- DEBUG OUTPUT ---
    
    if ( (base_ar = kernel_command(GET_PIDS, 0)) == NULL )
        return NULL;
    
    proc_array->proc_num = base_ar->num / sizeof(proto_process_array);
    proc_array->pids = (proto_process_array*)base_ar->array;
    
    printf("Received= %i, processes= %i\n", base_ar->num, proc_array->proc_num); // --- DEBUG OUTPUT ---
    
    // --- DEBUG OUTPUT ---
    //for (i = 0; i<proc_array->proc_num; i++)
    //{
    //    printf("P-%i: = %i || ", i, proc_array->pids[i].pid );
    //}
    // --- DEBUG OUTPUT ---
    
    free(base_ar);
    return proc_array;
}

vma_array* ask_for_vma_by_pid(int pid)
{
    base_array* base_ar = NULL;
    vma_array* vma_ar = (vma_array*)malloc( sizeof(vma_array) );
    
    //printf("Ask for vma by pid %i\n", pid); // --- DEBUG OUTPUT ---
    
    if ( (base_ar = kernel_command(GET_VMA, pid)) == NULL )
        return NULL;
    
    vma_ar->vma_num = base_ar->num / sizeof(proto_vma_array);
    vma_ar->vmas = (proto_vma_array*)base_ar->array;;
    
    //printf("Received= %i, vma number= %i\n", base_ar->num, vma_ar->vma_num); // --- DEBUG OUTPUT ---
    
    free(base_ar);
    return vma_ar;
}

int fork_process_by_pid(pid_t pid)
{
    pid_t new_pid;
    base_array* base_ar = NULL;
    
    base_ar = kernel_command(CLONE_PROC, pid);
    
    if (base_ar != NULL)
    {
        free(base_ar);
        return new_pid;
    }
    else
        return 0;
}

int delete_vma(pid_t pid)
{
    pid_t new_pid;
    base_array* base_ar = NULL;
    
    //printf("Deleting vma %i\n", pid); // --- DEBUG OUTPUT ---
    base_ar = kernel_command(DELETE_VMA, pid);
    
    if (base_ar != NULL)
    {
        free(base_ar);
        return 0;
    }
    else
        return 0;
}










