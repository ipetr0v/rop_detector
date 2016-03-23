#include "classifier.h"

extern process_list* proc_list;

inline rb_node* exec_prefix_rb_search(process_struct* process, unsigned int address)
{
    if ( address >= process->first_vma_start && address <= process->last_vma_end )
    {
        return search_prefix(process->exec_address_prefix_tree, address);
    }
    else 
        return NULL;
}

inline rb_node* vma_rb_search(process_struct* process, unsigned int address)
{
    return search_vma_by_address(process->vma_tree, address);
}

inline rb_node* exec_vma_rb_search(process_struct* process, unsigned int address)
{
    if ( address >= process->first_vma_start && address <= process->last_vma_end )
    {
        rb_node* node = search_vma_by_address(process->invert_vma_exec_tree, address);
        if ( node != NULL ) return NULL;
        return search_vma_by_address(process->vma_exec_tree, address);
    }
    else 
        return NULL;
}

inline rb_node* gadget_rb_search(vma_struct* vma, unsigned int address)
{
    return search_gadget_by_address( vma->gadget_tree, address);
}

return_addresses_array* classifier_address_search(process_struct* process, char* buffer_for_check, unsigned long buffer_len)
{
    unsigned long i = 0;
    unsigned int address = 0;
    unsigned long match_count = 0;
    rb_node* node = NULL;
    
    // DEBUG
    unsigned int exec_prefix_count = 0;
    unsigned int exec_vma_count = 0;
    unsigned int gadget_count = 0;
    // DEBUG
    
    return_addresses_array* ret_array = (return_addresses_array*)malloc( sizeof(return_addresses_array));
    int ret_array_buffer_size = 10;
    ret_array->ret_address = (return_address_in_buffer*)malloc( sizeof(return_address_in_buffer) * ret_array_buffer_size );
    
    while( i < buffer_len-1 - sizeof(unsigned int) )
    {
        address = *(int*)(buffer_for_check+i);
        //printf( "Address = %x |", address ); // --- DEBUG OUTPUT ---
        //printf( "Static analyze = %d of %d\n", i, buffer_len-1 - sizeof(unsigned int) ); // --- DEBUG OUTPUT ---
        //if ( exec_prefix_rb_search(process, address) != NULL )
        {
            exec_prefix_count++;
            node = exec_vma_rb_search(process, address);
            //printf("Address: %x\n", address);
            
            if (node != NULL)
            {
                exec_vma_count++;
                ///if ( gadget_rb_search( (vma_struct*)node->key, address ) != NULL )
                {
                    gadget_count++;
                    ret_array->ret_address[match_count].ret = (unsigned long*)address;
                    ret_array->ret_address[match_count].offset_in_buffer = i;
                    
                    match_count++;
                    if ( match_count >= ret_array_buffer_size ){
                        ret_array_buffer_size += 10;
                        ret_array->ret_address = (return_address_in_buffer*) realloc ( ret_array->ret_address, sizeof(return_address_in_buffer) * ret_array_buffer_size );
                    }
                }
                
                //printf("vma = %x-%x\n", ((vma_struct*)node->key)->vm_start, ((vma_struct*)node->key)->vm_end ); // --- DEBUG OUTPUT ---
            }
            else
            {
                //printf("\n"); // --- DEBUG OUTPUT ---
            }
        }
        i++;
    }
    ret_array->ret_num = match_count;
    
    if (LOGLVL >= DBGLOG) printf("Static: exec_vma= %d, gadget= %d\n", exec_vma_count, gadget_count ); // --- DEBUG OUTPUT ---
    
    return ret_array;
}

emulation_results_struct* classifier_emulation( process_struct* process, 
                                                char* buffer_for_check, unsigned long buffer_len, 
                                                return_addresses_array* ret_array)
{
    return init_emulator( process, buffer_for_check, buffer_len, ret_array );
}

unsigned long rop_detector_classifier(process_struct* process, char* buffer_for_check, unsigned long buffer_len, classifier_struct* classifier)
{
    return_addresses_array* ret_array = NULL;
    emulation_results_struct* emu_result = NULL;
    
    classifier->static_detection_count = 0;
    classifier->gadget_detection_count = 0;
    classifier->dynamic_detection_count = 0;
    classifier->system_call_detection_count = 0;
    
    //process_struct* process = get_process_by_pid( proc_list, pid );
    
    if ( process == NULL )
    {
        if (LOGLVL >= DBGLOG) printf("Prog: No such process\n"); // --- DEBUG OUTPUT ---
        return -1;
    }
    
    // STATIC CLASSIFIER
    ret_array = classifier_address_search( process, buffer_for_check, buffer_len );
    classifier->static_detection_count = ret_array->ret_num;
    if (LOGLVL >= DBGLOG) printf("Prog: Static return number = %i\n", ret_array->ret_num); // --- DEBUG OUTPUT ---

    if (LOGLVL >= ADVLOG) {
        int i;
        for(i=0; i<ret_array->ret_num; i++)
        {
            printf("Prog: Test %i ret - %x\n", i, (unsigned int)(ret_array->ret_address[i].ret) ); // --- DEBUG OUTPUT ---
            printf("Prog: Test %i offset_in_buffer - %i\n", i, (unsigned int)(ret_array->ret_address[i].offset_in_buffer) ); // --- DEBUG OUTPUT ---
        }
    }
    
    // DYNAMIC CLASSIFIER
    if ( ret_array->ret_num > 0 ) {
        emu_result = classifier_emulation( process, buffer_for_check, buffer_len, ret_array );
        
        if ( emu_result != NULL ) {
            classifier->gadget_detection_count = emu_result->gadget_number;
            classifier->dynamic_detection_count = emu_result->ret_number;
            classifier->system_call_detection_count = emu_result->system_call_number;
            
            if (LOGLVL >= DBGLOG) printf( "Prog: Gadget count= %d, Dynamic count = %d, SVC count= %d\n", 
                                        classifier->gadget_detection_count, 
                                        classifier->dynamic_detection_count,
                                        classifier->system_call_detection_count); // --- DEBUG OUTPUT ---
        }
    }
    else {
        if (LOGLVL >= DBGLOG) printf("Prog: No dynamic classifier\n"); // --- DEBUG OUTPUT ---
    }
    
    if ( ret_array != NULL ) {
        if ( ret_array->ret_address != NULL ) {
            free(ret_array->ret_address);
        }
        free(ret_array);
    }
    if ( emu_result != NULL ) {
        free(emu_result);
    }
    return classifier->dynamic_detection_count;
}


    
    //for(i=0; i<ret_array->ret_num; i++)
    //{
    //    printf("Prog: Test %i ret - %x\n", i, (unsigned int)(ret_array->ret_address[i].ret) ); // --- DEBUG OUTPUT ---
    //    printf("Prog: Test %i offset_in_buffer - %i\n", i, (unsigned int)(ret_array->ret_address[i].offset_in_buffer) ); // --- DEBUG OUTPUT ---
    //}









