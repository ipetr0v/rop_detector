#include "inject.h"

shared_memory_struct* shmem_st;

size_t MAX_ret_num = MAX_RETURN_NUMBER;
size_t MAX_vma_num = 0;

int dynamic_classifier(lib_arguments_struct* library_arguments)
{
    int gadget_number = 0;
    
    emulator_struct* emul_struct;
    //int emulation_result = 0;
    
    char *stack_buffer_pointer = library_arguments->stack_buffer;
    return_addresses_array ret_array;
    int ret_counter = 0;
    
    emulation_results_struct emu_results;
    emulation_results_struct tmp_emu_results;
    emu_results.ret_number = 0;
    emu_results.system_call_number = 0;
    
    //print_shmem(&shmem_st);      // --- DEBUG OUTPUT ---
    //print_vma_array(&shmem_st);  // --- DEBUG OUTPUT ---
    
    shmem_st = library_arguments->shmem_st;
    ///memcpy( stack_buffer_pointer, get_shmem_stack(shmem_st), STACK_BUFFER_SIZE);
    init_emulator_heap( get_shmem_header(shmem_st)->old_heap_pointer, get_shmem_header(shmem_st)->old_heap_size_value );
    init_emulator_stack( stack_buffer_pointer,      /*get_shmem_header(shmem_st)->stack_size*/STACK_BUFFER_SIZE,
                         get_shmem_stack(shmem_st), /*get_shmem_header(shmem_st)->stack_size*/STACK_BUFFER_SIZE );
    
    if (LOGLVL >= DBGLOG) {
        printf("\n"); // --- DEBUG OUTPUT ---
        printf("\n"); // --- DEBUG OUTPUT ---
        printf("\n"); // --- DEBUG OUTPUT ---
        printf("\n"); // --- DEBUG OUTPUT ---
        printf("================== NEW EMULATOR START ===================\n"); // --- DEBUG OUTPUT ---
    }
    
    if (LOGLVL >= ADVLOG) printf("Inject- %i : Stack= %x, Shmem_stack= %x\n", getpid(), (unsigned int)stack_buffer_pointer, (unsigned int)get_shmem_stack(shmem_st) ); // --- DEBUG OUTPUT ---
    if (LOGLVL >= ADVLOG) printf("Inject- %i : Test from shared memory - %x: %x\n", getpid(), (unsigned int)((int*)get_shmem_stack(shmem_st)  ), *((int*)get_shmem_stack(shmem_st)    ) ); // --- DEBUG OUTPUT ---
    if (LOGLVL >= ADVLOG) printf("Inject- %i : Test from shared memory - %x: %x\n", getpid(), (unsigned int)((int*)get_shmem_stack(shmem_st)+1), *((int*)get_shmem_stack(shmem_st) + 1) ); // --- DEBUG OUTPUT ---
    //printf("Inject- %i : Waiting for fork\n", getpid()); // --- DEBUG OUTPUT ---
    //getchar();                                           // --- DEBUG INPUT ---
    
    ret_array.ret_num = get_shmem_header(shmem_st)->return_array_size / sizeof(return_address_in_buffer);
    set_vma_array( get_shmem_vma(shmem_st,0), (get_shmem_header(shmem_st)->vma_array_size)/sizeof(proto_vma_array) );
    
    if (LOGLVL >= DBGLOG) printf("Inject- %i : Return number - %i\n", getpid(), ret_array.ret_num ); // --- DEBUG OUTPUT ---
    for( ret_counter=0; ret_counter < ret_array.ret_num; ret_counter++)
    {
        if (LOGLVL >= DBGLOG) printf("==========================================================\n"); // --- DEBUG OUTPUT ---
        ret_array.ret_address = get_shmem_ret(shmem_st,ret_counter);
        
        if (LOGLVL >= DBGLOG) printf("Inject- %i : Ret counter - %d\n", getpid(), ret_counter ); // --- DEBUG OUTPUT ---
        if (LOGLVL >= DBGLOG) printf("Inject- %i : Test ret - %x\n", getpid(), (unsigned int)(ret_array.ret_address->ret) ); // --- DEBUG OUTPUT ---
        if (LOGLVL >= DBGLOG) printf("Inject- %i : Test offset_in_buffer - %i\n", getpid(), (unsigned int)(ret_array.ret_address->offset_in_buffer) ); // --- DEBUG OUTPUT ---
        
        if ( find_gadget( (unsigned int)(ret_array.ret_address->ret) ) == 0 ) {
            if (LOGLVL >= DBGLOG) printf("Inject- %i : Return address - %x not a gadget\n", getpid(), (unsigned int)(ret_array.ret_address->ret) ); // --- DEBUG OUTPUT ---
        }
        else
        {
            if (LOGLVL >= DBGLOG) printf("Inject- %i : Return address - %x IS a gadget\n", getpid(), (unsigned int)(ret_array.ret_address->ret) ); // --- DEBUG OUTPUT ---
            gadget_number++;
            
            emul_struct = new_emulator();
            init_emulator( emul_struct, shmem_st, (uint32_t)stack_buffer_pointer, ret_array.ret_address );
            
            if (LOGLVL >= DBGLOG) emu_log_level_set(emu_logging_get(emul_struct->emulator), EMU_LOG_DEBUG); // --- DEBUG OUTPUT ---
            
            init_saved_memory();
            
            run_emulator(emul_struct, &tmp_emu_results);
            emu_results.ret_number = MAX(emu_results.ret_number, tmp_emu_results.ret_number );
            emu_results.system_call_number = MAX(emu_results.system_call_number, tmp_emu_results.system_call_number );
            
            if (LOGLVL >= DBGLOG) printf("Inject- %i : Ret number= %d | SVC number= %d\n", getpid(), tmp_emu_results.ret_number, 
                                                                                                     tmp_emu_results.system_call_number); // --- DEBUG OUTPUT ---
            if (LOGLVL >= DBGLOG) printf("Inject- %i : Finishing emulator instance number= %i\n", getpid(), ret_counter); // --- DEBUG OUTPUT ---
            
            restore_saved_memory();
            destroy_saved_memory();
            destroy_emulator(emul_struct);
        }
    }
    if (LOGLVL >= DBGLOG) printf("==========================================================\n"); // --- DEBUG OUTPUT ---
    destroy_emulator_heap();
    
    emu_results.gadget_number = gadget_number;
    get_shmem_header(shmem_st)->emu_results = emu_results;
    
    if (LOGLVL >= DBGLOG) printf("Inject- %i : Finishing the final emulator | Ret number= %i\n", getpid(), emu_results.ret_number); // --- DEBUG OUTPUT ---
    return 0;
}


