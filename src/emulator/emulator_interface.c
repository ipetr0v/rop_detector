#include "emulator_interface.h"

extern shared_memory_struct* shmem_st;

uintptr_t libinject_fork_handle;

void get_process_regs(pid_t pid, struct user_regs_struct* reg_str)
{
    ptrace_attach(pid);
    ptrace(PTRACE_GETREGS, pid, NULL, reg_str);
    ptrace_detach(pid);
}

pid_t clone_process(/*pid_t pid_for_clone*/process_struct* process, void* data, size_t datalen)
{
	uintptr_t  emulator_pid;
    int load_ret;
    
	if (process->hp) 
    {
        //libinject_fork_handle = hotpatch_dlopen( process->hp, "./bin/libinject_fork.so" );
        if ( process->libinject_fork_handle <= 0 ) {
            if (LOGLVL >= ERRLOG) printf("Prog: hotpatch_dlopen for %d failed\n", process->pid/*pid_for_clone*/); // --- DEBUG OUTPUT ---
            return -1;
        }
        
        load_ret = hotpatch_library_call( process->hp, process->libinject_fork_handle, "fork_process",
                                          data, datalen, &emulator_pid);
        
        if ( load_ret < 0 ) {
            if (LOGLVL >= ERRLOG) printf("Prog: hotpatch_inject_library for clone to %d failed\n", process->pid); // --- DEBUG OUTPUT ---
            return -1;
        }
        if ( (pid_t)emulator_pid <= 0 ) {
            if (LOGLVL >= ERRLOG) printf("Prog: process- %d clone failed\n", process->pid); // --- DEBUG OUTPUT ---
            return -1;
        }
        if (LOGLVL >= DBGLOG)
            printf("Prog: hotpatch_inject_library for clone to %d success-%i | New pid= %i\n", process->pid, load_ret, 
                                                                                               (pid_t)emulator_pid); // --- DEBUG OUTPUT ---
        
        ///while( ptrace_attach((pid_t)emulator_pid) < 0 ) ;
	}
    
    process->emulator_hp = hotpatch_create(emulator_pid, 0);
    return (pid_t)emulator_pid;
}

pid_t create_emulator(process_struct* process)
{
    pid_t emulator_pid;
    
    lib_arguments_struct* data = (lib_arguments_struct*)malloc( sizeof(lib_arguments_struct) );
    size_t datalen = sizeof(lib_arguments_struct);
    
    if ( (process->hp = hotpatch_create(process->pid, 0)) == NULL ) {
        if (LOGLVL >= ERRLOG) printf("Prog: hotpatch_create for clone to %d failed\n", process->pid); // --- DEBUG OUTPUT ---
        return -1;
    }
    if ( (process->libinject_fork_handle = hotpatch_dlopen( process->hp, "/mnt/hgfs/_Share/diplom/bin/libinject_fork.so" )) <= 0 ) {
        if (LOGLVL >= ERRLOG) printf("Prog: hotpatch_dlopen for clone to %d failed\n", process->pid); // --- DEBUG OUTPUT ---
        return -1;
    }
    
    data->main_prog_pid = getpid();
    data->name_len = 0;
    data->shared_memory_key = shmem_st->shared_memory_key;
    data->shared_memory_size = shmem_st->shared_memory_size;
    data->stack_buffer = NULL;
    data->shmem_st = NULL;
    
    if ( (emulator_pid = clone_process( process, data, datalen )) < 0 )
        return -1;
    
    free(data);
    return emulator_pid;
}

emulation_results_struct* init_emulator( process_struct* process, 
                                         char* buffer_for_check, size_t buffer_len, 
                                         return_addresses_array* ret_array )
{
    int load_ret;
    pid_t emulator_return = -1;
    struct user_regs_struct regs;
    emulation_results_struct* emu_result = NULL;
    
    get_process_regs(process->pid, &regs);
    if (LOGLVL >= DBGLOG) printf("Prog: Registers for %d taken\n", process->pid); // --- DEBUG OUTPUT ---
    
    init_shared_memory( shmem_st, 
                        process, 
                        &regs, 
                        buffer_len, 
                        buffer_for_check, 
                        ret_array );
    
    //printf("Prog: Test from shared memory - %x\n", (unsigned int)(get_shmem_ret(shmem_st,0)->ret)    ); // --- DEBUG OUTPUT ---
    //printf("Prog: Test from shared memory - %i\n", (unsigned int)(get_shmem_ret(shmem_st,0)->offset_in_buffer) ); // --- DEBUG OUTPUT ---
    
    load_ret = hotpatch_library_call( process->emulator_hp, process->libinject_fork_handle, "run_dynamic_classifier",
                                      NULL, 0, &emulator_return);
    
    if ( load_ret < 0 ) {
        if (LOGLVL >= ERRLOG) printf("Prog: Emulator- %d run failed\n", process->emulator_hp->pid); // --- DEBUG OUTPUT ---
        return NULL;
    }
    if ( emulator_return < 0 ) {
        if (LOGLVL >= ERRLOG) printf("Prog:"CLR_RED" Emulator- %d run failed (internal error)"CLR_RESET"\n", process->emulator_hp->pid); // --- DEBUG OUTPUT ---
        getchar();
        return NULL;
    }
    if (LOGLVL >= DBGLOG) printf("Prog: Emulator finished- %d\n", emulator_return); // --- DEBUG OUTPUT ---
    
    emu_result = (emulation_results_struct*)malloc( sizeof(emulation_results_struct) );
    emu_result->gadget_number = get_shmem_header(shmem_st)->emu_results.gadget_number;
    emu_result->ret_number = get_shmem_header(shmem_st)->emu_results.ret_number;
    emu_result->system_call_number = get_shmem_header(shmem_st)->emu_results.system_call_number;
    
    return emu_result;
}

///int emulation_results(process_struct* emu_parent_process, pid_t emulator_pid)
///{
///    if ( ptrace_cont(emulator_pid) < 0) {
///        if (LOGLVL >= ERRLOG) printf("Prog: Emulator- %d run failed\n", emulator_pid); // --- DEBUG OUTPUT ---
///    }
///    else {
///        if (LOGLVL >= DBGLOG) printf("Prog: Emulator- %d running\n", emulator_pid); // --- DEBUG OUTPUT ---
///    }
///    
///    if (LOGLVL >= DBGLOG) printf("Prog: Waiting emulator- %d for exit\n", emulator_pid); // --- DEBUG OUTPUT ---
///    waitpid_for_exit(emulator_pid);
///    if (LOGLVL >= DBGLOG) printf("Prog: Emulator- %d wait finished\n", emulator_pid); // --- DEBUG OUTPUT ---
///    
///    return get_shmem_header(shmem_st)->emu_results.ret_number;
///}

void destroy_emulator(process_struct* emu_parent_process)
{
	uintptr_t result1, result2;
    void* data = &(emu_parent_process->emulator_hp->pid);
    size_t datalen = sizeof(pid_t);
    int load_ret = -1;
    
    if (LOGLVL >= DBGLOG) printf("Prog: Destroying emulator for %d\n", emu_parent_process->pid); // --- DEBUG OUTPUT ---
    kill(emu_parent_process->emulator_hp->pid, SIGKILL);
    if (LOGLVL >= DBGLOG) printf("Prog: Emulator-%d killed\n", emu_parent_process->emulator_hp->pid); // --- DEBUG OUTPUT ---
    
    ///load_ret = hotpatch_library_call( emu_parent_process->emulator_hp, emu_parent_process->libinject_fork_handle, "exit_process",
    ///                                  NULL, 0, &result2);
    ///if ( load_ret < 0 ) {
    ///    if (LOGLVL >= ERRLOG) printf("Prog: hotpatch_inject_library for wait to %d failed\n", emu_parent_process->hp->pid); // --- DEBUG OUTPUT ---
    ///}
    ///if (LOGLVL >= DBGLOG) printf("Prog: Library-wait load success-%i | result= %i\n", load_ret, (pid_t)result2); // --- DEBUG OUTPUT ---
    
    load_ret = hotpatch_library_call( emu_parent_process->hp, emu_parent_process->libinject_fork_handle, "wait_emulator",
                                      data, datalen, &result2);
    if ( load_ret < 0 ) {
        if (LOGLVL >= ERRLOG) printf("Prog: hotpatch_inject_library for wait to %d failed\n", emu_parent_process->hp->pid); // --- DEBUG OUTPUT ---
    }
    if (LOGLVL >= DBGLOG) printf("Prog: Library-wait load success-%i | result= %i\n", load_ret, (pid_t)result2); // --- DEBUG OUTPUT ---
    
    if ( hotpatch_dlclose( emu_parent_process->hp, emu_parent_process->libinject_fork_handle ) < 0 ) {
        printf("Prog: hotpatch_dlclose for %d failed\n", emu_parent_process->hp->pid); // --- DEBUG OUTPUT ---
        return;
    }
    
    if (LOGLVL >= DBGLOG) printf("Prog: Emulator- %d exited\n", emu_parent_process->emulator_hp->pid); // --- DEBUG OUTPUT ---
    hotpatch_destroy(emu_parent_process->emulator_hp);
    hotpatch_destroy(emu_parent_process->hp);
}




//in emulation results
//printf("Prog: get_shmem_header(shmem_st)- %x\n", (unsigned int)(get_shmem_header(shmem_st)) ); // --- DEBUG OUTPUT ---
//printf("Prog: ->emu_results- %x\n", (unsigned int)&(get_shmem_header(shmem_st)->emu_results.ret_number) ); // --- DEBUG OUTPUT ---
//printf("Prog: .ret_number- %i\n", (unsigned int)(get_shmem_header(shmem_st)->emu_results.ret_number) ); // --- DEBUG OUTPUT ---



    //load_ret = hotpatch_inject_library( hp, "./bin/libinject_fork.so", "wait_emulator",
    //                                        data, datalen, &result1, &result2);
    //if ( load_ret < 0 || ptrace_detach(hp->pid) < 0 ) {
    //    printf("Prog: hotpatch_inject_library for wait to %d failed\n", hp->pid); // --- DEBUG OUTPUT ---
    //}
    //printf("Prog: Library-wait load success-%i | result= %i\n", load_ret, (pid_t)result2); // --- DEBUG OUTPUT ---
    
    //hotpatch_destroy(hp);
    //printf("Prog: Hotpatch-clone destroyed\n"); // --- DEBUG OUTPUT ---
    




        // --- WRITE STACK ---
        //while(1) {
        //    if (ptrace(PTRACE_SINGLESTEP, pid_for_clone, NULL, NULL) < 0) {
        //        printf("Ptrace singlestep for PID %d failed\n", pid_for_clone); // --- DEBUG OUTPUT ---
        //        return -1;
        //    }
        //    wait(&status);
        //    if(WIFEXITED(status)) {
        //        printf("Exited PID %d\n", pid_for_clone); // --- DEBUG OUTPUT ---
        //        return -1;
        //    }
        //    if(i == 0) {
        //        printf("%i-----------------------------------\n",i); // --- DEBUG OUTPUT ---
        //        print_process_regs(pid_for_clone); // --- DEBUG OUTPUT ---
        //        
        //        ptrace(PTRACE_GETREGS, pid_for_clone, NULL, &reg_str);
        //        
        //        for(j=0; j<30; j++)
        //        {
        //            word = ptrace(PTRACE_PEEKTEXT,
        //                        pid_for_clone, reg_str.esp + j*sizeof(long),
        //                        NULL);
        //            printf("ESP: %lx | value: %lx\n",
        //                reg_str.esp + j*sizeof(long), word);
        //        }
        //    }
        //    else
        //    {
        //        printf("%i-----------------------------------\n",i); // --- DEBUG OUTPUT ---
        //        print_process_regs(pid_for_clone); // --- DEBUG OUTPUT ---
        //        getchar(); // --- DEBUG INPUT ---
        //    }
        //    i++;
        //}


            
    // --- TEST ---
    //return_addresses_array* _ret_array = (return_addresses_array*)malloc( sizeof(return_addresses_array) );
    //_ret_array->ret_num = 2;
    //_ret_array->ret_address = (return_address_in_buffer*)malloc( 2*sizeof(return_address_in_buffer) );
    //_ret_array->ret_address[0].offset_in_buffer = 0;
    //_ret_array->ret_address[0].ret = (void*)0x0804847d;//0x0804847d;
    //_ret_array->ret_address[1].offset_in_buffer = sizeof(int);
    //_ret_array->ret_address[1].ret = (void*)0x0804847d;//0x0804847d;
    // --- TEST ---
    
    //if ( (child_pid = fork()) == 0 )
    //    exec_function("./bin/junk");
    