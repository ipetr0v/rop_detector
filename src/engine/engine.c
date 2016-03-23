#include "engine.h"

process_list* proc_list;
rb_tree* network_info_tree;
shared_memory_struct* shmem_st;
pid_t test_pid = 0;

size_t MAX_ret_num = MAX_RETURN_NUMBER;
size_t MAX_vma_num = 0;

void *libinject_fork_handle;
void *libinject_handle;

int engine_test_run(unsigned long random_address_iteration_number)
{
    classifier_struct classifier;
    char *error;
    
    // --- TEST ---
    process_struct* target_process;
    int i,j,k,m;
    int work;
    int multi;
    unsigned int address_number = 16384;//262144;//5000;
    unsigned long buffer_size = sizeof(unsigned int) * address_number;
    unsigned int* buffer = (unsigned int*)malloc( buffer_size );
    char* iter = (char*)buffer;
    double time0, time1;
    rb_node* node = NULL;
    unsigned int address = 0;
    unsigned long match_count = 0;
    int general_count = 0;
    int shellcode_count = 0;
    
    double average_speed = 0;
    double average_static_detection_count = 0;
    double average_gadget_detection_count = 0;
    double average_dynamic_detection_count = 0;
    double average_system_call_detection_count = 0;
    
    process_struct* process;
    unsigned long work_max = random_address_iteration_number;//1;
    int multi_max = 1;
    // --- TEST ---
    
    ///if (LOGLVL >= NONLOG) printf("Engine init\n"); // --- DEBUG OUTPUT ---
    ///client_init(9999,5555);
    ///if ( !(libinject_fork_handle = dlopen ("/mnt/hgfs/_Share/diplom/bin/libinject_fork.so", RTLD_LAZY)) ) {
    ///    if (LOGLVL >= ERRLOG) fputs (dlerror(), stderr);
    ///    return 1;
    ///}
    ///if ( !(libinject_handle = dlopen ("/mnt/hgfs/_Share/diplom/bin/libinject.so", RTLD_LAZY)) ) {
    ///    if (LOGLVL >= ERRLOG) fputs (dlerror(), stderr);
    ///    return 1;
    ///}
    ///if ( (shmem_st = create_shared_memory(SHARED_MEMORY_KEY)) == NULL ) {
    ///    if (LOGLVL >= ERRLOG) printf("Shared memory error\n"); // --- DEBUG OUTPUT ---
    ///    return -1;
    ///}
    ///if ( (proc_list = init_process_list()) == NULL ) {
    ///    if (LOGLVL >= ERRLOG) printf("Process list error\n"); // --- DEBUG OUTPUT ---
    ///    return -1;
    ///}
    ///if ( (network_info_tree = network_info_tree_init()) == NULL ) {
    ///    if (LOGLVL >= ERRLOG) printf("Network info error\n"); // --- DEBUG OUTPUT ---
    ///    return -1;
    ///}
    ///
    ///if (LOGLVL >= NONLOG) printf("Programm start\n"); // --- DEBUG OUTPUT ---
    
    // --- TEST --- 
    srand(time(0));
    if ( buffer_size > STACK_BUFFER_SIZE ) {
        if (LOGLVL >= ERRLOG) printf("Too big buffer\n"); // --- DEBUG OUTPUT ---
        return -1;
    }
    target_process = get_process_by_pid( proc_list, test_pid );
    printf("Executable space size = %d\n", target_process->executable_space_size);
    //process = get_process_by_pid( proc_list, getpid() );
    for(work = 0; work < work_max; work++)
    {
        //srand(time(0));
        for(i=0; i<address_number; i++)
        {
            //buffer[i] = rand();
            ((unsigned int*)get_shmem_stack(shmem_st))[i] = rand();//0x0804846F;
        }
        //((unsigned int*)get_shmem_stack(shmem_st))[0] = 0x080484DD; // Test function
        //((unsigned int*)get_shmem_stack(shmem_st))[1] = 0x080484DD; // Test function
        //((unsigned int*)get_shmem_stack(shmem_st))[2] = 0x08048486;// Retn          //0x09968000; // Heap address
        //((unsigned int*)get_shmem_stack(shmem_st))[3] = 0x08048486;// Retn
        wtime(&time0);
        for(multi = 0; multi < multi_max; multi++)
        {
            rop_detector_classifier( target_process, get_shmem_stack(shmem_st)/*(char*)buffer*/, buffer_size, &classifier );
        }
        wtime(&time1);  
        //printf("Time in seconds = %.02f sec\n", time1-time0);
        /*if (LOGLVL <= ERRLOG && multi_max > 1)*/
        ///{
        ///    printf( "Capability = %.02f Mbps | Addr= %d, Gadg= %d, Ret= %d, SVC= %d\n", 
        ///            8 * ((buffer_size*multi_max) / (time1-time0)) / (1024.0*1024.0), 
        ///            classifier.static_detection_count,
        ///            classifier.gadget_detection_count,
        ///            classifier.dynamic_detection_count,
        ///            classifier.system_call_detection_count );
        ///}
        general_count++;
        if ( classifier.dynamic_detection_count > 4 && classifier.system_call_detection_count > 0 )
        {
            shellcode_count++;
            printf( CLR_YELLOW"Speed = %.02f Mbps | Addr= %d, Gadg= %d, Ret= %d, SVC= %d | "\
                    CLR_RED"Shellcode found - %d/%d"CLR_RESET"\n", 
                    8 * ((buffer_size*multi_max) / (time1-time0)) / (1024.0*1024.0), 
                    classifier.static_detection_count,
                    classifier.gadget_detection_count,
                    classifier.dynamic_detection_count,
                    classifier.system_call_detection_count,
                    shellcode_count, general_count);
        }
        else
        {
            printf( CLR_YELLOW"Speed = %.02f Mbps | Addr= %d, Gadg= %d, Ret= %d, SVC= %d | "\
                    CLR_GREEN"Legitimate - %d/%d"CLR_RESET"\n", 
                    8 * ((buffer_size*multi_max) / (time1-time0)) / (1024.0*1024.0), 
                    classifier.static_detection_count,
                    classifier.gadget_detection_count,
                    classifier.dynamic_detection_count,
                    classifier.system_call_detection_count,
                    shellcode_count, general_count);
        }
        average_speed += 8 * ((buffer_size*multi_max) / (time1-time0)) / (1024.0*1024.0);
        average_static_detection_count += classifier.static_detection_count;
        average_gadget_detection_count += classifier.gadget_detection_count;
        average_dynamic_detection_count += classifier.dynamic_detection_count;
        average_system_call_detection_count += classifier.system_call_detection_count;
    }
    printf(CLR_CYAN"=========================== TEST REPORT =========================="CLR_RESET"\n");
    printf("Average speed = %.02f Mbps\n", average_speed / (double)general_count);
    printf("Shellcode - %d/%d\n", shellcode_count, general_count);
    printf("Average detection: Addr= %.02f, Gadg= %.02f, Ret= %.02f, SVC= %.02f\n", 
            average_static_detection_count / (double)general_count,
            average_gadget_detection_count / (double)general_count,
            average_dynamic_detection_count / (double)general_count,
            average_system_call_detection_count / (double)general_count);
    printf("Test buffer size = %lu\n", buffer_size);
    printf("Executable space size = %d\n", target_process->executable_space_size);
    printf("Memory space size = %d\n", target_process->memory_space_size);
    printf(CLR_CYAN"=================================================================="CLR_RESET"\n");
    free(buffer);
    // --- TEST ---
    
    ///destroy_process_list(proc_list);
    ///destroy_network_info_tree(network_info_tree);
    ///destroy_shared_memory(shmem_st);
    ///dlclose(libinject_handle);
    ///dlclose(libinject_fork_handle);
    ///if (LOGLVL >= NONLOG) printf("Prog was correctly finished\n"); // --- DEBUG OUTPUT ---
    return 0;
}

int engine_init()
{
    if (LOGLVL >= NONLOG) printf("Engine init\n"); // --- DEBUG OUTPUT ---
    client_init(9999,5555);
    if ( !(libinject_fork_handle = dlopen ("/mnt/hgfs/_Share/diplom/bin/libinject_fork.so", RTLD_LAZY)) ) {
        if (LOGLVL >= ERRLOG) fputs (dlerror(), stderr);
        return 1;
    }
    if ( !(libinject_handle = dlopen ("/mnt/hgfs/_Share/diplom/bin/libinject.so", RTLD_LAZY)) ) {
        if (LOGLVL >= ERRLOG) fputs (dlerror(), stderr);
        return 1;
    }
    if ( (shmem_st = create_shared_memory(SHARED_MEMORY_KEY)) == NULL ) {
        if (LOGLVL >= ERRLOG) printf("Shared memory error\n"); // --- DEBUG OUTPUT ---
        return -1;
    }
    if ( (proc_list = init_process_list()) == NULL ) {
        if (LOGLVL >= ERRLOG) printf("Process list error\n"); // --- DEBUG OUTPUT ---
        return -1;
    }
    if ( (network_info_tree = network_info_tree_init()) == NULL ) {
        if (LOGLVL >= ERRLOG) printf("Network info error\n"); // --- DEBUG OUTPUT ---
        return -1;
    }
    if ( (init_process_emulators(proc_list)) < 0 ) {
        if (LOGLVL >= ERRLOG) printf("Emulator init error error\n"); // --- DEBUG OUTPUT ---
        return -1;
    }
    
    if (LOGLVL >= NONLOG) printf("Engine start\n"); // --- DEBUG OUTPUT ---
}

void engine_destroy()
{
    destroy_process_list(proc_list);
    destroy_network_info_tree(network_info_tree);
    destroy_shared_memory(shmem_st);
    dlclose(libinject_handle);
    dlclose(libinject_fork_handle);
    if (LOGLVL >= NONLOG) printf("Engine was correctly finished\n"); // --- DEBUG OUTPUT ---
}

void* input_buffer()
{
    return (void*)get_shmem_stack(shmem_st);
}

int engine_classifier(unsigned long buffer_len, unsigned int ip, unsigned short port)
{
    process_struct* target_process;
    classifier_struct classifier;
    int i;
    int general_count = 0;
    int shellcode_count = 0;
    
    //if (LOGLVL >= DBGLOG) printf("Incomming trafic for: %d.%d.%d.%d:%d\n", ((ip) >> 0 ) & 0xFF,
    //                                                                       ((ip) >> 8 ) & 0xFF,
    //                                                                       ((ip) >> 16) & 0xFF,
    //                                                                       ((ip) >> 24) & 0xFF,
    //                                                                       port); // --- DEBUG OUTPUT ---
    
    if ( test_pid == 0 )
    {
        target_process = process_by_ip_port(network_info_tree, ip, port);
        //if ( target_process == NULL ) return 0;
        
        rop_detector_classifier( target_process, get_shmem_stack(shmem_st), buffer_len, &classifier );
    
    }
    else
    {
        if ( ip == 0 && port == 0 )
        {
            target_process = get_process_by_pid( proc_list, test_pid );
            //if ( target_process == NULL ) return 0;
            
            rop_detector_classifier( target_process, get_shmem_stack(shmem_st), buffer_len, &classifier );
        }
        else
        {
            target_process = process_by_ip_port(network_info_tree, ip, port);
            //if ( target_process == NULL ) return 0;
            
            if ( target_process == NULL ) {
                rop_detector_classifier( target_process, get_shmem_stack(shmem_st), buffer_len, &classifier );
            }
            else if ( target_process->pid == test_pid ) {
                rop_detector_classifier( target_process, get_shmem_stack(shmem_st), buffer_len, &classifier );
            }// else return 0;
            
        }
    }
    
    general_count++;
    if ( classifier.dynamic_detection_count > 4 && classifier.system_call_detection_count > 0 )
    {
        shellcode_count++;
        printf( CLR_YELLOW"Addr= %d, Gadg= %d, Ret= %d, SVC= %d | "\
                CLR_RED"Shellcode found"CLR_RESET"\n", 
                classifier.static_detection_count,
                classifier.gadget_detection_count,
                classifier.dynamic_detection_count,
                classifier.system_call_detection_count);
    }
    else
    {
        printf( CLR_YELLOW"Addr= %d, Gadg= %d, Ret= %d, SVC= %d | "\
                CLR_GREEN"Legitimate"CLR_RESET"\n",  
                classifier.static_detection_count,
                classifier.gadget_detection_count,
                classifier.dynamic_detection_count,
                classifier.system_call_detection_count);
    }
    
    // Detection characteristic
    if ( classifier.dynamic_detection_count > 4 && classifier.system_call_detection_count > 0 ) return 1;
    return 0;
}











// 0x0804846F call eax
    //buffer[i] = 0;//0x0804847d;//0x08048450;//0x08049ffe;//0xb7e18000;
    
    // Module file existence check
	/*pFile = fopen( moduleName, "rb" );
	if ( pFile == NULL ) {
		printf(" Cannot open module file " );
        return(1);
	}
    
    // Load kernel module
    if ( fork() == 0 )
    {
        execl("sudo insmod", moduleName, (char*)0);
    }*/
    
