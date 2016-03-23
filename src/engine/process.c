#include "process.h"

extern process_list* proc_list;
extern rb_tree* network_info_tree;
extern pid_t test_pid;

extern size_t MAX_ret_num;
extern size_t MAX_vma_num;

// ------------------------------------------------------------------------------ 
// ---------------------------------- PROCCESS ---------------------------------- 
// ------------------------------------------------------------------------------ 

int process_for_analyze(process_struct* process)
{
    if ( test_pid != 0 ) {
        if ( process->pid == test_pid ) return 1;
        else                            return 0;
    } else {
        if ( process->port != 0 ) return 1;
        else                      return 0;
    }
    
    return 0;
    //if ( process->pid == test_pid || process->port != 0 )
    //    return 1;
    //return 0;
    
    //if ( process->port != 0 )
    //    return 1;
    //return 0;
}

process_list* init_process_list()
{
    int proc_iter;
    process_struct* process;
    network_info_struct* info = NULL;
    process_list* list = create_empty_process_list();
    process_array* proc_array = ask_for_process_pids();
    
    //printf("Number of processes for insert: = %i\n", proc_array->proc_num ); // --- DEBUG OUTPUT ---
    for(proc_iter = 0; proc_iter < proc_array->proc_num; proc_iter++)
    {
        //printf("Initializing %3f%%\n", (100.0*(double)proc_iter/(double)proc_array->proc_num) ); // --- DEBUG OUTPUT ---
        //printf("Adding: = %i || \n", proc_array->pids[proc_iter].pid ); // --- DEBUG OUTPUT ---
        process = add_process( list, proc_array->pids[proc_iter].pid );
        process->start_brk = proc_array->pids[proc_iter].start_brk;
        process->brk = proc_array->pids[proc_iter].brk;
        init_vma_tree(process, process->pid);
        
        process->ip = 0;
        process->port = 0;
    
        //if ( process_for_analyze(process) ) {
        //    if (LOGLVL >= DBGLOG) printf("Prog: Creating emulator for %d\n", process->pid); // --- DEBUG OUTPUT ---
        //    if ( create_emulator(process) < 0 )
        //        return NULL;
        //}
    }
    list->proc_num = proc_array->proc_num;
    
    //printf("Initializing 100%%\n"); // --- DEBUG OUTPUT ---
    
    // --- DEBUG OUTPUT ---
    //for(process = list->process_list_head; process != NULL; process = process->next)
    //{
    //    printf("P: = %i || ", process->pid );
    //}
    //printf("Number: = %i || ", list->proc_num );
    // --- DEBUG OUTPUT ---
    
    if (proc_array!=NULL) 
    {
        free(proc_array->pids);
        free(proc_array);
    }
    
    proc_list = list; // Global variable
    return list;
}

int init_process_emulators(process_list* list)
{
    process_struct* process;
    
    for(process = list->process_list_head; process!=NULL; process = process->next)
    {
        if ( process_for_analyze(process) ) {
            if (LOGLVL >= DBGLOG) printf("Prog: Creating emulator for %d\n", process->pid); // --- DEBUG OUTPUT ---
            //if ( create_emulator(process) < 0 )
            //    return 1;
            create_emulator(process);
        }
    }
    return 0;
}

void destroy_process_list(process_list* list)
{
    process_struct* process;
    
    for(process = list->process_list_head; process!=NULL; process = process->next)
    {
        delete_process(list, process);
    }
    
    free(list);
}

process_list* create_empty_process_list()
{
    process_list* list = (process_list*)malloc( sizeof(process_list) );
    
    list->process_list_head = NULL;
    list->process_list_tail = NULL;
    return list;
}

process_struct* create_process(pid_t pid)
{
    process_struct* process;
    
    process = (process_struct*)malloc( sizeof(process_struct) );
    process->pid = pid;
    process->next = NULL;
    process->prev = NULL;
    
    return process;
}

void destroy_process(process_struct* process)
{
    //if ( process_for_analyze(process) ) {
    //    destroy_emulator(process);
    //}
    if ( process->emulator_hp != NULL ) {
        destroy_emulator(process);
    }
    
    destroy_vma_tree(process->vma_tree);
    destroy_vma_tree(process->vma_exec_tree);
    destroy_vma_tree(process->vma_write_mayexec_tree);
    destroy_prefix_tree(process->exec_address_prefix_tree);
    
    if ( process->plain_vma_array != NULL ) 
    {
        free(process->plain_vma_array->vmas);
        free(process->plain_vma_array);
    }
    
    free(process);
}

process_struct* get_process_by_pid(process_list* list, int pid)
{
    process_struct* process;
    for(process = list->process_list_head; process != NULL; process = process->next )
    {
        if (process->pid == pid) return process;
    }
    return NULL;
}

process_struct* add_process(process_list* list, int pid)
{
    process_struct* process = get_process_by_pid(list, pid);
    
    if ( process != NULL ) return process;
    
    process = create_process(pid);
    
    if (list->process_list_head == NULL)
    {
        list->process_list_head = process;
        list->process_list_tail = process;
    }
    else
    {
        list->process_list_tail->next = process;
        process->prev = list->process_list_tail;
        list->process_list_tail = process;
    }
    
    return process;
}

void delete_process_by_pid(process_list* list, pid_t pid)
{
    process_struct* process = get_process_by_pid(list, pid);
    
    if ( process == NULL ) return;    
    if ( process == list->process_list_head )
        list->process_list_head = process->next;
    else
        process->prev->next = process->next;
    
    if ( process == list->process_list_tail ) 
        list->process_list_tail == process->prev;
    else
        process->next->prev = process->prev;
    
    free(process);
    return;
}

void delete_process(process_list* list, process_struct* process)
{
    if ( process == NULL ) return;    
    if ( process == list->process_list_head )
        list->process_list_head = process->next;
    else
        process->prev->next = process->next;
    
    if ( process == list->process_list_tail ) 
        list->process_list_tail == process->prev;
    else
        process->next->prev = process->prev;
    
    destroy_process(process);
    return;
}

// ------------------------------------------------------------------------------ 
// ------------------------------------ VMA ------------------------------------- 
// ------------------------------------------------------------------------------ 

void init_vma_tree(process_struct* process, pid_t pid)
{
    int vma_iter = 0;
    unsigned char prefix_iter = 0;
    unsigned int prev_vma_end = 0;
    unsigned int curr_vma_start;
    vma_struct* vma;
    //rb_tree* tree = create_vma_tree();
    vma_array* vma_ar = ask_for_vma_by_pid(pid);
    prefix_struct* prefix = NULL;
    
    rb_tree* vma_tree = create_vma_tree();
    rb_tree* vma_exec_tree = create_vma_tree();
    rb_tree* vma_write_mayexec_tree = create_vma_tree();
    
    rb_tree* exec_address_prefix_tree = create_prefix_tree();
    rb_tree* invert_vma_exec_tree = create_vma_tree();
    
    //printf("Number of vma for insert: = %i\n", vma_ar->vma_num ); // --- DEBUG OUTPUT ---
    if ( vma_ar->vma_num > MAX_vma_num ) MAX_vma_num = vma_ar->vma_num;
    for(vma_iter = 0; vma_iter < vma_ar->vma_num; vma_iter++)
    {
        vma = (vma_struct*)malloc( sizeof(vma_struct) );
        vma->vm_start = vma_ar->vmas[vma_iter].vm_start;
        vma->vm_end   = vma_ar->vmas[vma_iter].vm_end;
        vma->vm_flags = vma_ar->vmas[vma_iter].vm_flags;
        
        process->memory_space_size += vma->vm_end - vma->vm_start;
        
        //if ( vma_iter == vma_ar->vma_num - 1 ) // STACK
        //    vma->vm_start = vma->vm_end - max_stack_size;
        
        //if ( pid == test_pid ) printf("Inserting vma: = %x-%x\n", vma->vm_start, vma->vm_end ); // --- DEBUG OUTPUT ---
        
        // All significant vma are exec_vma
        //insert_vma(vma_tree, vma);
        if ( (vma->vm_flags & VM_EXEC) != 0 ) 
        {
            process->executable_space_size += vma->vm_end - vma->vm_start;
            ///if ( pid == test_pid ) 
            ///{
            ///    vma->gadget_tree = init_gadget_tree(pid, vma->vm_start, vma->vm_end);
            ///    insert_vma(vma_exec_tree, vma);
            ///}
            ///else
            {
                vma->gadget_tree = NULL;
                insert_vma(vma_exec_tree, vma);
            }
            
            // Prefix tree
            for (prefix_iter = (unsigned char)((vma->vm_start >> 24) & 0xFF); prefix_iter <= (unsigned char)((vma->vm_end >> 24) & 0xFF); prefix_iter++)
            {
                //if ( pid == test_pid ) printf("Prefix: = %x\n", prefix_iter ); // --- DEBUG OUTPUT ---
                prefix = (prefix_struct*)malloc( sizeof(prefix_struct) );
                prefix->prefix_value = prefix_iter;
                insert_prefix( exec_address_prefix_tree, prefix );
            }
        }
        else
        {
            vma->gadget_tree = NULL;
        }
    }
    process->first_vma_start = vma_ar->vmas[0].vm_start;
    process->last_vma_end = vma_ar->vmas[vma_ar->vma_num - 1].vm_end;
    
    // Invert exec RB tree
    prev_vma_end = -1;
    for(vma_iter = 0; vma_iter < vma_ar->vma_num; vma_iter++)
    {
        if ( (vma_ar->vmas[vma_iter].vm_flags & VM_EXEC) != 0 )
        {
            curr_vma_start = vma_ar->vmas[vma_iter].vm_start;
            
            if ( prev_vma_end < curr_vma_start - 0x10000 )
            {
                vma = (vma_struct*)malloc( sizeof(vma_struct) );
                vma->vm_start = prev_vma_end + 1;   //vma_ar->vmas[vma_iter].vm_start;
                vma->vm_end   = curr_vma_start - 1; //vma_ar->vmas[vma_iter].vm_end;
                vma->vm_flags = 0;                  //vma_ar->vmas[vma_iter].vm_flags;
                insert_vma(invert_vma_exec_tree, vma);
            }
            
            prev_vma_end = vma_ar->vmas[vma_iter].vm_end;
        }
    }
    vma = (vma_struct*)malloc( sizeof(vma_struct) );
    vma->vm_start = prev_vma_end + 1;   
    vma->vm_end   = (unsigned int)(-1); 
    vma->vm_flags = 0;                  
    insert_vma(invert_vma_exec_tree, vma);
    // Invert exec RB tree
    
    // Commented due to shared memory needs
    //if (vma_ar!=NULL) 
    //{
    //    free(vma_ar->vmas);
    //    free(vma_ar);
    //}
    
    process->vma_tree = vma_tree;
    process->vma_exec_tree = vma_exec_tree;
    process->vma_write_mayexec_tree = vma_write_mayexec_tree;
    
    process->exec_address_prefix_tree = exec_address_prefix_tree;
    process->invert_vma_exec_tree = invert_vma_exec_tree;
    
    process->plain_vma_array = vma_ar;
}

rb_tree* create_vma_tree()
{
    return (rb_tree*)RBTreeCreate( compare_vma, destroy_vma, null_function, null_function_const, null_function );
}

rb_node* insert_vma(rb_tree* tree, vma_struct* vma)
{
    return (rb_node*)RBTreeInsert( (rb_red_blk_tree*)tree, (void*)vma, NULL);
}

inline rb_node* search_vma_by_address(rb_tree* tree, unsigned int address)
{
    //rb_red_blk_node* node;
    vma_struct vma = {address,address,0,NULL};
    //vma_struct* vma_for_search = (vma_struct*)malloc( sizeof(vma_struct) );
    //vma_for_search->vm_start = address;
    //vma_for_search->vm_end = address;
    
    //node = RBExactQuery( (rb_red_blk_tree*)tree, vma_for_search);
    
    //free(vma_for_search);
    //return (rb_node*)node;
    return (rb_node*) RBExactQuery( (rb_red_blk_tree*)tree, &vma);
}

void destroy_vma_tree(rb_tree* tree)
{
    RBTreeDestroy( (rb_red_blk_tree*)tree );
}

int compare_vma(const void* a,const void* b)
{    
    if ( ((vma_struct*)a)->vm_start >= ((vma_struct*)b)->vm_end   ) return(1);
    if ( ((vma_struct*)a)->vm_end   <= ((vma_struct*)b)->vm_start ) return(-1);
    return(0);
}

void destroy_vma(void* a)
{
    if ( ((vma_struct*)a)->gadget_tree != NULL ) RBTreeDestroy( ((vma_struct*)a)->gadget_tree );
    free( (vma_struct*)a );
}

// ------------------------------------------------------------------------------ 
// ------------------------------ ADDRESS PREFIX -------------------------------- 
// ------------------------------------------------------------------------------ 

rb_tree* create_prefix_tree()
{
    return (rb_tree*)RBTreeCreate( compare_prefix, destroy_prefix, null_function, null_function_const, null_function );
}

rb_node* insert_prefix(rb_tree* tree, prefix_struct* prefix)
{
    return (rb_node*)RBTreeInsert( (rb_red_blk_tree*)tree, (void*)prefix, NULL);
}

inline rb_node* search_prefix(rb_tree* tree, unsigned int address)
{
    //(unsigned char)((vma->vm_start >> 24) & 0xFF);
    prefix_struct prefix = { (unsigned char)(address >> 24) };
    return (rb_node*) RBExactQuery( (rb_red_blk_tree*)tree, &prefix);
}

void destroy_prefix_tree(rb_tree* tree)
{
    RBTreeDestroy( (rb_red_blk_tree*)tree );
}

int compare_prefix(const void* a,const void* b)
{
    //if ( ((prefix_struct*)a)->prefix_start >= ((prefix_struct*)b)->prefix_end   ) return(1);
    //if ( ((prefix_struct*)a)->prefix_end   <= ((prefix_struct*)b)->prefix_start ) return(-1);
    if ( ((prefix_struct*)a)->prefix_value > ((prefix_struct*)b)->prefix_value ) return(1);
    if ( ((prefix_struct*)a)->prefix_value < ((prefix_struct*)b)->prefix_value ) return(-1);
    return(0);
}

void destroy_prefix(void* a)
{
    free( (prefix_struct*)a );
}

// ------------------------------------------------------------------------------ 
// ------------------------------- NETWORK INFO --------------------------------- 
// ------------------------------------------------------------------------------ 

rb_tree* network_info_tree_init()
{
    rb_tree* network_info_tree = create_network_info_tree();
    FILE* netstat ;
    unsigned char symbol;
    unsigned int ip_arr[4];
    unsigned int port;
    char proto[5];
    pid_t pid;
    int scanf_status;
    
    printf("Network info init\n"); // --- DEBUG OUTPUT ---
    if ( (netstat = popen("netstat -patun", "r")) != NULL )
    {
        do
        {
            port = 0;
            pid = 0;
            // Active Internet connections (only servers)
            // Proto Recv-Q Send-Q      Local Address           Foreign Address         State       PID/Program name
            // tcp        0      0      127.0.1.1:53            0.0.0.0:*               LISTEN      1355/dnsmasq
            fscanf(netstat, "%4s", proto);
            proto[4] = 0;
            if ( (strncmp( proto, "tcp6", 4 ) == 0) || (strncmp( proto, "udp6", 4 ) == 0) )
                do { scanf_status = fscanf(netstat, "%c", &symbol); } while( symbol != '\n' );
            else if ( (strncmp( proto, "tcp", 3 ) != 0) && (strncmp( proto, "udp", 3 ) != 0) )
                do { scanf_status = fscanf(netstat, "%c", &symbol); } while( symbol != '\n' );
            else if ( strncmp( proto, "tcp", 3 ) == 0 )
            {
                scanf_status = fscanf(netstat, " %*d  %*d  %3d.%3d.%3d.%3d:%5d  %*s %*s %d/%*[^\n]", ip_arr + 0, 
                                                                                                     ip_arr + 1,
                                                                                                     ip_arr + 2,
                                                                                                     ip_arr + 3,
                                                                                                     &port,
                                                                                                     &pid);
            }
            else if ( strncmp( proto, "udp", 3 ) == 0 )
            {
                scanf_status = fscanf(netstat, " %*d  %*d  %3d.%3d.%3d.%3d:%5d  %*s %d/%*[^\n]", ip_arr + 0, 
                                                                                                 ip_arr + 1,
                                                                                                 ip_arr + 2,
                                                                                                 ip_arr + 3,
                                                                                                 &port,
                                                                                                 &pid);
            }
            //printf("Raw network info: ip= %d.%d.%d.%d\n", ip_arr[0], ip_arr[1], ip_arr[2], ip_arr[3] ); // --- DEBUG OUTPUT ---
            if ( pid != 0 && port != 0 )
            {
                network_info_struct* net_info = (network_info_struct*)malloc( sizeof(network_info_struct) );
                net_info->ip = (ip_arr[3]*256*256*256) + (ip_arr[2]*256*256) + (ip_arr[1]*256) + (ip_arr[0]);
                net_info->port = port;
                net_info->pid = pid;
                net_info->process = get_process_by_pid(proc_list, pid);
                net_info->process->ip = net_info->ip;
                net_info->process->port = net_info->port;
                //printf("Network info: ip= %d, port= %d, pid= %d\n", net_info->ip, net_info->port = port, net_info->pid ); // --- DEBUG OUTPUT ---
                printf("Network info: ip= %d.%d.%d.%d, port= %d, pid= %d\n", ((net_info->ip) >> 0 ) & 0xFF,
                                                                             ((net_info->ip) >> 8 ) & 0xFF, 
                                                                             ((net_info->ip) >> 16) & 0xFF, 
                                                                             ((net_info->ip) >> 24) & 0xFF, 
                                                                             net_info->port = port, net_info->pid ); // --- DEBUG OUTPUT ---
                insert_network_info(network_info_tree, net_info);
            }
        }
        while( scanf_status > 0 );
    }
    else
    {
        perror("popen");
        return NULL;
    }
    
    pclose(netstat);
    return network_info_tree;
}

rb_tree* create_network_info_tree()
{
    return (rb_tree*)RBTreeCreate( compare_network_info, destroy_network_info, null_function, null_function_const, null_function );
}

rb_node* insert_network_info(rb_tree* tree, network_info_struct* network_info)
{
    return (rb_node*)RBTreeInsert( (rb_red_blk_tree*)tree, (void*)network_info, NULL);
}

inline rb_node* search_network_info_ip_port(rb_tree* tree, unsigned int ip, unsigned short port)
{
    network_info_struct network_info = {ip,port,0};
    return (rb_node*) RBExactQuery( (rb_red_blk_tree*)tree, &network_info);
}

inline process_struct* process_by_ip_port(rb_tree* tree, unsigned int ip, unsigned short port)
{
    rb_node* node = search_network_info_ip_port(tree, ip, port);
    if ( node != NULL) return ((network_info_struct*)(node->key))->process;
    else return NULL;
} 

void destroy_network_info_tree(rb_tree* tree)
{
    RBTreeDestroy( (rb_red_blk_tree*)tree );
}

int compare_network_info(const void* a,const void* b)
{
    if ( ((network_info_struct*)a)->port > ((network_info_struct*)b)->port ) return(1);
    if ( ((network_info_struct*)a)->port < ((network_info_struct*)b)->port ) return(-1);
    
    if ( ((network_info_struct*)a)->ip == 0 ) return 0;
    if ( ((network_info_struct*)a)->ip > ((network_info_struct*)b)->ip ) return(1);
    if ( ((network_info_struct*)a)->ip < ((network_info_struct*)b)->ip ) return(-1);
    
    return 0;
}

void destroy_network_info(void* a)
{
    free( (network_info_struct*)a );
}










//void null_function(void * junk) { ; }
//void null_function_const(const void * junk) { ; }



