#include "server.h"
#include "kernel_include.h"
#include "../types.h"

#define BUFF_SLICE_COEFF (50)

#define RETN (0xC3)

//extern rwlock_t tasklist_lock __attribute__((weak));;
//extern spinlock_t task_capability_lock __attribute__((weak));;
//extern struct task_struct *find_task_by_vpid(pid_t nr);

MODULE_LICENSE( "GPL" );
MODULE_AUTHOR( "IPetr0v" );

//extern void mm_release(struct task_struct *, struct mm_struct *);
//EXPORT_SYMBOL(mm_release);

inline int is_kernel_thread(struct task_struct* task)
{
    return (task->mm == NULL);
}

inline int is_zombie(struct task_struct* task)
{
    return (pid_alive(task) != 1);
}

void* heap_buffer_increase(void* old_buff, long old_size, long new_size)
{
    void* new_buff = kmalloc(new_size, GFP_KERNEL);
    
    memcpy(new_buff, old_buff, old_size);
    
    kfree(old_buff);
    return new_buff;
}

proto_process_array* get_process_pids( void )
{
    struct task_struct *task;
    
    pid_count_t process_count=0;
    long buffer_size = (BUFF_SLICE_COEFF)*sizeof(proto_process_array) + 1*sizeof(long); // Size in bytes
    long new_buffer_size = buffer_size;
    proto_process_array* infobuf_proc_array = (proto_process_array*)kmalloc( buffer_size, GFP_KERNEL);
    proto_process_array* proc_array = (proto_process_array*) ((long*)infobuf_proc_array + 1 /* *sizeof(long) */);
    
    //printk(KERN_DEBUG "Get process pids\n"); // --- DEBUG OUTPUT ---
    //printk(KERN_DEBUG "Buffer start size %lu\n", buffer_size); // --- DEBUG OUTPUT ---
    
    rcu_read_lock();
    for_each_process(task)
    {
        get_task_struct(task);
        if ( !is_kernel_thread(task) && !is_zombie(task) )
        {
            proc_array[process_count].pid = task->pid;
            proc_array[process_count].start_brk = task->mm->start_brk;
            proc_array[process_count].brk = task->mm->brk;
            process_count++;
            
            if ( (process_count+1)*sizeof(proto_process_array) + 1*sizeof(long) > buffer_size )
            {
                rcu_read_unlock();
                
                new_buffer_size = buffer_size + (BUFF_SLICE_COEFF)*sizeof(proto_process_array);
                infobuf_proc_array = (proto_process_array*) heap_buffer_increase( infobuf_proc_array, buffer_size, new_buffer_size);
                proc_array = (proto_process_array*) ((long*)infobuf_proc_array + 1 /* *sizeof(long) */);
                buffer_size = new_buffer_size;
                
                rcu_read_lock();
            }
        }
        put_task_struct(task);
    }
    rcu_read_unlock();
    //printk(KERN_DEBUG "Buffer finish size %lu\n", buffer_size); // --- DEBUG OUTPUT ---
    
    ((long*)infobuf_proc_array)[0] = process_count;
    
    return infobuf_proc_array;
    //return process_count*sizeof(proto_process_array);
}

proto_vma_array* get_process_vma(pid_t pid)
{
    int vma_count=0;
    long buffer_size = (BUFF_SLICE_COEFF)*sizeof(proto_vma_array) + 1*sizeof(long); // Size in bytes
    long new_buffer_size = buffer_size;
    
    struct task_struct *task;
    struct mm_struct* mm;
    struct vm_area_struct* vma;
    
    proto_vma_array* infobuf_vma_ar = (proto_vma_array*)kmalloc( buffer_size, GFP_KERNEL);
    proto_vma_array* vma_ar = (proto_vma_array*) ((long*)infobuf_vma_ar + 1 /* *sizeof(long) */);
    
    //printk(KERN_DEBUG "Get vma of %i process\n", pid); // --- DEBUG OUTPUT ---
    //printk(KERN_DEBUG "Buffer start size %lu\n", buffer_size); // --- DEBUG OUTPUT ---
    
    rcu_read_lock();
    if( (task = pid_task(find_vpid(pid), PIDTYPE_PID)) == NULL ) return NULL;
    if ( is_kernel_thread(task) || is_zombie(task) ) return NULL;
    get_task_struct(task);
    
    //smp_wmb();
    //raw_spin_lock_irqsave(&task->pi_lock, flags); // LOCK
    
    mm = task->mm;    
    for( vma = mm->mmap; vma!=NULL; vma = vma->vm_next )
    {
        //printk(KERN_DEBUG "Inserting vma: = %lx-%lx\n", vma->vm_start, vma->vm_end ); // --- DEBUG OUTPUT ---
        vma_ar[vma_count].vm_start = vma->vm_start;
        vma_ar[vma_count].vm_end   = vma->vm_end;
        vma_ar[vma_count].vm_flags = vma->vm_flags;
        vma_count++;
        
        if ( (vma_count+1)*sizeof(proto_vma_array) + 1*sizeof(long) > buffer_size )
        {
            rcu_read_unlock();
            
            new_buffer_size = buffer_size + (BUFF_SLICE_COEFF)*sizeof(proto_vma_array);
            infobuf_vma_ar = (proto_vma_array*) heap_buffer_increase( infobuf_vma_ar, buffer_size, new_buffer_size);
            vma_ar = (proto_vma_array*) ((long*)infobuf_vma_ar + 1 /* *sizeof(long) */);
            buffer_size = new_buffer_size;
            
            rcu_read_lock();
        }
        
        // IF VMA == STACK
        if ( vma_ar[vma_count-1].vm_start <= task->mm->start_stack && task->mm->start_stack < vma_ar[vma_count-1].vm_end )
        {
            //if ( task->pid == 10600 )
            //printk(KERN_DEBUG "Stack pointer= %x | Stack size: cur= %i\n | VMA_start_stack= %x", 
            //                                                     (unsigned int)task->mm->start_stack, 
            //                                                     task->signal->rlim[RLIMIT_STACK].rlim_cur,
            //                                                     task->mm->start_stack - task->signal->rlim[RLIMIT_STACK].rlim_cur); // --- DEBUG OUTPUT ---
            vma_ar[vma_count-1].vm_start = task->mm->start_stack - task->signal->rlim[RLIMIT_STACK].rlim_cur;
        }
        
        //if ( task->pid == 10600 )
        //{
        //    printk(KERN_DEBUG "VMA= %x | %x\n", (unsigned int)vma_ar[vma_count-1].vm_start, (unsigned int)vma_ar[vma_count-1].vm_end ); // --- DEBUG OUTPUT ---
        //}
        
    }
    //raw_spin_unlock_irqrestore(&task->pi_lock, flags); // UNLOCK
    put_task_struct(task);
    rcu_read_unlock();
    
    //printk(KERN_DEBUG "Buffer finish size %lu\n", buffer_size); // --- DEBUG OUTPUT ---
    
    ((long*)infobuf_vma_ar)[0] = vma_count;
    
    return infobuf_vma_ar;    
    //return vma_count*sizeof(proto_vma_array);
}



int copy_process_mm(pid_t source_pid, pid_t pid)
{
    //struct task_struct *source_task, *task;
    //struct mm_struct *source_mm, *mm;
    //
    //if( (source_task = pid_task(find_vpid(source_pid), PIDTYPE_PID)) == NULL ) return -1;
    //if( (task = pid_task(find_vpid(pid), PIDTYPE_PID)) == NULL ) return -1;
    //
    //get_task_struct(source_task);
    //get_task_struct(task);
    //
    //// CLONE
    ////atomic_inc(&source_mm->mm_users);
    ////task->mm = source_mm;
    ////task->active_mm = source_mm;
    //
    //source_mm = source_task->mm;    
    ////vmacache_flush(task);
    //
    //// --- mm = dup_mm(tsk); ---
    //mm = allocate_mm();
    //if (!mm){
    //    put_task_struct(task);
    //    put_task_struct(source_task);
    //    printk(KERN_DEBUG "No memory\n"); // --- DEBUG OUTPUT ---
    //    return -1;
    //}
    //
    //memcpy(mm, source_mm, sizeof(*mm));
    //
    //if (!mm){
    //    put_task_struct(task);
    //    put_task_struct(source_task);
    //    printk(KERN_DEBUG "Dup task error\n"); // --- DEBUG OUTPUT ---
    //    return -1;
    //}
    //
    ////mm->hiwater_rss = get_mm_rss(mm);
    ////mm->hiwater_vm = mm->total_vm;
    //
    //put_task_struct(task);
    //put_task_struct(source_task);
    
    return 0;
    //static struct task_struct *copy_process(unsigned long clone_flags,
    //                                        unsigned long stack_start,
    //                                        unsigned long stack_size,
    //                                        int __user *child_tidptr,
    //                                        struct pid *pid,
    //                                        int trace)
    
    //spinlock_t mr_lock = SPIN_LOCK_UNLOCKED;
    //unsigned long flags;
    //spin_lock_irqsave(&mr_lock, flags);
    ///* critical section ... */
    //spin_unlock_irqrestore(&mr_lock, flags);
    
    //struct task_struct *p;
    //int trace = 0;
    //long nr;
    //
    //if (!(clone_flags & CLONE_UNTRACED)) {
    //        if (clone_flags & CLONE_VFORK)
    //                trace = PTRACE_EVENT_VFORK;
    //        else if ((clone_flags & CSIGNAL) != SIGCHLD)
    //                trace = PTRACE_EVENT_CLONE;
    //        else
    //                trace = PTRACE_EVENT_FORK;
    //
    //        if (likely(!ptrace_event_enabled(current, trace)))
    //                trace = 0;
    //}
    //
    //p = copy_process(clone_flags, stack_start, stack_size,
    //                 child_tidptr, NULL, trace);
}

int delete_vma(pid_t pid)
{
    //unsigned long flags; 
    //struct task_struct *task;
    //struct mm_struct *mm, *active_mm;
    //void (*mm_release_pointer)(struct task_struct *, struct mm_struct *);
    ////void (*mmput_pointer)(struct mm_struct *);
    //
    //mm_release_pointer = ( void(*)(struct task_struct *, struct mm_struct *)) ( kallsyms_lookup_name("mm_release") );
    //
    //if( (task = pid_task(find_vpid(pid), PIDTYPE_PID)) == NULL ) return -1;
    //
    //smp_wmb(); 
    //raw_spin_lock_irqsave(&task->pi_lock, flags);
    //get_task_struct(task);
    //task->state = TASK_STOPPED;
    //
    //mm = task->mm;
    //if ( mm == NULL )
    //{
    //    raw_spin_unlock_irqrestore(&task->pi_lock, flags);
    //    printk(KERN_DEBUG "Thread has no VMA\n"); // --- DEBUG OUTPUT ---
    //    return -1;
    //}
    ////mmput_pointer = ( void(*)(struct mm_struct *)) ( kallsyms_lookup_name("mmput") );
    //
    ////exec_mmap_pointer(mm);
    //printk(KERN_DEBUG "Calling function %x\n", (unsigned int)mm_release_pointer); // --- DEBUG OUTPUT ---
    ////task_lock(task);
    ////mm_release_pointer(task, old_mm);
    //
    //mmput(mm);
    //
    ////mm_release(task, mm);
    ////unsigned long sym_addr = kallsyms_lookup_name(sym_name);
    //
    //put_task_struct(task);
    //raw_spin_unlock_irqrestore(&task->pi_lock, flags);
    
    return 0;
}

int change_parent(pid_t pid, pid_t parent_pid)
{
    unsigned long flags;
    struct task_struct *task;
    struct task_struct *parent_task;
    
    if( (task        = pid_task(find_vpid(pid),        PIDTYPE_PID)) == NULL ) return -1;
    if( (parent_task = pid_task(find_vpid(parent_pid), PIDTYPE_PID)) == NULL ) return -1;
    
    smp_wmb(); 
    raw_spin_lock_irqsave(&task->pi_lock, flags);
    raw_spin_lock_irqsave(&parent_task->pi_lock, flags);
    get_task_struct(task);
    get_task_struct(parent_task);
    
    /* 
    * pointers to (original) parent process, youngest child, younger sibling,
    * older sibling, respectively.  (p->father can be replaced with 
    * p->p_pptr->pid)
    */
    //struct task_struct *p_opptr, *p_pptr, *p_cptr, 
    //                   *p_ysptr, *p_osptr;
    
    
    put_task_struct(parent_task);
    put_task_struct(task);
    raw_spin_unlock_irqrestore(&parent_task->pi_lock, flags);
    raw_spin_unlock_irqrestore(&task->pi_lock, flags);
    return 0;
}

proto_port_array* get_process_ports(pid_t pid)
{
    struct file *file;
    struct socket *sock;
    int fd = 0;
    struct inode *inode;
    struct task_struct *task;
    //struct pid *mypid;
    struct files_struct *files;
    
    //mypid = find_vpid(pidnr);
    //if (!mypid) {
    //    return -ESRCH;
    //}
    
    if( (task = pid_task(find_vpid(pid), PIDTYPE_PID)) == NULL ) return NULL;
    
    //printk("\nProcess %s\n", task->comm);
    
    files = task->files;
    
    rcu_read_lock();
    file = fcheck_files(files, fd);
    rcu_read_unlock();
    while(file) {
        inode = file->f_path.dentry->d_inode;
        if (S_ISSOCK(inode->i_mode)) {
            sock = file->private_data;
            printk("\ntype = %d\n", sock->type);
        }
        fd++;
        rcu_read_lock();
        file = fcheck_files(files, fd);
        rcu_read_unlock();
    }
    return NULL;
}

// -----------------------------------------------------------------------------------
// ----------------------------------- HANDLER ---------------------------------------
// -----------------------------------------------------------------------------------
void msgHandler( char* income_msg, size_t income_size )
{
    //int i; 
    int msg_size = 0;
    proto_respond* proto_resp = (proto_respond*)kmalloc( sizeof(proto_respond), GFP_KERNEL );
    char* infobuf_outcome_msg = NULL; // buffer with header containing size of array
    char* outcome_msg = NULL;
    pid_t pid, /*source_pid,*/ parent_pid;
    
    //printk(KERN_DEBUG "Incomming message with code %i\n", ((proto_command*)income_msg)->command); // --- DEBUG OUTPUT ---
    
    switch ( ((proto_command*)income_msg)->command ) 
    {
		case GET_PIDS:
			//msg_size = get_process_pids( &(proto_process_array*)outcome_msg );
            if ( (infobuf_outcome_msg = (char*)get_process_pids()) != NULL ) 
            {
                msg_size = ((long*)infobuf_outcome_msg)[0] * sizeof(proto_process_array);
                outcome_msg = (char*) ( (long*)infobuf_outcome_msg + 1 /* *sizeof(long) */);
            }
            else msg_size = 0;
            
            // --- DEBUG OUTPUT ---
            //printk(KERN_DEBUG "Going to send= %i, processes= %i\n", msg_size, msg_size/sizeof(proto_process_array)); // --- DEBUG OUTPUT ---
            //for (i = 0; i<msg_size/sizeof(proto_process_array); i+=1 /*sizeof(proto_process_array)*/)
            //    printk(KERN_DEBUG "P-%i: %i || ", i, ((proto_process_array*)outcome_msg)[i].pid); // --- DEBUG OUTPUT ---
            // --- DEBUG OUTPUT ---
            
            proto_resp->command = ((proto_command*)income_msg)->command;
            proto_resp->data_size = msg_size;
            send_message( (char*)proto_resp, sizeof(proto_respond));
            if ( proto_resp->data_size != 0 ) 
                send_message(outcome_msg, msg_size);
            
			break;
		case GET_VMA:
            if ( (infobuf_outcome_msg = (char*)get_process_vma(((proto_command*)income_msg)->pid) ) != NULL )
            {
                msg_size = ((long*)infobuf_outcome_msg)[0] * sizeof(proto_process_array);
                outcome_msg = (char*) ( (long*)infobuf_outcome_msg + 1 /* *sizeof(long) */);
            }
            else msg_size = 0;
            
            // --- DEBUG OUTPUT ---
            //printk(KERN_DEBUG "Going to send= %i, processes= %i\n", msg_size, msg_size/sizeof(proto_process_array)); // --- DEBUG OUTPUT ---
            //for (i = 0; i<msg_size/sizeof(proto_process_array); i+=1 /*sizeof(proto_process_array)*/)
            //    printk(KERN_DEBUG "Inserting vma: = %x-%x\n", 
            //            ((proto_vma_array*)outcome_msg)[i].vm_start, 
            //            ((proto_vma_array*)outcome_msg)[i].vm_end );
            // --- DEBUG OUTPUT ---
            
            proto_resp->command = ((proto_command*)income_msg)->command;
            proto_resp->data_size = msg_size;
            send_message( (char*)proto_resp, sizeof(proto_respond));
            if ( proto_resp->data_size != 0 ) 
                send_message(outcome_msg, msg_size);
            
			break;
        case CLONE_PROC:            
            //pid = ((proto_command*)income_msg)->pid;
            //source_pid = ((proto_command*)income_msg)->source_pid;
            //
            //if ( copy_process_mm(source_pid, pid) == 0 )
            //    proto_resp->success = 1;
            //else
            //    proto_resp->success = 0;
            //
            //proto_resp->command = ((proto_command*)income_msg)->command;
            //proto_resp->data_size = 0;
            //send_message( (char*)proto_resp, sizeof(proto_respond));
        case DELETE_VMA:
            pid = ((proto_command*)income_msg)->pid;
            
            if ( delete_vma(pid) == 0 )
                proto_resp->success = 1;
            else
                proto_resp->success = 0;
            
            proto_resp->command = ((proto_command*)income_msg)->command;
            proto_resp->data_size = 0;
            send_message( (char*)proto_resp, sizeof(proto_respond));
            break;
        case CHANGE_PARENT:
            pid = ((proto_command*)income_msg)->pid;
            parent_pid = ((proto_command*)income_msg)->parent_pid;
            
            if ( change_parent(pid,parent_pid) == 0 )
                proto_resp->success = 1;
            else
                proto_resp->success = 0;
            
            proto_resp->command = ((proto_command*)income_msg)->command;
            proto_resp->data_size = 0;
            send_message( (char*)proto_resp, sizeof(proto_respond));
            break;
		default:
			break;
    }
    
    if ( infobuf_outcome_msg!=NULL ) kfree(infobuf_outcome_msg);
    kfree(proto_resp);
}

static int __init kernel_module_init( void ) {
    printk(KERN_DEBUG "ROP Module start\n");
    
    if ( server_init(msgHandler) != 0 )
        return 1;
    
    return 0;
}

static void __exit kernel_module_exit( void ) {
    server_exit();
    printk(KERN_DEBUG "ROP Module finish\n");
}

module_init( kernel_module_init );
module_exit( kernel_module_exit );



// usefull stuff
/*
    spin_lock(&task_capability_lock);

    if (pid && pid != current->pid) {
	    read_lock(&tasklist_lock); 
            target = find_task_by_pid(pid);  //identify target of query
            if (!target) 
                    error = -ESRCH;
    } else {
            target = current;
    }

    if (!error) { 
	    data.permitted = cap_t(target->cap_permitted);
	    data.inheritable = cap_t(target->cap_inheritable); 
	    data.effective = cap_t(target->cap_effective);
    }

    if (target != current)
	    read_unlock(&tasklist_lock); 
    spin_unlock(&task_capability_lock);

//----------------------------------

    spin_lock(&task_capability_lock);
    read_lock(&tasklist_lock); 
    read_unlock(&tasklist_lock);
    spin_unlock(&task_capability_lock);

//----------------------------------


    rcu_read_lock();
    rcu_read_unlock();
    
    unsigned long flags_tmp; 
    smp_wmb(); 
    raw_spin_lock_irqsave(&task->pi_lock, flags);
    do your stuff
    raw_spin_unlock_irqrestore(&task->pi_lock, flags);*/
