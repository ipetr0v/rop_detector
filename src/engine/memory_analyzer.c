#include <errno.h>

#include "memory_analyzer.h"

int attached = 0;
pid_t target_pid = 0;
unsigned long* start_address = NULL;
unsigned long* end_address = NULL;
int gadit = 0;
int retit = 0;

void* word_align(void* address)
{
    return address - (( (unsigned long)address & 0x0000000F) % sizeof(long));
}

unsigned long get_long_from_mem( pid_t pid, void* address )
{
    long memory_word;
    
    memory_word = ptrace(PTRACE_PEEKDATA, pid, address, NULL);
    
    ///if ( 0x0804846e <= (unsigned long)address && (unsigned long)address <= 0x08048486 )
    ///    printf("memory_word= 0x%lx\n", memory_word); // --- DEBUG OUTPUT ---
    return memory_word;
}

void get_buffer_from_mem( pid_t pid, unsigned long* buffer, void* address, unsigned int len)
{
    void* tmp_address = 0;
    int word_count = 0;
    for(tmp_address = (void*)address; tmp_address < ((void*)address) + len; tmp_address += sizeof(unsigned long) )
    {
        buffer[word_count] = get_long_from_mem( target_pid, tmp_address );
        ///if ( 0x0804846e <= (unsigned long)tmp_address && (unsigned long)tmp_address <= 0x08048486 )
        ///    printf("returned_memory_word 0x%lx : 0x%lx\n", tmp_address, get_long_from_mem( target_pid, tmp_address )); // --- DEBUG OUTPUT ---
        word_count++;
    }
}

int is_correct_disassembled_gadget( unsigned char* buffer, unsigned int len, unsigned long address, unsigned long ret_address )
{
    int size;
    x86_insn_t insn;
    int offset = 0;
    
    while( offset < len )
    {
        size = disassemble_buffer( buffer+offset, len - offset, &insn);
        ///if ( (unsigned long)ret_address == 0x8048483 ) 
        ///    printf("disas= 0x%lx - 0x%lx | size= %d\n", address+offset, ret_address, size); // --- DEBUG OUTPUT ---
        
        if ( size <= 0 ) {
            x86_oplist_free( &insn );
            return 0;
        }
        if ( is_call_or_jmp_with_register_operands(&insn) ) {
            x86_oplist_free( &insn );
            return 0;
        }
        
        offset += size;
        x86_oplist_free( &insn );
    }
    if ( offset != len ) return 0;
    
    return 1;
}

/*gadget_struct**/void create_gadget(rb_tree* tree, unsigned long ret_address)
{
    int i, test;
    ///unsigned int real_start_positions_number = 0;
    ///unsigned long* real_start_positions = (unsigned long*)malloc( OFFSET_BEFORE_RET * sizeof(unsigned long) );
    int buffer_iter = 0;
    unsigned char memory_buffer[OFFSET_BEFORE_RET];
    
    // Get memory buffer
    void* gadget_start_address = ( (unsigned long)start_address <= (unsigned long)(ret_address - OFFSET_BEFORE_RET) ) ? (void*)(ret_address - OFFSET_BEFORE_RET): start_address;
    get_buffer_from_mem( target_pid, (unsigned long*)memory_buffer, gadget_start_address, OFFSET_BEFORE_RET);
    ///if ( (unsigned long)ret_address == 0x8048483 ) 
    ///    for(i=0; i<OFFSET_BEFORE_RET/*/sizeof(long)*/; i++)
    ///        printf("Buffer= 0x%lx:  0x%lx\n", gadget_start_address+i/**sizeof(long)*/, (/*(long*)*/memory_buffer)[i] ); // --- DEBUG OUTPUT ---
    
    // Disas
    disassembler_init();
    // Disas
    
    // Create gadget
    ///gadget_struct* gadget = (gadget_struct*)malloc( sizeof(gadget_struct) );
    ///gadget->ret_address = ret_address;
    
    // Analyze possible real_start_positions
    for(buffer_iter = 0; buffer_iter < OFFSET_BEFORE_RET; buffer_iter++)
    {
        test = is_correct_disassembled_gadget( memory_buffer + buffer_iter, OFFSET_BEFORE_RET - buffer_iter, ret_address - (OFFSET_BEFORE_RET - buffer_iter), ret_address );
        ///if ( (unsigned long)ret_address == 0x8048483 ) printf("Correct= 0x%lx - %i\n", ret_address - (OFFSET_BEFORE_RET - buffer_iter), test); // --- DEBUG OUTPUT ---
        if ( test )
        {
            ///real_start_positions[real_start_positions_number] = ret_address - (OFFSET_BEFORE_RET - buffer_iter);
            ///real_start_positions_number++;
            
            gadget_struct* gadget = (gadget_struct*)malloc( sizeof(gadget_struct) );
            gadget->start_address = ret_address - (OFFSET_BEFORE_RET - buffer_iter);
            //gadget->ret_address = ret_address;
            insert_gadget(tree, gadget);
            
            gadit++;
        }
    }
    gadget_struct* gadget = (gadget_struct*)malloc( sizeof(gadget_struct) );
    gadget->start_address = ret_address;
    //gadget->ret_address = ret_address;
    insert_gadget(tree, gadget);
    gadit++;
    
    // Disas
    disassembler_destroy();
    // Disas
    
    ///if ( real_start_positions_number == 0 ) return NULL;
    ///
    ///real_start_positions = (unsigned long*)realloc( real_start_positions, real_start_positions_number * sizeof(unsigned long) );
    ///
    ///gadget->real_start_positions_number = real_start_positions_number;
    ///gadget->real_start_positions = real_start_positions;
    ///
    /////gadget->start_address = (unsigned long) ((char*)gadget->ret_address - OFFSET_BEFORE_RET);
    ///gadget->start_address = gadget->real_start_positions[0];
    ///
    //////if ( (unsigned long)ret_address == 0x8048483 ) printf("Gadget= 0x%lx - 0x%lx\n", gadget->start_address, ret_address); // --- DEBUG OUTPUT ---
    ///return gadget;
}

rb_tree* init_gadget_tree(pid_t pid, unsigned int vm_start, unsigned int vm_end)
{
    //long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
    int byte_count;
    unsigned char byte;
    unsigned long* address;
    unsigned long memory_word;
    //unsigned long test_memory_word;
    unsigned long memory_word_secondary;
    int status;
    rb_tree* tree = create_gadget_tree();
    gadget_struct* gadget;
    start_address = (unsigned long*)vm_start;
    end_address = (unsigned long*)vm_end;
    
    // Disas
    int size;                /* size of instruction */
    x86_insn_t insn;         /* instruction */
    // Disas
    
    target_pid = pid;
    if ( target_pid == getpid() ) return tree;
    
    
    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) < 0) {
        int err = errno;
        //printf("Prog: Ptrace Attach to %i failed with error %s\n", target_pid, strerror(err)); // --- DEBUG OUTPUT ---
        attached = 0;
    }
    else
    {
        attached = 1;
        waitpid(target_pid, &status, 0);
    }
    
    for( address = start_address; address < end_address; address++ )
    {
        if ( attached ) memory_word = get_long_from_mem( target_pid, (void*)address );
        else memory_word = 0x0;
        
        for(byte_count=0; byte_count<4; byte_count++)
        {
            byte = ( memory_word >> (0x8*byte_count) ) & 0xff;
            
            if ( byte == RET_OPCODE ) // Ret
            {
                /**gadget = */create_gadget( tree, (unsigned long) ((char*)address + byte_count) );
                ///if ( gadget != NULL )
                ///    insert_gadget(tree, gadget);
                retit++;
            }
            else if ( byte == CALL_OR_JMP_OPCODE ) // JMP or CALL
            {
                memory_word_secondary = get_long_from_mem( target_pid, (void*)((char*)address + byte_count) );
                
                size = disassemble_word( (unsigned char*)(&memory_word_secondary), &insn);
                if ( size != -1 ) {
                    if ( is_call_or_jmp_with_register_operands(&insn) ) {
                        /**gadget = */create_gadget( tree, (unsigned long) ((char*)address + byte_count) );
                        ///if ( gadget != NULL )
                        ///    insert_gadget(tree, gadget);
                        retit++;
                    }
                }
                x86_oplist_free( &insn );
            }
        }
    }
    if (LOGLVL >= ERRLOG) printf("Gadget iterator: %x-%x: gad= %d, ret= %d\n", (unsigned int)start_address, (unsigned int)end_address, gadit, retit); // --- DEBUG OUTPUT ---
    gadit = 0; retit = 0;
    
    if ( attached ) ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
    return tree;
}

rb_tree* create_gadget_tree()
{
    return (rb_tree*)RBTreeCreate( compare_gadgets, destroy_gadget, null_function, null_function_const, null_function );
}

rb_node* insert_gadget(rb_tree* tree, gadget_struct* gadget)
{
    return (rb_node*)RBTreeInsert( (rb_red_blk_tree*)tree, (void*)gadget, NULL);
}

rb_node* search_gadget_by_address(rb_tree* tree, unsigned int address)
{
    gadget_struct gadget_for_search = {address};
    
    if ( tree != NULL )
        return RBExactQuery( (rb_red_blk_tree*)tree, &gadget_for_search);
    else
        return NULL;
    
    ///int iter;
    ///rb_node* node = NULL;
    ///
    ///gadget_struct gadget_for_search = {address,address,0,0};
    ///
    ///node = RBExactQuery( (rb_red_blk_tree*)tree, &gadget_for_search);
    ///if ( node == NULL ) return NULL;
    ///
    ///for(iter = 0; iter < ((gadget_struct*)(node->key))->real_start_positions_number; iter++)
    ///{
    ///    if ( (unsigned long)address == 0x8048483 ) 
    ///        printf("0x%lx-0x%lx: Real= 0x%lx-0x%lx \n", ((gadget_struct*)(node->key))->start_address, ((gadget_struct*)(node->key))->ret_address, ((gadget_struct*)(node->key))->real_start_positions[iter]); // --- DEBUG OUTPUT ---
    ///    
    ///    if ( ((gadget_struct*)(node->key))->real_start_positions[iter] == address )
    ///        return node;
    ///}
    ///if ( ((gadget_struct*)(node->key))->ret_address == address )
    ///    return node;
    ///
    ///return NULL;
}

void destroy_gadget_tree(rb_tree* tree)
{
    RBTreeDestroy( (rb_red_blk_tree*)tree );
}

int compare_gadgets(const void* a,const void* b)
{
    ///if ( ((gadget_struct*)a)->start_address >= ((gadget_struct*)b)->ret_address   ) return(1);
    ///if ( ((gadget_struct*)a)->ret_address   <= ((gadget_struct*)b)->start_address ) return(-1);
    ///return(0);
    if ( ((gadget_struct*)a)->start_address > ((gadget_struct*)b)->start_address ) return(1);
    if ( ((gadget_struct*)a)->start_address < ((gadget_struct*)b)->start_address ) return(-1);
    return(0);
}

void destroy_gadget(void* a)
{
    ///if ( ((gadget_struct*)a)->real_start_positions != NULL )
    ///    free( ((gadget_struct*)a)->real_start_positions );
    free( (gadget_struct*)a );
}

void null_function(void * junk) { ; }
void null_function_const(const void * junk) { ; }


