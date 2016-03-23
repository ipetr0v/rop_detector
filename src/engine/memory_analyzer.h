#ifndef _MEMORY_ANALYZER_H
#define _MEMORY_ANALYZER_H

#include "../general_include.h"

#include "../disassembler/disassembler_interface.h"
#include "../rb_tree/red_black_tree.h"

#define OFFSET_BEFORE_RET (24)

typedef rb_red_blk_tree rb_tree;
typedef rb_red_blk_node rb_node;

typedef struct gadget_struct{
    unsigned long start_address;
    //unsigned long ret_address; // Or JMP
    
    ///unsigned int real_start_positions_number;
    ///unsigned long* real_start_positions;
} gadget_struct;

typedef struct return_address_in_buffer{
    unsigned long offset_in_buffer;
    unsigned long* ret;
} return_address_in_buffer;

typedef struct return_addresses_array{
    int ret_num;
    return_address_in_buffer* ret_address;
} return_addresses_array;

rb_tree* init_gadget_tree(pid_t pid, unsigned int vm_start, unsigned int vm_end);
rb_tree* create_gadget_tree();
rb_node* insert_gadget(rb_tree* tree, gadget_struct* gadget);
rb_node* search_gadget_by_address(rb_tree* tree, unsigned int address);
void destroy_gadget_tree(rb_tree* tree);
int compare_gadgets(const void* a,const void* b);
void destroy_gadget(void* a);
void null_function(void * junk);
void null_function_const(const void * junk);

#endif