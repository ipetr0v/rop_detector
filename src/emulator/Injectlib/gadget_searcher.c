#include "gadget_searcher.h"

int is_correct_disassembled_gadget( unsigned char* buffer, unsigned int len, unsigned int address, unsigned int ret_address )
{
    int size;
    x86_insn_t insn;
    int offset = 0;
    
    while( offset < len )
    {
        size = disassemble_buffer( buffer+offset, len - offset, &insn);
        
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

unsigned int find_gadget(unsigned int target_address)
{
    unsigned char memory_byte;
    unsigned int memory_word;
    unsigned int possible_ret_address;
    unsigned int start_iteration_address;
    unsigned int end_iteration_address;
    unsigned int vma_last_address;
    int vma_num;
    
    // Disas
    int size;                /* size of instruction */
    x86_insn_t insn;         /* instruction */
    // Disas
    
    if ( (vma_num = find_vma_by_address( (uint32_t)target_address )) == -1 )
        return 0;
    
    // Disas
    disassembler_init();
    // Disas
    
    vma_last_address = get_vma_end(vma_num);
    start_iteration_address = target_address;
    end_iteration_address = ( target_address + OFFSET_BEFORE_RET < vma_last_address ) ? target_address + OFFSET_BEFORE_RET: vma_last_address;
    
    for( possible_ret_address = start_iteration_address; possible_ret_address < end_iteration_address; possible_ret_address++ )
    {
        memory_byte = *((char*)possible_ret_address);
           
        if ( memory_byte == RET_OPCODE ) // Ret
        {
            if ( is_correct_disassembled_gadget( (unsigned char*)target_address, possible_ret_address - target_address, target_address, possible_ret_address ) )
                return possible_ret_address;
        }
        else if ( memory_byte == CALL_OR_JMP_OPCODE && possible_ret_address + 3 < vma_last_address) // JMP or CALL
        {
            memory_word = *((unsigned long*)possible_ret_address);
            
            size = disassemble_word( (unsigned char*)(&memory_word), &insn);
            if ( size != -1 ) {
                if ( is_call_or_jmp_with_register_operands(&insn) ) {
                    if ( is_correct_disassembled_gadget( (unsigned char*)target_address, possible_ret_address - target_address, target_address, possible_ret_address ) )
                        return possible_ret_address;
                }
            }
            x86_oplist_free( &insn );
        }
    }
    // Disas
    disassembler_destroy();
    // Disas
    
    return 0;
}