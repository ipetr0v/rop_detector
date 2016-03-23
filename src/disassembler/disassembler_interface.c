#include "disassembler_interface.h"

void disassembler_init()
{
    x86_init(opt_none, NULL, NULL);
}

void disassembler_destroy()
{
    x86_cleanup();
}

int disassemble_word(unsigned char* memory_word, x86_insn_t* insn)
{
    return x86_disasm( memory_word, sizeof(long), 0, 0, insn);
}

int disassemble_buffer(unsigned char* memory_address, unsigned int lenght, x86_insn_t* insn)
{
    int disas_size =  x86_disasm( memory_address, lenght, 0, 0, insn);
	x86_oplist_free( insn );
    return disas_size;
}

int has_register_operand(x86_insn_t* insn)
{
    x86_oplist_t *ins_operand = insn->operands;
    while( ins_operand != NULL )
    {
        if ( ins_operand->op.type == op_register )
            return 1;
        ins_operand = ins_operand->next;
    }
    return 0;
}

int is_call_or_jmp_with_register_operands(x86_insn_t* insn)
{
    if ( insn->type == insn_jmp || insn->type == insn_jcc || insn->type == insn_call || insn->type == insn_callcc )
    {
        return has_register_operand(insn);
    }
    return 0;
}







