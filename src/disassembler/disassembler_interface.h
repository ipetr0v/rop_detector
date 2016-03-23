#ifndef _DISASSEMBLER_INTERFACE_H
#define _DISASSEMBLER_INTERFACE_H

//#include "libudis86/udis86.h"
#include "../general_include.h"
#include "libdisasm/libdis.h"

#define RET_OPCODE (0xC3)
#define CALL_OR_JMP_OPCODE (0xFF)

void disassembler_init();
void disassembler_destroy();

int disassemble_word(unsigned char* memory_word, x86_insn_t* insn);
int disassemble_buffer(unsigned char* memory_address, unsigned int lenght, x86_insn_t* insn);
int has_register_operand(x86_insn_t* insn);
int is_call_or_jmp_with_register_operands(x86_insn_t* insn);

#endif