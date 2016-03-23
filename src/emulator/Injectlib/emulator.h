#ifndef _EMULATOR_H
#define _EMULATOR_H

#include "../libemu/emu.h"
#include "../libemu/emu_cpu.h"
#include "../libemu/emu_memory.h"
#include "../libemu/emu_cpu_data.h"
#include "../libemu/emu_log.h"
#include "../libemu/emu_cpu_instruction.h"

#include "../emul_types.h"
#include "../shared_memory_wrapper.h"
#include "../libemu_memory_access.h"
#include "../../engine/auxiliary.h"

typedef struct emulator_struct{
    struct emu *emulator;
    
	struct emu_logging *log;
	struct emu_memory *memory; 
	struct emu_cpu *cpu;
    
} emulator_struct;

typedef struct saved_returns_struct{
    unsigned int mem_pointer;
    unsigned int saved_ret_value;
} saved_returns_struct;

emulator_struct* new_emulator();
void init_emulator( emulator_struct* emul_struct, shared_memory_struct* shmem_st, uint32_t stack_buffer_pointer,
                                                                                  return_address_in_buffer* return_addr );
void destroy_emulator(emulator_struct* emul_struct);
int run_emulator(emulator_struct* emul_struct, emulation_results_struct* emu_results);

#endif