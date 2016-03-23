#include "emulator.h"

extern struct emu_cpu_instruction_info ii_onebyte[];

emulator_struct* new_emulator()
{
    emulator_struct* emul_struct = (emulator_struct*)malloc( sizeof(emulator_struct) );
    
    emul_struct->emulator = emu_new();
	emul_struct->cpu = emu_cpu_get(emul_struct->emulator);
	emul_struct->memory = emu_memory_get(emul_struct->emulator);
    
    return emul_struct;
}

void init_emulator( emulator_struct* emul_struct, shared_memory_struct* shmem_st, uint32_t stack_buffer_pointer,
                                                                                  return_address_in_buffer* return_addr )
{
    /*if (pos==0) {
		pos = reader->start();
	}
	offset = reader->map(pos) - pos;
	uint start = max((int) reader->start(), (int) pos - mem_before), end = min(reader->size(), pos + mem_after);

	for (int i=0; i<8; i++) {
		emu_cpu_reg32_set(emul_struct->cpu, (emu_reg32) i, 0);
	}
    */
    ///init_emulator_heap( get_shmem_header(shmem_st)->old_heap_pointer, get_shmem_header(shmem_st)->old_heap_size_value );
    
    if ( correct_shmem(shmem_st) )
    {
        emu_cpu_reg32_set(emul_struct->cpu, esp, stack_buffer_pointer + 
                                                 /*(get_shmem_ret(shmem_st,0))*/return_addr->offset_in_buffer + sizeof(int) ); // Stack
        emu_cpu_eip_set( emul_struct->cpu, (unsigned int)/*(get_shmem_ret(shmem_st,0))*/return_addr->ret ); // Process counter
    }
    /*printf("Inject- %i : In stack= %x\n", getpid(), *( (unsigned int*)(stack_buffer_pointer + 
                                                                        (get_shmem_ret(shmem_st,0))->offset_in_buffer) + 0 ) ); // --- DEBUG OUTPUT ---
    printf("Inject- %i : In stack= %x\n", getpid(), *( (unsigned int*)(stack_buffer_pointer + 
                                                                        (get_shmem_ret(shmem_st,0))->offset_in_buffer) + 1 ) ); // --- DEBUG OUTPUT ---
    printf("Inject- %i : In stack= %x\n", getpid(), *( (unsigned int*)(stack_buffer_pointer + 
                                                                        (get_shmem_ret(shmem_st,0))->offset_in_buffer) + 2 ) ); // --- DEBUG OUTPUT ---
    */
    emu_memory_segment_set(emul_struct->memory, s_cs, ((shared_memory_header*)shmem_st->shmaddr)->regs.xcs);
    emu_memory_segment_set(emul_struct->memory, s_ss, ((shared_memory_header*)shmem_st->shmaddr)->regs.xss);
    emu_memory_segment_set(emul_struct->memory, s_ds, ((shared_memory_header*)shmem_st->shmaddr)->regs.xds);
    emu_memory_segment_set(emul_struct->memory, s_es, ((shared_memory_header*)shmem_st->shmaddr)->regs.xes);
    emu_memory_segment_set(emul_struct->memory, s_fs, ((shared_memory_header*)shmem_st->shmaddr)->regs.xfs);
    emu_memory_segment_set(emul_struct->memory, s_gs, ((shared_memory_header*)shmem_st->shmaddr)->regs.xgs);
    
    emu_cpu_reg32_set(emul_struct->cpu, 0, ((shared_memory_header*)shmem_st->shmaddr)->regs.eax);
    emu_cpu_reg32_set(emul_struct->cpu, 1, ((shared_memory_header*)shmem_st->shmaddr)->regs.ecx);
    emu_cpu_reg32_set(emul_struct->cpu, 2, ((shared_memory_header*)shmem_st->shmaddr)->regs.edx);
    emu_cpu_reg32_set(emul_struct->cpu, 3, ((shared_memory_header*)shmem_st->shmaddr)->regs.ebx);
    //emu_cpu_reg32_set(emul_struct->cpu, 4, ((shared_memory_header*)shmem_st->shmaddr)->regs.esp);
    emu_cpu_reg32_set(emul_struct->cpu, 5, ((shared_memory_header*)shmem_st->shmaddr)->regs.ebp);
    emu_cpu_reg32_set(emul_struct->cpu, 6, ((shared_memory_header*)shmem_st->shmaddr)->regs.esi);
    emu_cpu_reg32_set(emul_struct->cpu, 7, ((shared_memory_header*)shmem_st->shmaddr)->regs.edi);
    //
	//emu_cpu_reg32_set(emul_struct->cpu, esp, state->regs.esi - STACK_BUFFER_SIZE); // Stack
	//emu_cpu_eip_set(emul_struct->cpu, state->regs.eip); // Process counter
    //
    ////void *memcpy(void *dst, const void *src, size_t n);
    //
	//emu_memory_clear(emul_struct->memory);
	////emu_memory_write_block(emul_struct->memory, offset + start, reader->pointer() + start, end - start);
}

void destroy_emulator(emulator_struct* emul_struct)
{
	emu_free(emul_struct->emulator);
    free(emul_struct);
}

inline int is_system_call(struct emu_cpu *c)
{
    if ( (unsigned int)(c->cpu_instr_info) == (unsigned int)(&ii_onebyte[0xcd]) ) {
        return 1;
    }
    return 0;
}

inline int is_ret(struct emu_cpu *c)
{
    if ( c == NULL )
        return 0;
    
    if ( (unsigned int)(c->cpu_instr_info) == (unsigned int)(&ii_onebyte[0xc3]) ) {
        return 1;
    }
    return 0;
}

inline int is_jmp_reg(struct emu_cpu *c)
{
    if ( c == NULL )
        return 0;
    /* 4 = instr_group_5_ff_jmp */
    if ( ( ( (unsigned int)(c->cpu_instr_info) == (unsigned int)(&ii_onebyte[0xff]) ) && (c->instr.is_fpu != 1) ) && 
         ( c->instr.cpu.modrm.opc == 4 ) ) {
        return 1;
    }
    return 0;
}

inline int is_call_reg(struct emu_cpu *c)
{
    if ( c == NULL )
        return 0;
    /* 2 = instr_group_5_ff_call */
    if ( ( ( (unsigned int)(c->cpu_instr_info) == (unsigned int)(&ii_onebyte[0xff]) ) && (c->instr.is_fpu != 1) ) && 
         ( c->instr.cpu.modrm.opc == 2 ) ) {
        return 1;
    }
    return 0;
}

inline int is_call_imm(struct emu_cpu *c)
{
    if ( c == NULL )
        return 0;
    /* 3 = instr_group_5_ff_call */
    if ( ( ( (unsigned int)(c->cpu_instr_info) == (unsigned int)(&ii_onebyte[0xff]) ) && (c->instr.is_fpu != 1) ) && 
         ( c->instr.cpu.modrm.opc == 3 ) ) {
        return 1;
    }
    return 0;
}

inline int is_call_e8(struct emu_cpu *c)
{
    if ( c == NULL )
        return 0;
    
    if ( ( (unsigned int)(c->cpu_instr_info) == (unsigned int)(&ii_onebyte[0xe8]) ) ) {
        return 1;
    }
    return 0;
}

inline int is_call(struct emu_cpu *c)
{
    if ( c == NULL )
        return 0;
        
    if ( is_call_e8(c) || is_call_reg(c) || is_call_imm(c) ) {
        return 1;
    }
    
    return 0;
}

inline int check_ret(struct emu_cpu *c)
{
    if ( c == NULL )
        return 0;
    
    /////printf("Inject- %i : opc= %d, fpu= %d, info= %d, ii= %d \n", getpid(), c->instr.cpu.modrm.opc, c->instr.is_fpu, (unsigned int)(c->cpu_instr_info), (unsigned int)(&ii_onebyte[0xff])); // --- DEBUG OUTPUT ---
    ///if ( (unsigned int)(c->cpu_instr_info) == (unsigned int)(&ii_onebyte[0xc3]) ) {
    ///    return 1;
    ///}
    ///
    ////* 2 = instr_group_5_ff_call */
    ////* 4 = instr_group_5_ff_jmp */
    ///if ( ( ( (unsigned int)(c->cpu_instr_info) == (unsigned int)(&ii_onebyte[0xff]) ) && (c->instr.is_fpu != 1) ) && 
    ///     ( c->instr.cpu.modrm.opc == 2 || c->instr.cpu.modrm.opc == 4 ) ) {
    ///    return 1;
    ///}
    if ( is_ret(c) || is_jmp_reg(c) || is_call_reg(c) ) {
        return 1;
    }
    
    return 0;
}

int run_emulator(emulator_struct* emul_struct, emulation_results_struct* emu_results)
{
    struct emu_cpu *c = emul_struct->cpu;
    
    single_list* saved_ret_list = NULL;
    saved_returns_struct* saved_ret = NULL;
    unsigned int saved_ret_value = 0;
    unsigned int* mem_pointer = 0;
    
	int steps = 0;
    int ret_number = 0;
    int system_call_number = 0;
    
    int prev_step_ret = 0;
    if (LOGLVL >= DBGLOG) printf("---------------- Emulation ------------------\n"); // --- DEBUG OUTPUT ---
	while (emu_cpu_parse(c) == 0)
	{
        if (prev_step_ret) {
            ret_number++;
            prev_step_ret = 0;
        }
        // -------------------------------
        
        if ( check_ret(c) ) {
            prev_step_ret = 1;
        }
        else {
            prev_step_ret = 0;
        }
        
        if ( is_call(c) ) {
            saved_ret = (saved_returns_struct*)malloc( sizeof(saved_returns_struct) );
            saved_ret->mem_pointer = (unsigned int)get_translated_address( emu_cpu_reg32_get(c, esp) - 4, VM_READ );
            saved_ret->saved_ret_value = emu_cpu_eip_get(c);
            add_elem(&saved_ret_list, saved_ret->mem_pointer, saved_ret);
            ///if (LOGLVL >= DBGLOG) printf("Inject- %i : SAVE: sp= 0x%x, mem= 0x%x, saved= 0x%x\n", getpid(), 
            ///                                                                                      emu_cpu_reg32_get(c, esp) - 4, 
            ///                                                                                      saved_ret->mem_pointer, 
            ///                                                                                      saved_ret->saved_ret_value); // --- DEBUG OUTPUT ---
        }
        
        if ( is_ret(c) ) {
            mem_pointer = (unsigned int*)get_translated_address( emu_cpu_reg32_get(c, esp), VM_READ );
            if ( mem_pointer != NULL )
            {
                saved_ret_value = *mem_pointer;
                ///if (LOGLVL >= DBGLOG) printf("Inject- %i : LOAD: sp= 0x%x, mem= 0x%x, saved= 0x%x\n", getpid(), 
                ///                                                                                      emu_cpu_reg32_get(c, esp), 
                ///                                                                                      (unsigned int)mem_pointer, 
                ///                                                                                      saved_ret_value); // --- DEBUG OUTPUT ---
                saved_ret = (saved_returns_struct*)find_elem_by_key(&saved_ret_list, (unsigned int)mem_pointer);
                ///printf("Inject- %i : saved_ret= 0x%x\n", getpid(), (unsigned int)saved_ret); // --- DEBUG OUTPUT ---
                if ( saved_ret != NULL )
                {
                    if ( saved_ret->saved_ret_value == saved_ret_value )
                    {
                        prev_step_ret = 0;
                        delete_elem(&saved_ret_list, saved_ret_value);
                    }
                }
            }
        }
        
        if ( is_system_call(c) ) {
            system_call_number++;
        }
        
        ///printf("Inject- %i : ii= %x, info= %x, opc= %d\n", getpid(), 
        ///                                                   (unsigned int)(&ii_onebyte[0xff]),
        ///                                                   (unsigned int)(c->cpu_instr_info),
        ///                                                   c->instr.cpu.modrm.opc ); // --- DEBUG OUTPUT ---
        
        if (LOGLVL >= DBGLOG) {
            if ( prev_step_ret )
                printf("Inject- %i : ISRET, current retnum= %i\n", getpid(), ret_number-1); // --- DEBUG OUTPUT ---
            else
                printf("Inject- %i : NOTRET, current retnum= %i\n", getpid(), ret_number-1); // --- DEBUG OUTPUT ---
        }
        // -------------------------------
        if (LOGLVL >= DBGLOG) printf("----------------------------------------\n"); // --- DEBUG OUTPUT ---
		if ( emu_cpu_step(c) != 0 )
			break;
		steps++;
        if ( steps > MAX_EMULATOR_STEPS )
            break;
	}
    if (LOGLVL >= DBGLOG) printf("------------- Emulation ends ----------------\n"); // --- DEBUG OUTPUT ---
    if (LOGLVL >= DBGLOG)
    {
        if ( steps > MAX_EMULATOR_STEPS )
            printf("Inject- %i : Max steps value %i reached\n", getpid(), MAX_EMULATOR_STEPS); // --- DEBUG OUTPUT ---
        else
            printf("Inject- %i : %s \n", getpid(), emu_strerror(c->emu)); // --- DEBUG OUTPUT ---
    }
    
    destroy_list(&saved_ret_list);
    
    emu_results->ret_number = ret_number;
    emu_results->system_call_number = system_call_number;
	return ret_number;
}

