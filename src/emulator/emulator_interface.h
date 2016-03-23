#ifndef _EMULATOR_INTERFACE_H
#define _EMULATOR_INTERFACE_H

#include "../general_include.h"

#include "../engine/kernel_interface.h"
#include "../engine/auxiliary.h"
#include "hotpatch/hotpatch.h"
#include "hotpatch/hotpatch_internal.h"
#include "emul_types.h"
#include "shared_memory_wrapper.h"
#include "../engine/process.h"

#define HOTPATCH_LOG 0

pid_t create_emulator(process_struct* process);
emulation_results_struct* init_emulator( process_struct* process, 
                                         char* buffer_for_check, size_t buffer_len, 
                                         return_addresses_array* ret_array );
///int emulation_results(process_struct* emu_parent_process, pid_t emulator_pid);
void destroy_emulator(process_struct* emu_parent_process);

#endif