#ifndef _GADGET_SEARCHER_ACCESS_H
#define _GADGET_SEARCHER_ACCESS_H

#include "../emul_types.h"
#include "../shared_memory_wrapper.h"
#include "../libemu_memory_access.h"

#include "../../disassembler/disassembler_interface.h"

int is_correct_disassembled_gadget( unsigned char* buffer, unsigned int len, unsigned int address, unsigned int ret_address );
unsigned int find_gadget(unsigned int target_address);

#endif
