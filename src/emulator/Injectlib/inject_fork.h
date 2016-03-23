#ifndef _INJECT_FORK_H
#define _INJECT_FORK_H

#include "../emul_types.h"
#include "../shared_memory_wrapper.h"

pid_t fork_process(lib_arguments_struct* data, size_t datalen);
int load_emulator_library(void* data);
int run_dynamic_classifier();
int wait_emulator(pid_t* data, size_t datalen);

#endif