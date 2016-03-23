#ifndef _ENGINE_H
#define _ENGINE_H

#include "../general_include.h"

#include "sniffer.h"
#include "process.h"
#include "../classifier/classifier.h"
#include "../rb_tree/red_black_tree.h"
#include "../emulator/shared_memory_wrapper.h"

int engine_test_run(unsigned long random_address_iteration_number);
int engine_init();

void* input_buffer();
int engine_classifier(unsigned long buffer_len, unsigned int ip, unsigned short port);

#endif