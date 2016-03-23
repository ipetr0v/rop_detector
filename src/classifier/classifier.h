#ifndef _CLASSIFIER_H
#define _CLASSIFIER_H

#include "../general_include.h"

#include "../engine/process.h"
#include "../emulator/emulator_interface.h"

typedef struct classifier_struct{
    int static_detection_count;
    int gadget_detection_count;
    int dynamic_detection_count;
    int system_call_detection_count;
} classifier_struct;

rb_node* vma_rb_search(process_struct* process, unsigned int address);
rb_node* exec_vma_rb_search(process_struct* process, unsigned int address);
return_addresses_array* classifier_address_search(process_struct* process, char* buffer_for_check, unsigned long buffer_len);
emulation_results_struct* classifier_emulation( process_struct* process, 
                                                char* buffer_for_check, unsigned long buffer_len, 
                                                return_addresses_array* ret_array);

unsigned long rop_detector_classifier(process_struct* process, char* buffer_for_check, unsigned long buffer_len, classifier_struct* classifier);

#endif