#ifndef _LIBEMU_MEMORY_ACCESS_H
#define _LIBEMU_MEMORY_ACCESS_H

#include "../general_include.h"

#include "../types.h"
#include "shared_memory_wrapper.h"
#include "../engine/process.h"

typedef struct memory_access_struct{
    void *address;
    void *last_address_in_vma;
} memory_access_struct;

typedef struct saved_buffer_struct{
    void* memory_address;
    size_t size;
    
    void* buffer;
} saved_buffer_struct;

typedef struct saved_memory_struct{
    unsigned int array_size;
    unsigned int allocated_elems;
    saved_buffer_struct* buffer_array;
} saved_memory_struct;

void init_saved_memory();
void destroy_saved_memory();
void restore_saved_memory();
void add_saved_memory(void* destination, const void* source, size_t size);
void safe_memcpy(void* destination, const void* source, size_t size);

void set_vma_array(proto_vma_array* vma_ar, int vma_ar_size);
void init_emulator_heap(void* old_heap_pointer, size_t old_heap_size_value);
void init_emulator_stack( void* old_stack_pointer, size_t old_stack_size_value,
                          void* new_stack_pointer, size_t new_stack_size_value );
void destroy_emulator_heap();

inline unsigned int get_vma_flags(int vma_num);
inline unsigned int get_vma_start(int vma_num);
inline unsigned int get_vma_end(int vma_num);
inline int find_vma_by_address(uint32_t addr);
inline uint32_t heap_access(uint32_t addr);

void translate_address(memory_access_struct* m_str, uint32_t addr, unsigned int flag);
void* get_translated_address(uint32_t addr, unsigned int flag);
void safe_memcpy(void * destination, const void * source, size_t num);

#endif