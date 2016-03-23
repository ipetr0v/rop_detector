#include "libemu_memory_access.h"

/*typedef struct proto_vma_array{
    unsigned int vm_start;
    unsigned int vm_end;
    unsigned int vm_flags;
} proto_vma_array;
typedef struct vma_array{
    int vma_num;
    proto_vma_array* vmas;
} vma_array;*/

int global_vma_ar_size;
proto_vma_array* global_vma_ar;

size_t emulator_stack_size;
void* emulator_stack;
size_t old_stack_size;
void* old_stack;

size_t emulator_heap_size;
void* emulator_heap;
size_t old_heap_size;
void* old_heap;

saved_memory_struct* saved_memory;

void init_saved_memory()
{
    saved_memory = (saved_memory_struct*)malloc( sizeof(saved_memory_struct) );
    saved_memory->array_size = 0;
    saved_memory->allocated_elems = 10;
    saved_memory->buffer_array = (saved_buffer_struct*)malloc( sizeof(saved_buffer_struct) * saved_memory->allocated_elems );
}

void destroy_saved_memory()
{
    int iter;
    
    if ( saved_memory == NULL ) return;
    if ( saved_memory->array_size > 0 && saved_memory->buffer_array != NULL )
    {
        for(iter=0; iter < saved_memory->array_size; iter++)
        {
            if ( (saved_memory->buffer_array)[iter].size > 0 && (saved_memory->buffer_array)[iter].buffer != NULL )
                free( (saved_memory->buffer_array)[iter].buffer );
        }
        free( saved_memory->buffer_array );
    }
    free(saved_memory);
}

void restore_saved_memory()
{
    int iter;
    
    if ( saved_memory == NULL ) return;
    if ( saved_memory->array_size > 0 && saved_memory->buffer_array != NULL )
    {
        ///for(iter=0; iter < saved_memory->array_size; iter++)
        for(iter = saved_memory->array_size - 1; iter >= 0; iter--)
        {
            if ( (saved_memory->buffer_array)[iter].size > 0 && (saved_memory->buffer_array)[iter].buffer != NULL )
            {
                if (LOGLVL >= ADVLOG) printf("Inject- %i : Restore 0x%08x with: %x (%d)\n", getpid(), 
                                                             (unsigned int)( (saved_memory->buffer_array)[iter].memory_address ), 
                                                             *((unsigned int*)( (saved_memory->buffer_array)[iter].buffer )),
                                                             (saved_memory->buffer_array)[iter].size ); // --- DEBUG OUTPUT ---
                
                memcpy( (saved_memory->buffer_array)[iter].memory_address,
                        (saved_memory->buffer_array)[iter].buffer,
                        (saved_memory->buffer_array)[iter].size );
            }
        }
    }
}

void add_saved_memory(void* destination, const void* source, size_t size)
{
    if ( saved_memory->array_size >= saved_memory->allocated_elems )
    {
        saved_memory->allocated_elems += 10;
        saved_memory->buffer_array = (saved_buffer_struct*)realloc( saved_memory->buffer_array, 
                                                                    sizeof(saved_buffer_struct) * saved_memory->allocated_elems );
    }
    
    (saved_memory->buffer_array)[saved_memory->array_size].memory_address = destination;
    (saved_memory->buffer_array)[saved_memory->array_size].size = size;
    
    (saved_memory->buffer_array)[saved_memory->array_size].buffer = malloc( size );
    memcpy( (saved_memory->buffer_array)[saved_memory->array_size].buffer, destination, size );
    
    saved_memory->array_size += 1;
}

void safe_memcpy(void* destination, const void* source, size_t size)
{
    if ( saved_memory == NULL || size <=0 )
        return;
    add_saved_memory(destination, source, size);
    memcpy(destination, source, size);
}

void set_vma_array(proto_vma_array* vma_ar, int vma_ar_size)
{
    global_vma_ar_size = vma_ar_size;
    global_vma_ar = vma_ar;
}

void init_emulator_heap(void* old_heap_pointer, size_t old_heap_size_value)
{
    old_heap_size = old_heap_size_value;
    old_heap = old_heap_pointer;
    
    emulator_heap_size = old_heap_size;
    emulator_heap = mmap(NULL, old_heap_size_value, PROT_WRITE|PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
}

void init_emulator_stack( void* old_stack_pointer, size_t old_stack_size_value,
                          void* new_stack_pointer, size_t new_stack_size_value )
{
    old_stack_size = old_stack_size_value;
    old_stack = old_stack_pointer;
    
    emulator_stack_size = new_stack_size_value;
    emulator_stack = new_stack_pointer;
}

void destroy_emulator_heap()
{
    munmap(emulator_heap, emulator_heap_size);
}

inline unsigned int get_vma_flags(int vma_num)
{
    if ( 0 <= vma_num && vma_num < global_vma_ar_size)
        return global_vma_ar[vma_num].vm_flags;
    else
        return 0;
}
inline unsigned int get_vma_start(int vma_num)
{
    if ( 0 <= vma_num && vma_num < global_vma_ar_size)
        return global_vma_ar[vma_num].vm_start;
    else
        return -1;
}
inline unsigned int get_vma_end(int vma_num)
{
    if ( 0 <= vma_num && vma_num < global_vma_ar_size)
        return global_vma_ar[vma_num].vm_end;
    else
        return -1;
}

inline int find_vma_by_address(uint32_t addr)
{
    int i;
    for( i=0; i<global_vma_ar_size; i++)
    {
        if ( (unsigned int)addr >= get_vma_start(i) )
            if ( (unsigned int)addr < get_vma_end(i) )
                return i;
    }
    return -1;
}

inline uint32_t heap_access(uint32_t addr)
{
    if ( (uint32_t)old_heap <= addr && addr < (uint32_t)old_heap + old_heap_size )
        return (uint32_t)( emulator_heap + (addr - (uint32_t)old_heap) );
    else
        return 0;
}

inline uint32_t stack_access(uint32_t addr)
{
    if ( (uint32_t)old_stack <= addr && addr < (uint32_t)old_stack + old_stack_size ) {
        if (LOGLVL >= ADVLOG) printf("Inject- %i : Address %x in stack, new addr= %x\n", 
                                     getpid(), addr, 
                                     (uint32_t)( emulator_stack + (addr - (uint32_t)old_stack) ) ); // --- DEBUG OUTPUT ---
        
        return (uint32_t)( emulator_stack + (addr - (uint32_t)old_stack) );
    }
    else {
        if (LOGLVL >= ADVLOG) printf("Inject- %i : Address %x not in stack\n", getpid(), addr ); // --- DEBUG OUTPUT ---
        return 0;
    }
}

void translate_address(memory_access_struct* m_str, uint32_t addr, unsigned int flag)
{
    int vma_num;
    uint32_t shifted_addr = 0;
    
    shifted_addr = stack_access(addr);
    if ( shifted_addr == 0 ) {
        shifted_addr = heap_access(addr);
    }
    
    // --- TEST ---
    //printf("Inject- %i : Addr: %x, VMA-start %x | ", getpid(), addr, get_vma_start( find_vma_by_address(addr) ) ); // --- DEBUG OUTPUT ---
    //switch ( flag ) 
    //{
    //    case VM_READ:
    //        printf("flag VM_READ \n"); // --- DEBUG OUTPUT ---
    //        break;
    //    case VM_WRITE:
    //        printf("flag VM_WRITE \n"); // --- DEBUG OUTPUT ---
    //        break;
    //    case VM_EXEC:
    //        printf("flag VM_EXEC \n"); // --- DEBUG OUTPUT ---
    //        break;
    //    default:
    //        printf("\n"); // --- DEBUG OUTPUT ---
	//		break;
    //}
    // --- TEST ---
    vma_num = find_vma_by_address(addr);
    switch ( flag ) 
    {
		case VM_READ:
            if ( shifted_addr != 0 )
            {// printf("Inject- %i : Address %x for read\n", getpid(), (unsigned int)m_str->address ); // --- DEBUG OUTPUT ---
                m_str->address = (void*)shifted_addr;
                m_str->last_address_in_vma = (void*)shifted_addr + emulator_heap_size;
            }
			else if ( (get_vma_flags(vma_num) & VM_READ) != 0 )
            {
                m_str->address = (void*)addr;
                m_str->last_address_in_vma = (void*)get_vma_end(vma_num);
            }
            else
            {
                m_str->address = NULL;
            }
			break;
        case VM_WRITE:
            if ( shifted_addr != 0 )
            {
                m_str->address = (void*)shifted_addr;
                m_str->last_address_in_vma = (void*)shifted_addr + emulator_heap_size;
            }
            else if ( (get_vma_flags(vma_num) & VM_WRITE) != 0 )
            {
                m_str->address = (void*)addr;
                m_str->last_address_in_vma = (void*)get_vma_end(vma_num);
            }
            else
            {
                m_str->address = NULL;
            }
            break;
        case VM_EXEC:
            if ( shifted_addr != 0 )
            {
                m_str->address = NULL;
            }
            else if ( (get_vma_flags(vma_num) & VM_EXEC) != 0 )
            {
                m_str->address = (void*)addr;
                m_str->last_address_in_vma = (void*)get_vma_end(vma_num);
            }
            else
            {
                m_str->address = NULL;
            }
            break;
        default:
            return;
			break;
    }
}

void* get_translated_address(uint32_t addr, unsigned int flag)
{
    int vma_num;
    uint32_t shifted_addr = 0;
    
    shifted_addr = stack_access(addr);
    if ( shifted_addr == 0 ) {
        shifted_addr = heap_access(addr);
    }
    
    vma_num = find_vma_by_address(addr);
    switch ( flag ) 
    {
		case VM_READ:
            if ( shifted_addr != 0 )
            {
                return (void*)shifted_addr;
            }
			else if ( (get_vma_flags(vma_num) & VM_READ) != 0 )
            {
                return (void*)addr;
            }
            else
            {
                return NULL;
            }
			break;
        case VM_WRITE:
            if ( shifted_addr != 0 )
            {
                return (void*)shifted_addr;
            }
            else if ( (get_vma_flags(vma_num) & VM_WRITE) != 0 )
            {
                return (void*)addr;
            }
            else
            {
                return NULL;
            }
            break;
        case VM_EXEC:
            if ( shifted_addr != 0 )
            {
                return NULL;
            }
            else if ( (get_vma_flags(vma_num) & VM_EXEC) != 0 )
            {
                return (void*)addr;
            }
            else
            {
                return NULL;
            }
            break;
        default:
            return NULL;
			break;
    }
    return NULL;
}

//void* nearest_vma_end(uint32_t addr)
//{
//    int i;
//    get_vma_end( find_vma_by_address(addr) );
//    for( i=0; i<global_vma_ar_size; i++)
//    {
//        if ( (unsigned int)addr >= get_vma_start(i) )
//            if ( (unsigned int)addr < get_vma_end(i) )
//                return i;
//    }
//    return -1;
//}





