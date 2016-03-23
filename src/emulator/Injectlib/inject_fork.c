#include "inject_fork.h"

pid_t emulator_pid = 0;
void* emulator_lib_handle = NULL;
lib_arguments_struct* library_arguments = NULL;
shared_memory_struct shmem_st;
int test_supertest = 0;

size_t MAX_ret_num = MAX_RETURN_NUMBER;
size_t MAX_vma_num = 0;

pid_t fork_process(lib_arguments_struct* data, size_t datalen)
{
    pid_t child_pid;
    
    char stack_buffer[STACK_BUFFER_SIZE]; // Stack buffer analized data
    data->stack_buffer = (void*)stack_buffer;
    
    void *child_stack = mmap(NULL, CHILD_STACK_SIZE, PROT_WRITE|PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    child_pid = clone(&load_emulator_library, child_stack + CHILD_STACK_SIZE, CLONE_IO|SIGCHLD, (void*)data/*(void*)(&stack_buffer)*/);
    
    if ( child_pid != 0 ){
        if (LOGLVL >= DBGLOG) printf("Inject_fork: I am not forked= %i, going to return\n", getpid()); // --- DEBUG OUTPUT ---
        munmap(child_stack, CHILD_STACK_SIZE);
        return child_pid;
    }
    return 0;
}

int load_emulator_library(/*char* lib_name, size_t name_len, void* stack_buffer*/void* data)
{
    library_arguments = (lib_arguments_struct*)data;
    emulator_pid = getpid();
    
    shmem_st.shared_memory_key = library_arguments->shared_memory_key;
    if ( attach_shared_memory(&shmem_st) == NULL) {
        if (LOGLVL >= ERRLOG) printf("Inject- %i : attach_shared_memory error\n", getpid()); // --- DEBUG OUTPUT ---
        return -1;
    }
    library_arguments->shmem_st = &shmem_st;
    
    if (LOGLVL >= DBGLOG) printf("Inject_fork: I am forked= %i\n", getpid()); // --- DEBUG OUTPUT ---
    emulator_lib_handle = dlopen ("/mnt/hgfs/_Share/diplom/bin/libinject.so", RTLD_LAZY);
    if (!emulator_lib_handle) {
        if (LOGLVL >= ERRLOG) fputs (dlerror(), stderr);
        return 1;
    }
    
    // Sleep until main prog calls emulator
    while(1) {
        sleep(10);
    }
    
    detach_shared_memory(&shmem_st);
    dlclose(emulator_lib_handle);
    return 0;
}

int run_dynamic_classifier()
{
    char *error;
    int (*dynamic_classifier)(lib_arguments_struct*);
    
    if (LOGLVL >= DBGLOG) printf("Inject_fork: run_emulator= %i\n", getpid()); // --- DEBUG OUTPUT ---
    dynamic_classifier = dlsym(emulator_lib_handle, "dynamic_classifier");
    if ((error = dlerror()) != NULL)  {
        if (LOGLVL >= ERRLOG) fputs(error, stderr);
        return -1;
    }
    
    // --- CALL EMULATOR FUNCTION ---
    return (*dynamic_classifier)( (lib_arguments_struct*)library_arguments );
}

int wait_emulator(pid_t* data, size_t datalen)
{
    int status;
    if (LOGLVL >= DBGLOG) printf("Inject_fork %d : wait_emulator= %d\n", getpid(), *data); // --- DEBUG OUTPUT ---
    ///while(1){
    ///    waitpid(*data, &status, 0);
    ///    if(WIFEXITED(status)) {
    ///        return 0;
    ///    }
    ///}
    waitpid(*data, &status, 0);
    if (LOGLVL >= DBGLOG) printf("Inject_fork %d : wait success\n", getpid() ); // --- DEBUG OUTPUT ---
    return 0;
}




