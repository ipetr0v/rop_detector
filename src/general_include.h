#ifndef _GENERAL_INCLUDE_H
#define _GENERAL_INCLUDE_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

// main
#include <dirent.h>

// memory_analyzer
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/time.h> 
#include <sys/resource.h>

// engine
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

// sniffer
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

// client
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>

// emul_types
#include <dlfcn.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sched.h>
#include <signal.h>
#include <fcntl.h>

// Log color
#define CLR_RED     "\x1b[31m"
#define CLR_GREEN   "\x1b[32m"
#define CLR_YELLOW  "\x1b[33m"
#define CLR_BLUE    "\x1b[34m"
#define CLR_MAGENTA "\x1b[35m"
#define CLR_CYAN    "\x1b[36m"
#define CLR_RESET   "\x1b[0m"

// Log system
#define NONLOG (0)
#define ERRLOG (1)
#define DBGLOG (2)
#define ADVLOG (3)

#define LOGLVL (1)




#endif