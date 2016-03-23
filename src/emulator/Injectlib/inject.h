#ifndef _INJECT_H
#define _INJECT_H

#include "../emul_types.h"
#include "../shared_memory_wrapper.h"
#include "../libemu_memory_access.h"

#include "emulator.h"
#include "gadget_searcher.h"
#include <sys/prctl.h>

int dynamic_classifier(lib_arguments_struct* library_arguments);

#endif