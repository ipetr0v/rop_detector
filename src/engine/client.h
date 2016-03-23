#ifndef _CLIENT_H
#define _CLIENT_H

#include "../general_include.h"
#include "../types.h"

int client_init( int process_port, int module_port );
int send_to_module( char* message, int size );
int recv_from_module( char* message, int size );

#endif