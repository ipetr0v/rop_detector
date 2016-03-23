#ifndef _SNIFFER_H
#define _SNIFFER_H

#include "../general_include.h"

void sniffer_init(char *dev);
void sniffer_destroy();
int sniffer_process_packet(unsigned char** payload_pointer, unsigned int* ip_address, unsigned short* port_number);

#endif