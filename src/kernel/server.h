#ifndef _SERVER_H
#define _SERVER_H

#include "kernel_include.h"
#include "../types.h"

struct wq_wrapper{
    struct work_struct worker;
	struct sock* sk;
};

void cb_data(struct sock *sk, int bytes);

void recv_message(struct work_struct *data);
void send_message(char* send_message_body, size_t send_message_len);
int server_init( void (*handler)(char *, size_t) );
void server_exit( void );

#endif