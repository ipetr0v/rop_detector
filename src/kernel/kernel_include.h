#ifndef _KERNEL_INCLUDE_H
#define _KERNEL_INCLUDE_H

// kernel_main.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/seqlock.h>
#include <linux/capability.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
//#include <linux/vmacache.h>
#include <net/sock.h>
#include <linux/fs.h>
#include <linux/pid.h>
#include <linux/net.h>
#include <linux/sched.h>
#include <linux/fdtable.h>

// serber.h
#include <linux/module.h>
#include <linux/init.h>
#include <linux/in.h>
#include <net/sock.h>
#include <linux/skbuff.h>
#include <linux/delay.h>
#include <linux/inet.h>

#define SERVER_PORT 5555


#endif