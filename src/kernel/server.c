#include "server.h"

MODULE_LICENSE( "GPL" );
MODULE_AUTHOR( "IPetr0v" );

struct socket *udpsocket = NULL;
struct socket *clientsocket = NULL;
static DECLARE_COMPLETION( threadcomplete );
struct workqueue_struct *wq;

unsigned short * port; // Current answering port

struct wq_wrapper wq_data;

void (*message_handler)(char *, size_t);

void cb_data(struct sock *sk, int bytes)
{
	wq_data.sk = sk;
	queue_work(wq, &wq_data.worker);
}

void recv_message(struct work_struct *data)
{
	struct  wq_wrapper * foo = container_of(data, struct  wq_wrapper, worker);
	int len = 0;
    //int sent_len = 0;
    
	// message receiving cycle
	while( (len = skb_queue_len(&foo->sk->sk_receive_queue)) > 0 )
    {
        struct sk_buff *skb = NULL;
        //unsigned short * port;
        //struct msghdr msg;
        //struct iovec iov;
        //mm_segment_t oldfs;
        //struct sockaddr_in to;
        //char* send_message_body;
        //int send_message_len;
    
        // receive packet
        skb = skb_dequeue(&foo->sk->sk_receive_queue);
        port = (unsigned short *)skb->data;
        //printk(KERN_DEBUG "ROP Module message len: %i message: %s\n", skb->len - 8, skb->data+8); /*8 for udp header*/
        
        message_handler( skb->data+8/*msg body*/, len /*msg len*/ );
        
        /*
        // generate answer message
        memset(&to,0, sizeof(to));
        to.sin_family = AF_INET;
        to.sin_addr.s_addr = in_aton("127.0.0.1");  
        port = (unsigned short *)skb->data;
        to.sin_port = *port;
        memset(&msg,0,sizeof(msg));
        msg.msg_name = &to;
        msg.msg_namelen = sizeof(to);
        
        // send the message back
        send_message_body = (char*)kmalloc(RECV_SIZE, GFP_KERNEL);
        send_message_len = message_handler(skb->data+8, send_message_body);
        iov.iov_base = send_message_body;
        iov.iov_len  = send_message_len;
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        
        // adjust memory boundaries
        oldfs = get_fs();
        set_fs(KERNEL_DS);
        sent_len = sock_sendmsg(clientsocket, &msg, send_message_len);//skb->len-8);
        set_fs(oldfs);
        printk(KERN_DEBUG "Message sent= %i\n", sent_len); // --- DEBUG OUTPUT ---
        
        kfree(send_message_body);
        // free the initial skb*/
        kfree_skb(skb);
	}
}

void send_message(char* send_message_body, size_t send_message_len)
{
    size_t sent_len = 0;
    
    //struct sk_buff *skb = NULL;
    //unsigned short * port;
    struct msghdr msg;
    struct iovec iov;
    mm_segment_t oldfs;
    struct sockaddr_in to;
    //char* send_message_body;
    //int send_message_len;
    
    // generate answer message
    memset(&to,0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = in_aton("127.0.0.1");  
    //port = (unsigned short *)skb->data;
    to.sin_port = *port;
    memset(&msg,0,sizeof(msg));
    msg.msg_name = &to;
    msg.msg_namelen = sizeof(to);
    
    // send the message back
    //send_message_body = (char*)kmalloc(RECV_SIZE, GFP_KERNEL);
    //send_message_len = message_handler(skb->data+8, send_message_body);
    iov.iov_base = send_message_body;
    iov.iov_len  = send_message_len;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    
    // adjust memory boundaries
    oldfs = get_fs();
    set_fs(KERNEL_DS);
    sent_len = sock_sendmsg(clientsocket, &msg, send_message_len);//skb->len-8);
    set_fs(oldfs);
    //printk(KERN_DEBUG "Message sent= %i\n", sent_len); // --- DEBUG OUTPUT ---
    
    //kfree(send_message_body);    
}

int server_init( void (*handler)(char *, size_t) )
{
	struct sockaddr_in server;
	int servererror;
	
	// socket to receive data
	if (sock_create(PF_INET, SOCK_DGRAM, IPPROTO_UDP, &udpsocket) < 0) {
		printk( KERN_ERR "server: Error creating udpsocket.n" );
		return -EIO;
	}
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons( (unsigned short)SERVER_PORT );
	servererror = udpsocket->ops->bind( udpsocket, (struct sockaddr *) &server, sizeof(server) );
	if (servererror) {
		sock_release(udpsocket);
		return -EIO;
	}
	udpsocket->sk->sk_data_ready = cb_data;
	
	// create work queue
    message_handler = handler;
	INIT_WORK(&wq_data.worker, recv_message);
	wq = create_singlethread_workqueue("moduleQueue"); 
	if (!wq){
		return -ENOMEM;
	}
	
	// socket to send data
	if (sock_create(PF_INET, SOCK_DGRAM, IPPROTO_UDP, &clientsocket) < 0) {
		printk( KERN_ERR "server: Error creating clientsocket.n" );
		return -EIO;
	}
	return 0;
}

void server_exit( void )
{
	if (udpsocket)
		sock_release(udpsocket);
	if (clientsocket)
		sock_release(clientsocket);

	if (wq) {
        flush_workqueue(wq);
        destroy_workqueue(wq);
	}
}


