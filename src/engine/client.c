#include "client.h"

int client_sock;
struct sockaddr_in  receiveclient_socket;
struct sockaddr_in  sendclient_socket;

int client_sendlen, client_receivelen;
int received = 0;
	

/** @brief Client initialization
 *
 *  @param process_port Userspace process port.
 *  @param module_port Kernel module port.
 *  @return Socket.
 */
int client_init( int process_port, int module_port )
{
	int ret = 0;
    
    printf("Client init\n"); // --- DEBUG OUTPUT ---

	// Create the UDP socket
	if ((client_sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		perror("socket");
		return -1;
	}
    
    // process address
	memset(&receiveclient_socket, 0, sizeof(receiveclient_socket));  
	receiveclient_socket.sin_family = AF_INET; 
	receiveclient_socket.sin_addr.s_addr = htonl(INADDR_ANY);
	receiveclient_socket.sin_port = htons(process_port);
    
    int yes = 1;
    if ( setsockopt(client_sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 ){
        perror("setsockopt");
        return -1;
    }
    
	client_receivelen = sizeof(receiveclient_socket);
	if (bind(client_sock, (struct sockaddr *) &receiveclient_socket, client_receivelen) < 0) {
		perror("bind");
		return -1;		
	}
    
	// module address
	memset(&sendclient_socket, 0, sizeof(sendclient_socket));
	sendclient_socket.sin_family = AF_INET;
	sendclient_socket.sin_addr.s_addr = inet_addr("127.0.0.1");
	sendclient_socket.sin_port = htons(module_port);
    
	return client_sock;
}

int send_to_module( char* message, int size )
{
    int sent_size;
    int msg_size = (size < ROP_PROTO_DATASIZE) ? size: ROP_PROTO_DATASIZE;
    
	if ( (sent_size = sendto(client_sock, message, msg_size, 0, (struct sockaddr *) &sendclient_socket, sizeof(sendclient_socket))) != msg_size){
		perror("sendto");
		return -1;
	}
    //printf("Sent message size= %i\n", sent_size); // --- DEBUG OUTPUT ---
	return 0;
}

int recv_from_module( char* message, int size )
{
    int received_size;
    
	if ((received_size = recvfrom(client_sock, message, ROP_PROTO_DATASIZE, 0, NULL, NULL)) < 0){
		perror("recvfrom");
		return -1;
	}
    //printf("Received message size= %i\n", received_size); // --- DEBUG OUTPUT ---
	return received_size;
}


