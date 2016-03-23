#include "sniffer.h"

pcap_t *handle;
char *dev;
char errbuf[PCAP_ERRBUF_SIZE];

unsigned char* payload;
int payload_size = 0;

unsigned int ip_source_addr = 0;
unsigned int ip_dest_addr = 0;
unsigned short source_port = 0;
unsigned short dest_port = 0;

struct iphdr ip_hdr;
struct tcphdr * tcp_hdr;
struct udphdr * udp_hdr;

int process_tcp_pkt( const u_char * raw_tcp_part, int remaining_len, struct iphdr * hdr_ip, int size_ip )
{
	//PRINT_DEBUG << "tcp packet, remaining len: " <<remaining_len << endl;
	if( remaining_len < (int)sizeof(struct tcphdr ) ) {
		//PRINT_DEBUG << "partial_fill_chunk_tcp: remaining_len < sizeof(struct tcphdr )" << endl;
		return 0;
	}

	struct tcphdr * hdr_tcp = (struct tcphdr * )( raw_tcp_part );
	int size_tcp = hdr_tcp->doff * 4;
	
	//PRINT_DEBUG << "size_tcp: " <<size_tcp << endl;
	
	if ( size_tcp < 20 ) {
		//PRINT_DEBUG << "partial_fill_chunk_tcp: Invalid TCP header length: " << size_tcp << " bytes, less than 20 bytes" << endl;
		return 0;
	}

	tcp_hdr = hdr_tcp;
	///ip_saddr = inet_ntoa(*(struct in_addr * )&hdr_ip->saddr);
	///ip_daddr = inet_ntoa(*(struct in_addr * )&hdr_ip->daddr);
	source_port = ntohs(hdr_tcp->source);
	dest_port = ntohs(hdr_tcp->dest);
	
	payload = (unsigned char *)(raw_tcp_part + size_tcp);
	payload_size = remaining_len - size_tcp;
	
	//PRINT_DEBUG << "real payload size: " << strlen((const char *)payload) << endl;
	//PRINT_DEBUG << "now the real payload size: " << remaining_len - size_tcp  << endl;
	//PRINT_DEBUG << "payload: " << payload << endl << "raw_tcp_part: " << (unsigned char*)(raw_tcp_part+size_tcp)<< endl;
	//PRINT_DEBUG << "raw_tcp_part: " << (unsigned char*)(raw_tcp_part) << endl;

	return 1;
}

int process_udp_pkt( const u_char * raw_udp_part, int remaining_len, struct iphdr * hdr_ip, int size_ip  )
{
	if( remaining_len < (int)sizeof(struct udphdr ) ) {
		//PRINT_DEBUG << "partial_fill_chunk_udp: remaining_len < sizeof(struct tcphdr )" << endl;
		return 0;
	}

	struct udphdr * hdr_udp = (struct udphdr * )( raw_udp_part );
	int size_udp = sizeof(struct udphdr);
    
    udp_hdr = hdr_udp;
    source_port = ntohs(hdr_udp->source);
	dest_port = ntohs(hdr_udp->dest);
    
    payload = (unsigned char *)(raw_udp_part + size_udp);
	payload_size = remaining_len - size_udp;

	return 1;
}


int process_ethernet_pkt( struct pcap_pkthdr * header, const u_char * raw_packet )
{
	int caplen = header->caplen; /* length of portion present from bpf  */
	int length = header->len;    /* length of this packet off the wire  */

	//PRINT_DEBUG << "captured eth packet, caplen: "<<caplen << " len: "<<length<<endl;

	if( caplen < length ) {
		//PRINT_DEBUG << "init_packet: caplen " << caplen << " is less than packet size " << length << endl;
		return 0;
	}

	if( caplen < 14 ) { 
		//PRINT_DEBUG << "init_packet: caplen " << caplen << " is less than header size, total packet size " << length << endl;
		return 0;
	}

	struct ether_header * hdr_ethernet = (struct ether_header*)( raw_packet );
	u_int16_t type = ntohs( hdr_ethernet->ether_type );
 
	if( type != ETHERTYPE_IP ) {
		//PRINT_DEBUG << "got packet with non-IPv4 header , type = " << type << endl;
		return 0;
	}

	struct iphdr * hdr_ip = (struct iphdr * )(raw_packet + sizeof(struct ether_header) );
	int size_ip = hdr_ip->ihl * 4;
	//PRINT_DEBUG << "ip header len: " << size_ip << endl;
    
    //printf("src= %d, dst= %d \n", *(struct in_addr * )&hdr_ip->saddr, *(struct in_addr * )&hdr_ip->daddr);
    ip_source_addr = ((struct in_addr *)&hdr_ip->saddr)->s_addr;
    ip_dest_addr = ((struct in_addr *)&hdr_ip->daddr)->s_addr;
    //inet_ntoa(*(struct in_addr * )&hdr_ip->saddr);

	if (size_ip < 20) {
		//PRINT_DEBUG << "init_packet: Invalid IP header length: " << size_ip << " bytes, less than 20 bytes" << endl;
		return 0;
	}

	//tcp packet has been received
	if( hdr_ip->protocol == 6 ) {
		return process_tcp_pkt( raw_packet + sizeof(struct ether_header) + size_ip, 
                                length - sizeof(struct ether_header) + size_ip, 
                                hdr_ip, size_ip );
		/*payload = (unsigned char *)(raw_packet + sizeof(ether_header) + size_ip);
		payload_size = length - sizeof(ether_header) + size_ip;
		return 0;*/		
	}
	//udp packet
	else if( hdr_ip->protocol == 17 ) {
		return process_udp_pkt( raw_packet + sizeof(struct ether_header) + size_ip, 
                                length - sizeof(struct ether_header) + size_ip, 
                                hdr_ip, size_ip );
		/*payload = (unsigned char *)(raw_packet + sizeof(ether_header) + size_ip);
		payload_size = length - sizeof(ether_header) + size_ip;
		return 0;*/
	}

	return 1;
}



int process_raw_pkt( struct pcap_pkthdr * header, const u_char * raw_packet )
{
	size_t caplen = header->caplen; /* length of portion present from bpf  */
	size_t length = header->len;    /* length of this packet off the wire  */

	if( caplen < length ) {
		//PRINT_DEBUG << "init_packet: caplen " << caplen << " is less than packet size " << length << endl;
		return 0;
	}

	struct iphdr * hdr_ip = (struct iphdr * )(raw_packet);
	int size_ip = hdr_ip->ihl * 4;

	if (size_ip < 20) {
		//PRINT_DEBUG << "init_packet: Invalid IP header length: " << size_ip << " bytes, less than 20 bytes" << endl;
		return 0;
	}

	if( hdr_ip->protocol == 6 ) {
		return process_tcp_pkt( raw_packet + size_ip, length - size_ip, hdr_ip, size_ip );
	}
	/*else if( hdr_ip->protocol == 17 ) {
		return process_udp_pkt( raw_packet + size_ip, length - size_ip, hdr_ip, size_ip );
	}*/
 
	return 0;
}

//-------------------------------------------------------------------------------------

void sniffer_init( char *dev )
{
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return;
	}
}

void sniffer_destroy()
{
    pcap_close(handle);
}

int sniffer_process_packet(unsigned char** payload_pointer, unsigned int* ip_address, unsigned short* port_number)
{
	struct pcap_pkthdr header;
	const u_char * packet = pcap_next( handle, &header );
	if( !packet )
		return 0;

	if( pcap_datalink(handle) == DLT_EN10MB ) {
		process_ethernet_pkt( &header, packet);
	}
	else if( pcap_datalink(handle) == DLT_RAW ) 
		process_raw_pkt( &header, packet );
	
    *payload_pointer = payload;
    *ip_address = ip_dest_addr;
    *port_number = dest_port;
    return payload_size;
}



