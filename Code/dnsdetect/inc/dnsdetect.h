#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#define BUFFSIZE 1600 //Max packet size
//#define PCAPSIZE 65535 // MAX no. of packets expected
//#define MAX_SIZE 16777216 //Maxx 1 GB RAM.
#define ERR_RETURN -1
#define SIZE_ETHERNET 14
#define MSS 1420
#define PACKET_HISTORY 1000
#define MAX_SIZE 256
/* Ethernet addresses are 6 bytes */
//#define ETHER_ADDR_LEN    6
    struct _ip_record{
        char ip_address[16];
        char domain_name[256];
    }ip_record;

    /* Ethernet header */
     struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
    };

    /* IP header */
    struct sniff_ip {
        u_char ip_vhl;        /* version << 4 | header length >> 2 */
        u_char ip_tos;        /* type of service */
        u_short ip_len;        /* total length */
        u_short ip_id;        /* identification */
        u_short ip_off;        /* fragment offset field */
    #define IP_RF 0x8000        /* reserved fragment flag */
    #define IP_DF 0x4000        /* dont fragment flag */
    #define IP_MF 0x2000        /* more fragments flag */
    #define IP_OFFMASK 0x1fff    /* mask for fragmenting bits */
        u_char ip_ttl;        /* time to live */
        u_char ip_p;        /* protocol */
        u_short ip_sum;        /* checksum */
        struct in_addr ip_src,ip_dst; /* source and dest address */
    };
    #define IP_HL(ip)        (((ip)->ip_vhl) & 0x0f)
    #define IP_V(ip)        (((ip)->ip_vhl) >> 4)

    /* TCP header */
    typedef u_int tcp_seq;

     struct sniff_udp {
        uint16_t        sport;    /* source port */
        uint16_t        dport;    /* destination port */
        uint16_t        udp_length;
        uint16_t        udp_sum;    /* checksum */
    };
     struct sniff_dnsq{
        char *query;
        char query_type[2];
        char query_class[2];     
    };
     struct sniff_dnsa{
        char * name;
        char ans_type[2];
        char ans_class[2];
        char ttl[4];
        char Rdata_len[2];
        char* Rdata;
    };
     struct sniff_dns {
      char id[2];
      char flags[2];
      char qdcount[2];
      char ancount[2];
      char nscount[2];
      char arcount[2];
    };

void got_packet(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet);
int open_pcap(void);
int compile_filter(struct bpf_program *fp,bpf_u_int32 net);
int set_filter(struct bpf_program *fp);
void convert_payload_to_string(const u_char* payload,char* payload_printable,int payload_size);
void get_raw_ip(u_int32_t raw_ip, char* ip);
void get_dns_request(struct sniff_dnsq *dns_query, char *request);
void send_dns_answer(char* ip, u_int16_t port,int packlen);





