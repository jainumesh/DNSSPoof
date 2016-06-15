#include "dnsdetect.h"

/*Using  some global variables for easy communication :)*/
/*Bad practice but...............*/
char * spdevice_name;
char * filename;
char * _string;
char * _expressions;
pcap_t* phndlr;
char errbuf[BUFFSIZE];

int global_counter = 0;                    
int buffer_dns_id[PACKET_HISTORY];    
char ip_to_check[64];    
char ip_dup[MAX_SIZE];
char store_ip[PACKET_HISTORY][16];        

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
    we only support '-i' , '-r' for this exercise :D */
    
    while(argc>counter_i)
    {
        if(argv[counter_i][0] == '-'){
            
            switch(argv[counter_i][1]){
                case 'i':
                    spdevice_name = argv[counter_i+1];
                    break;
                case 'r':
                    filename = argv[counter_i+1];
                    read_from_file = 1;
                    break;
                default:
                    fprintf(stdout,"UNSUPPORTED INPUT \n");
                    fprintf(stdout, "USAGE  Directions:\ndnsdetect [-i interface] [-r tracefile] [-s string]  expression\n");
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
			phndlr = pcap_fopen_offline(filep,errbuf);
			if(NULL == phndlr){
				fprintf(stdout,"failed to capture with error [%s]\n", errbuf);
				return ERR_RETURN;
			}
		}
    } else{   

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
    sprintf(filter, "src port 53");
    if(ERR_RETURN == pcap_compile(phndlr,fp,filter,0,net)){
        fprintf(stdout,"Couldn't parse filter %s: %s\n", _expressions, pcap_geterr(phndlr));
        return ERR_RETURN;
    }

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

void get_dns_request(struct sniff_dnsq *dns_query, char *request){
  unsigned int i, j, k;
  char *curr = dns_query->query;
  unsigned int size;
  size = (unsigned int)curr[0];
  j=0;
  i=1;
 
  while(size > 0){
    for(k=0; k<size; k++){
      request[j++] = curr[i+k];
    }
    request[j++]='.';
    i+=size;
    size = curr[i++];
  }
  request[--j] = '\0';
}
int is_duplicate(int num_dns)
{
    int m;
    int flag = 0;

    for (m=0 ; m < global_counter; m++)
    {
        if ((buffer_dns_id[m] == num_dns))
        {	
			//fprintf(stdout,"ipdup = [%s]\n",ip_dup);
			//fprintf(stdout,"store_ip = [%s]\n",store_ip[m]);
            flag = 1;
            strcat(ip_dup, store_ip[m]);
            strcat(ip_dup, ", ");
        }
        
    }

    if (flag)
    {    
        strcat(ip_dup, ip_to_check);
        strcat(ip_dup, ", ");
    }
    return flag;
}

int fetch_duplicate(u_char *qr)
{
    int i = 0;
    int flag1 = 0;
    int flag2 = 0;
    int flag_no_dns_packet = 0;
    int response = 0;
    char buf_temp[8];
    do
    {
        if ((qr[i] == 0x00))
            flag1 = 1;
        else
            flag1 = 0;    

        if ((qr[i+1] == 0x04))
            flag2 = 1;
        else
            flag2 = 0;

        response = flag1 * flag2;
        i = i + 1;
        if (i == 256){
            response = 1;    
            flag_no_dns_packet = 1;
        }
    }while (response == 0);

    i = i + 1;
    
    if (flag_no_dns_packet == 0)
    {    
        memset(ip_to_check,0,16);
        sprintf (buf_temp, "%d", qr[i]);
        strcat (ip_to_check, buf_temp);
        strcat (ip_to_check, "." );
        sprintf (buf_temp, "%d", qr[i+1]);
        strcat (ip_to_check, buf_temp);
        strcat (ip_to_check, "." );
        sprintf (buf_temp, "%d", qr[i+2]);
        strcat (ip_to_check, buf_temp);
        strcat (ip_to_check, "." );
        sprintf (buf_temp, "%d", qr[i+3]);
        strcat (ip_to_check, buf_temp);
        return 1;
    }
    else
        return 0;
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
    char ip_src[16],ip_dst[16];
    struct sniff_dnsa dns_a;
    struct sniff_dnsq dns_q;
    u_int16_t port,dnsId;
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
    if(dns_q.query[0]<=0 ||dns_q.query[0]>255)
		return;
    get_dns_request(&dns_q,domain_name);
    dnsId = (dns->id[1]<<8)+dns->id[0];
       if (fetch_duplicate((u_char *)dns))
        {
            if (is_duplicate(dnsId)){
				time_t time_of_attack = time(NULL);
				fprintf(stdout,"\n");
				fprintf(stdout,ctime(&time_of_attack));
				fprintf(stdout,"DNS poisoning attempt\n");
				fprintf(stdout,"TXID %u Request %s\n",dnsId,domain_name);
				fprintf(stdout,"Answers [%s]\n",ip_dup);
                memset(ip_dup,0,MAX_SIZE);    
            }
            buffer_dns_id[global_counter] = (dnsId);
            strcpy(store_ip[global_counter], (ip_to_check));
    
            if (global_counter < PACKET_HISTORY)
                global_counter++;
            else
                memset(store_ip,0,16*PACKET_HISTORY); 
      
    }
    
return;
}
