/**
 * Printing help message
 */

// #include "ipk-scan.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>



#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netdb.h>

#include <pcap.h>


#include <iostream>
#include <string>
#include <queue>

#include <unistd.h>


#define CORRECT 0
#define ERROR_ADDR 197
#define ERROR_PORT_OF 198
#define ERROR_PORT 199
#define ERROR_PARAMS 200

struct tcp_pseudo_header {

  u_int32_t source_address;
  u_int32_t destination_address;
  u_int8_t  reserved;
  u_int8_t  protocol;
  u_int16_t tcp_segment_length;
};


using namespace std;


// https://www.tenouk.com/Module43a.html

static void usage() {
  printf("Usage: ./ipk-scan -pu <port-ranges> -pt <port-ranges> [<domain-name> | <IP-address>]\n"
          "Feedreader of rss and atom with TLS support\n\n"
            "-pu   to specify feedfile\n"
            "-pt   to specify cert file\n\n"

            "<port-ranges>   to specify cert directory\n"
            "<domain-name>   to extract author from feed/rss message\n"
            "<IP-address>   to extract url\n" );
  exit(CORRECT);
}

static void raise_err(int err_code){

  switch (err_code) {
    case ERROR_PARAMS:
      fprintf(stderr, "ERROR : PARAMS : Unknown or missing parameter use -help\n");
      exit(err_code);
    case ERROR_PORT:
      fprintf(stderr, "ERROR : PARAMS : Given port number is not integer\n");
      exit(err_code);
    case ERROR_PORT_OF:
      fprintf(stderr, "ERROR : PARAMS : Given port number out of range\n");
      exit(err_code);
    case ERROR_ADDR:
      fprintf(stderr, "ERROR : PARAMS : Given ip address or hostname is invalid\n");
      exit(err_code);
    default:
        exit(1);
  }
}

/*
  https://stackoverflow.com/questions/4654636/how-to-determine-if-a-string-is-a-number-with-c
*/
void is_number(const string& s)
{
    string::const_iterator it = s.begin();
    while (it != s.end() && isdigit(*it)) ++it;
    if(!s.empty() && it == s.end()){
      ;
    } else raise_err(ERROR_PORT);
}

void port_in_range(int port){
  if(!(port < 0 || port > 65535)){
    raise_err(ERROR_PORT_OF);
  }
}


unsigned short CheckSum(unsigned short *buffer, int size)
{
    unsigned long cksum=0;
    while(size >1)
    {
        cksum+=*buffer++;
        size -=sizeof(unsigned short);
    }
    if(size)
        cksum += *(unsigned char*)buffer;

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (unsigned short)(~cksum);
}


//https://github.com/chinmay29/PortScanner
unsigned short generate_tcp_checksum(iphdr *ip_header, tcphdr *tcp_header, u_int16_t length)
{

    tcp_pseudo_header pseudo_header;
    int packet_size;
    char *pseudo_packet=NULL;
    unsigned short check_sum;

    memset(&pseudo_header,0,sizeof(tcp_pseudo_header));

    //Populate the header with IP values
    //Source and destination addresses
    pseudo_header.source_address = ip_header->saddr;
    pseudo_header.destination_address = ip_header->daddr;

    //Reserved bits all 0
    pseudo_header.reserved = 0;

    //protocol is TCP and length
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_segment_length = htons(length);

    packet_size = sizeof(tcp_pseudo_header) + length;


    //Calculate the checksum on combined packet
    pseudo_packet = new char [packet_size];
    memcpy(pseudo_packet, (char*)&pseudo_header, sizeof(tcp_pseudo_header));
    //finished adding IPv4 pseudo header, now add the actual tcp header
    memcpy(pseudo_packet + sizeof(tcp_pseudo_header), tcp_header, length);


    check_sum=CheckSum((unsigned short*)pseudo_packet, packet_size);
    delete[] pseudo_packet;
    return check_sum;

}


queue<int> parse_ports(string ports){

  queue<int> s_ports;

  // case of ports range
  if(ports.find("-") != string::npos){
    ;
  }
  // comma separated values
  else if(ports.find(",") != string::npos){
    string port_numb = "";

    for (unsigned int i = 0; i < ports.size(); i++){
      if(ports[i] == ','){
        s_ports.push(stoi(port_numb));
        port_numb.clear();
      }
      else {
        port_numb += ports[i];
      }
    }
  }
  else{
    is_number(ports);
    s_ports.push(stoi(ports));
  }
  // single port specified

  s_ports.push(2);

  return s_ports;
}


string HostToIp(const string& host) {
    hostent* hostname = gethostbyname(host.c_str());

    if(hostname) return string(inet_ntoa(**(in_addr**)hostname->h_addr_list));
    return {};
}

void create_udp_packet(udphdr * udp, int s_port, int dest_port){

  udp->source = s_port; /* source port */
  udp->dest = dest_port; /* destination port */
  udp->len = htons(sizeof(udphdr)); /* udp length */
  udp->uh_sum = 0; /* udp checksum */
}


int main(int argc, char **argv) {

  string domain_name = "", ip_addr = "", tcp_ports = "", udp_ports = "", host_name = "";
  queue<int> s_tcp_ports;
  queue<int> s_udp_ports;

  int s_socket;
  char *buffer = new char[8192]();

  int one = 1;
  const int *val = &one;

  char *dev, errbuffer[100];  /*  Interface name and error buffer for pcap  */
  char pcap_filter[100];
  pcap_t *handle;
  struct bpf_program fp;
  bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
  struct pcap_pkthdr header;
	const u_char *packet;

  memset(buffer, 0, 8192);

  struct iphdr *ip = (struct iphdr *) buffer;
  struct tcphdr *tcp = (struct tcphdr *) (buffer + sizeof(struct iphdr));
  struct sockaddr_in sin, din;
  struct hostent *dest;

  struct udphdr *udp = (struct udphdr *) (buffer + sizeof(struct iphdr));

  if(argc == 6){
    if(string(argv[1]) == "-pu"){
      udp_ports = string(argv[2]);
      if(string(argv[3]) == "-pt"){
        tcp_ports = string(argv[4]);
        domain_name = string(argv[5]);
      }
      else raise_err(ERROR_PARAMS);
    }
    else if (string(argv[1]) == "-pt"){
      tcp_ports = string(argv[2]);
      if(string(argv[3]) == "-pu"){
        udp_ports = string(argv[4]);
        domain_name = string(argv[5]);
      }
      else raise_err(ERROR_PARAMS);
    }
    else raise_err(ERROR_PARAMS);

  }
  else if(argc == 2){
    if(string(argv[--argc]) == "-help"){
      usage();
    }
    else raise_err(ERROR_PARAMS);
  }
  else raise_err(ERROR_PARAMS);


/* ***************************************************************************/

  s_tcp_ports = parse_ports(tcp_ports);
  s_udp_ports = parse_ports(udp_ports);

  // Creating TCP socket with RAW schranka
  if((s_socket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0 ){
    perror("ERROR : An error occured in function socket()");
    exit(-1);
  }

  int port_numb = s_tcp_ports.front();

  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = inet_addr("192.168.0.10");  //new
  sin.sin_port = htons(60358);

  // sin.sin_addr.s_addr = inet_addr("127.0.0.1");
  //new
  din.sin_family = AF_INET;
  din.sin_addr.s_addr = inet_addr("147.229.9.23");
  din.sin_port = htons(80);
  //


  // Source address
  inet_pton(AF_INET, "192.168.0.10", &(sin.sin_addr.s_addr));

  if ((dest = gethostbyname(domain_name.c_str())) == NULL){
    perror("ERROR : An error occured in function gethostbyname()");
    exit(-1);
  }

  memcpy(&sin.sin_addr, dest->h_addr, dest->h_length);

  /*  Trying to convert IP addr to hostname and viceversa  */
  char str[100];
  string stri;
  struct sockaddr_in test_sin;
  test_sin.sin_family = AF_INET;

  if((inet_pton(AF_INET, domain_name.c_str(), &(test_sin.sin_addr))) != 1){
      if((inet_ntop(AF_INET, &(din.sin_addr), str, 100)) == NULL){
        raise_err(ERROR_ADDR);
      }
       stri = HostToIp(domain_name);  /*  Get IP from hostname  */
  }
  else {  /* Get hostname from IP */
    if (getnameinfo((struct sockaddr*)&test_sin, sizeof(test_sin), str, sizeof(str), NULL, 0, NI_NAMEREQD)){
      perror("ERROR : HOSTNAME : Could not resolve hostname in getnameinfo()");
      exit(-1);
    }
    stri = string(str);
  }

  /*  Determine device - interface name */
	dev = pcap_lookupdev(errbuffer);

  if (dev == NULL) {
		fprintf(stderr, "ERROR : INTERFACE : Couldn't find default device: %s\n", errbuffer);
		return(-1);
	}
  printf("%s\n", dev);

  if (pcap_lookupnet(dev, &net, &mask, errbuffer) == -1) {
			fprintf(stderr, "ERROR : Couldn't get netmask for device %s: %s\n", dev, errbuffer);
			net = 0;
			mask = 0;
	}

  /*  Open device for sniffing  */
  // set 1 -> 0 for non-promiscuous
  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuffer);
  if(handle == NULL){
    fprintf(stderr, "ERROR : SNIFFING : An error occured in function pcap_open_live(). Couldn't open device: %s %s\n", dev, errbuffer);
		return(-1);
  }

  if(pcap_datalink(handle) != DLT_EN10MB) {
    fprintf(stderr, "ERROR : INTERFACE : Device %s doesn't provide Ethernet headers - not supported\n", dev);
    return(-1);
  }

  string t_fp = "port " + to_string(port_numb);
  strcpy(pcap_filter, t_fp.c_str());
  char fltr[] = "port 80";

  if (pcap_compile(handle, &fp, fltr, 0, net) == -1) {
			fprintf(stderr, "ERROR : Couldn't parse filter %s: %s\n", pcap_filter, pcap_geterr(handle));
			return(-1);
  }
  if (pcap_setfilter(handle, &fp) == -1) {
  		 fprintf(stderr, "Couldn't install filter %s: %s\n", pcap_filter, pcap_geterr(handle));
  		 return(-1);
  }

  ip->ihl = 5;
  ip->version = 4;
  ip->tos = 16;
  ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
  ip->id = htons(54321);
  ip->frag_off = 0;
  ip->ttl = 64;
  ip->protocol = 6; // TCP
  ip->check = 0; // Done by kernel
  ip->saddr = inet_addr("192.168.0.10");
  ip->daddr = inet_addr("147.229.9.23");
  // memcpy(&ip->iph_destip, dest->h_addr, dest->h_length);
  //  int csum = in_cksum((unsigned short *) buffer, (sizeof(struct iphdr) + sizeof(struct tcphdr)));//CheckSum((unsigned short *) buffer, (sizeof(struct iphdr) + sizeof(struct tcphdr)));
  tcp->source = htons(60358);
  tcp->dest = htons(80);
  tcp->seq = 0;
  tcp->ack_seq = 0;
  tcp->doff = 5;
  tcp->syn = 1;
  tcp->ack = 0;
  tcp->window = htons(29200);
  tcp->check = 0;
  tcp->rst = 0;
  tcp->urg_ptr = 0;
  tcp->th_seq = htonl(23456);
  tcp->check = 0;
  // IP checksum calculation
  // tcp->check = in_cksum((unsigned short *) buffer, (sizeof(struct tcphdr)));
  tcp->check = generate_tcp_checksum(ip, tcp, (ip->tot_len-(ip->ihl*4)));


  if(setsockopt(s_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0){
    perror("ERROR : An error occured in setsockopt()");
    exit(-1);
  }

  cout << endl << "Interesting ports on " << domain_name << " (" << stri <<"):" << endl;
  cout << "PORT   " << "  STATE" << endl;

  for (int i = 0; i < 1; i++) {
    if(sendto(s_socket, buffer, ip->tot_len, 0,(struct sockaddr *)&din, sizeof(din)) < 0){
      perror("ERROR : An error occured in sendto()");
      exit(-1);
    }
    else {
      printf("OK\n");
      // cout << port_numb << "/tcp";
      /* Grab a packet */
  		 packet = pcap_next(handle, &header);

  		/* Print its length */
  		 printf("Jacked a packet with length of [%d]\n", header.len);
  		/* And close the session */
      cout << endl;
    }
    sleep(1);
  }

  close(s_socket);
/*
  port_numb = udp_ports.front();
  int s = 80;
  int b = 60358;

  ip->ihl = 5;
  ip->version = 4;
  ip->tos = 16;
  ip->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr);
  ip->id = htons(54321);
  ip->frag_off = 0;
  ip->ttl = 64;
  ip->protocol = 6; // TCP
  ip->check = 0; // Done by kernel
  ip->saddr = inet_addr("192.168.0.10");
  ip->daddr = inet_addr("147.229.9.23");

  create_udp_packet(udp, b, s);

  if((s_socket = socket(PF_INET, SOCK_RAW, IPPROTO_UDP)) < 0 ){
    perror("ERROR : An error occured in function socket()");
    exit(-1);
  }

  if(setsockopt(s_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0){
    perror("ERROR : An error occured in setsockopt()");
    exit(-1);
  }

  if(sendto(s_socket, buffer, ip->tot_len, 0,(struct sockaddr *)&sin, sizeof(sin)) < 0){
    perror("ERROR : An error occured in sendto()");
    exit(-1);
  }
  else{
    printf("OK\n");
  }

  sleep(1);
  close(s_socket);*/


  pcap_close(handle);
  return 0;
}