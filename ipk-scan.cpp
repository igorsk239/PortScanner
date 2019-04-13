/**
 * Printing help message
 */

// #include "ipk-scan.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <signal.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <net/if.h>

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

#define IP_HL(ip)               (((ip)->ihl) & 0x0f)

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
  printf("Usage: ./ipk-scan {-i <interface>} -pu <port-ranges> -pt <port-ranges> [<domain-name> | <IP-address>]\n"
          "Port scanner using TCP SYN scanning or UDP port scanning\n\n"
            "-i    interface name\n"
            "-pu   to specify feedfile\n"
            "-pt   to specify cert file\n\n"

            "<interface>     \n"
            "<port-ranges>   to specify cert directory\n"
            "<domain-name>   to extract author from feed/rss message\n"
            "<IP-address>    to extract url\n" );
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

    for (unsigned int i = 0; i <= ports.size(); i++){
      if(ports[i] == ','){
        s_ports.push(stoi(port_numb));
        port_numb.clear();
      }
      else {
        if (ports[i] == '\0'){  /*  End of ports stream  */
          s_ports.push(stoi(port_numb));
          break;
        }
        port_numb += ports[i];

      }
    }
  }
  // single port specified
  else {
    is_number(ports);
    s_ports.push(stoi(ports));
  }


  return s_ports;
}


string HostToIp(const string& host) {
    hostent* hostname = gethostbyname(host.c_str());

    if(hostname) return string(inet_ntoa(**(in_addr**)hostname->h_addr_list));
    return {};
}

string get_interface_ip(string interface_name){

  char *ip_address = new char[15](); /* Maximum length  */
  int t_socket;
  struct ifreq ifr;


  //  string interface_name = ;

  /*  AF_INET - interface IPv4  */
  /*  Creating socket for it */
  t_socket = socket(AF_INET, SOCK_DGRAM, 0);

  /*AF_INET - define IPv4 Address type.*/
  ifr.ifr_addr.sa_family = AF_INET;

  memcpy(ifr.ifr_name, interface_name.c_str(), IFNAMSIZ-1);

  ioctl(t_socket, SIOCGIFADDR, &ifr);
  /*closing fd*/
  close(t_socket);

  /*Extract IP Address*/
  strcpy(ip_address,inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

  return ip_address;
}

// void create_udp_packet(udphdr * udp, int s_port, int dest_port){
//
//   udp->source = s_port; /* source port */
//   udp->dest = dest_port; /* destination port */
//   udp->len = htons(sizeof(udphdr)); /* udp length */
//   udp->uh_sum = 0; /* udp checksum */
// }


void create_tcp_header(struct tcphdr *tcp, struct iphdr *ip, int dest_port){
  tcp->source = htons(60358);
  tcp->dest = htons(dest_port);
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
  // TCP checksum calculation
  // tcp->check = in_cksum((unsigned short *) buffer, (sizeof(struct tcphdr)));
  tcp->check = generate_tcp_checksum(ip, tcp, (ip->tot_len-(ip->ihl*4)));
}

void create_ip_header(struct tcphdr *tcp ,struct iphdr *ip, string dest_ip, string source_ip){

  ip->ihl = 5;
  ip->version = 4;
  ip->tos = 16;
  ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
  ip->id = htons(54321);
  ip->frag_off = 0;
  ip->ttl = 64;
  ip->protocol = 6; // TCP
  ip->check = 0; // Done by kernel
  ip->saddr = inet_addr(source_ip.c_str());
  ip->daddr = inet_addr(dest_ip.c_str());
}

int pcap_set_new_filter(pcap_t *handle, bpf_program fp, bpf_u_int32 mask, bpf_u_int32 net, int port_numb){

  char pcap_filter[100];
  string t_fp = "port " + to_string(port_numb);
  strcpy(pcap_filter, t_fp.c_str());
  // char fltr[] = "port 60358"; /*  Source port of our application  */

  if (pcap_compile(handle, &fp, pcap_filter, 0, net) == -1) {
			fprintf(stderr, "ERROR : Couldn't parse filter %s: %s\n", pcap_filter, pcap_geterr(handle));
			return(-1);
  }
  if (pcap_setfilter(handle, &fp) == -1) {
  		 fprintf(stderr, "Couldn't install filter %s: %s\n", pcap_filter, pcap_geterr(handle));
  		 return(-1);
  }
  return 0;
}

// void handle_packets(u_char *useless, const struct pcap_pkthdr* header, const u_char* packet){
//   const struct iphdr *ip_sniff;
//   ip_sniff = (struct iphdr*)(packet + 14);
//   int ip_size = IP_HL(ip_sniff)*4;
//   if(ip_sniff->protocol == IPPROTO_TCP){
//     printf("YE\n");
//   }
//
// }

int main(int argc, char **argv) {

  string domain_name = "", ip_addr = "", tcp_ports = "", udp_ports = "", host_name = "";
  queue<int> q_tcp_ports;
  queue<int> s_udp_ports;

  int s_socket = 0;
  char *buffer = new char[8192]();
  char *interface;
  bool interface_set = false;

  int one = 1;
  const int *val = &one;

  char *dev, errbuffer[100];  /*  Interface name and error buffer for pcap  */
  // char pcap_filter[100];
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


/********************* Argument parsing ***************************************/
  if(argc <= 8){
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
    else if (string(argv[1]) == "-i"){
      interface = argv[2];
      interface_set = true;

      if(string(argv[3]) == "-pu"){
        udp_ports = string(argv[4]);

        if(string(argv[5]) == "-pt"){
          tcp_ports = string(argv[6]);
          domain_name = string(argv[7]);
        }
        else raise_err(ERROR_PARAMS);
      }
      else if(string(argv[3]) == "-pt"){
        tcp_ports = string(argv[4]);

        if(string(argv[5]) == "-pu"){
          udp_ports = string(argv[6]);
          domain_name = string(argv[7]);
        }
        else raise_err(ERROR_PARAMS);
      }
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

  /*  Parsed tcp and udp ports in queues  */
  q_tcp_ports = parse_ports(tcp_ports);
  s_udp_ports = parse_ports(udp_ports);

/*************  Create pcap filter and prepare filtering  *********************/

  /*  Determine device - interface name */
	dev = pcap_lookupdev(errbuffer);
  /* Interface specified by user with -i */
  if(interface_set) dev = interface;

  string source_ip = get_interface_ip(dev);

  if (dev == NULL) {
		fprintf(stderr, "ERROR : INTERFACE : Couldn't find default device: %s\n", errbuffer);
		return(-1);
	}

  if (pcap_lookupnet(dev, &net, &mask, errbuffer) == -1) {
			fprintf(stderr, "ERROR : Couldn't get netmask for device %s: %s\n", dev, errbuffer);
			net = 0;
			mask = 0;
      return(-1);
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

  // string t_fp = "port " + to_string(port_numb);
  // strcpy(pcap_filter, t_fp.c_str());

  pcap_set_new_filter(handle, fp, mask, net, 60358);
  // char fltr[] = "port 60358"; /*  Source port of our application  */
  //
  // if (pcap_compile(handle, &fp, fltr, 0, net) == -1) {
	// 		fprintf(stderr, "ERROR : Couldn't parse filter %s: %s\n", fltr, pcap_geterr(handle));
	// 		return(-1);
  // }
  // if (pcap_setfilter(handle, &fp) == -1) {
  // 		 fprintf(stderr, "Couldn't install filter %s: %s\n", fltr, pcap_geterr(handle));
  // 		 return(-1);
  // }


/********************** Resolve hostname/IP ***********************************/

  /*  Trying to convert IP addr to hostname and viceversa  */
  char str[100];
  string stri;
  string dest_ip = domain_name;
  struct sockaddr_in test_sin;
  test_sin.sin_family = AF_INET;

  if((inet_pton(AF_INET, domain_name.c_str(), &(test_sin.sin_addr))) != 1){
      if((inet_ntop(AF_INET, &(din.sin_addr), str, 100)) == NULL){
        raise_err(ERROR_ADDR);
      }
       stri = HostToIp(domain_name);  /*  Get IP from hostname  */
       dest_ip = stri;  /*  Store IP for further use of creating IP packet  */
  }
  else {  /* Get hostname from IP */
    if (getnameinfo((struct sockaddr*)&test_sin, sizeof(test_sin), str, sizeof(str), NULL, 0, NI_NAMEREQD)){
      perror("ERROR : HOSTNAME : Could not resolve hostname in getnameinfo()");
      exit(-1);
    }
    stri = string(str);
  }
  // cout << "HERER " <<  dest_ip << endl;


  // inet_pton(AF_INET, "192.168.0.10", &(sin.sin_addr.s_addr));
  /*  Verify given IP-address */
  if ((dest = gethostbyname(domain_name.c_str())) == NULL){
    perror("ERROR : An error occured in function gethostbyname()");
    exit(-1);
  }
  // memcpy(&sin.sin_addr, dest->h_addr, dest->h_length);

  cout << endl << "Interesting ports on " << domain_name << " (" << stri <<"):" << endl;
  cout << "PORT   " << "    STATE" << endl;


/********************** Create TCP socket *************************************/

/*  Number of ports to sniff  */
int ports_sniff = q_tcp_ports.size();

for (int i = 0; i < ports_sniff; i++) {
  // Creating TCP socket with RAW schranka
  if((s_socket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0 ){
    perror("ERROR : An error occured in function socket()");
    exit(-1);
  }

  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = inet_addr(source_ip.c_str());  //new
  sin.sin_port = htons(60358);

  // sin.sin_addr.s_addr = inet_addr("127.0.0.1");
  //new
  din.sin_family = AF_INET;
  din.sin_addr.s_addr = inet_addr(dest_ip.c_str());
  din.sin_port = htons(q_tcp_ports.front());

  create_ip_header(tcp, ip, dest_ip, source_ip);
  create_tcp_header(tcp, ip, q_tcp_ports.front());

  q_tcp_ports.pop(); /* Remove used port  */

  if(setsockopt(s_socket, IPPROTO_IP, IP_HDRINCL, dev, sizeof(dev)) < 0){
    perror("ERROR : An error occured in setsockopt()");
    exit(-1);
  }

  // create_tcp_packet(s_socket, dest_ip, domain_name, tcp, ip);

  if(sendto(s_socket, buffer, ip->tot_len, 0,(struct sockaddr *)&din, sizeof(din)) < 0){
    perror("ERROR : An error occured in sendto()");
    exit(-1);
  }
  else {

    /* Grab a packet and start sniffing information */
		 packet = pcap_next(handle, &header); //my

    //  pcap_loop(handle, 100, handle_packets, NULL);
    //  printf("Jacked a packet with length of [%d]\n", header.len);
     packet = pcap_next(handle, &header); //received

		/* Print its length */
     const struct iphdr *ip_sniff;
     ip_sniff = (struct iphdr*)(packet + 14);
     int ip_size = IP_HL(ip_sniff)*4;
     if(ip_sniff->protocol == IPPROTO_TCP){

       const struct tcphdr *tcp_sniff;
       tcp_sniff = (struct tcphdr*)(packet + 14 + ip_size);


       if(tcp_sniff->ack && tcp_sniff->syn) {
         cout << ntohs(tcp_sniff->source) << "/tcp  " << "open" << endl;
        //  pcap_set_new_filter(handle, fp, mask, net, q_tcp_ports.front());
         for(int i = 0; i < 7; i++) pcap_next(handle, &header); /* Filter unwanted */

       }
       else if (tcp_sniff->ack && tcp_sniff->rst) {
         cout << ntohs(tcp_sniff->source) << "/tcp  " << "closed" << endl;
       }
       else {
         printf("NO %d %d %d %d \n",tcp_sniff->ack, tcp_sniff->syn, tcp_sniff->fin, tcp_sniff->rst );
       }
     }
     else {printf("NO\n" );}
   }
  //  sleep(1);
   close(s_socket);
 }

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

  /* And close the session */
  pcap_close(handle);
  return 0;
}