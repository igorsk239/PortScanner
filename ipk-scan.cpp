/**
 * Printing help message
 */

// #include "ipk-scan.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>

#include <iostream>
#include <string>
#include <queue>


#define CORRECT 0
#define ERROR_ADDR 197
#define ERROR_PORT_OF 198
#define ERROR_PORT 199
#define ERROR_PARAMS 200

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

unsigned short csum(unsigned short *buf, int len){
  unsigned long sum;

  for(sum=0; len>0; len--){
    sum += *buf++;
  }
  sum = (sum >> 16) + (sum &0xffff);
  sum += (sum >> 16);
  return (unsigned short)(~sum);
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


int main(int argc, char **argv) {

  string domain_name = "", ip_addr = "", tcp_ports = "", udp_ports = "", host_name = "";
  queue<int> s_tcp_ports;
  queue<int> s_udp_ports;

  int s_socket;
  char buffer[8192];

  int one = 1;
  const int *val = &one;

  memset(buffer, 0, 8192);

  struct iphdr *ip = (struct iphdr *) buffer;
  struct tcphdr *tcp = (struct tcphdr *) (buffer + sizeof(struct iphdr));
  struct sockaddr_in sin, din;
  struct hostent *dest;

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

  s_tcp_ports = parse_ports(tcp_ports);
  s_udp_ports = parse_ports(udp_ports);

  // Creating TCP socket with RAW schranka
  if((s_socket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0 ){
    perror("ERROR : An error occured in function socket()");
    exit(-1);
  }

  int port_numb = s_tcp_ports.front();

  sin.sin_family = AF_INET;
  sin.sin_port = htons(port_numb);

  // sin.sin_addr.s_addr = inet_addr("127.0.0.1");

  // Source address
  inet_pton(AF_INET, "100.10.0.10", &(sin.sin_addr.s_addr));

  if ((dest = gethostbyname(domain_name.c_str())) == NULL){
    perror("ERROR : An error occured in function gethostbyname()");
    exit(-1);
  }

  memcpy(&sin.sin_addr, dest->h_addr, dest->h_length);

  // Trying to convert IP addr to hostname and viceversa
  char str[100];
  string stri;
  struct sockaddr_in test_sin;
  test_sin.sin_family = AF_INET;

  if((inet_pton(AF_INET, domain_name.c_str(), &(test_sin.sin_addr))) != 1){
      if((inet_ntop(AF_INET, &(din.sin_addr), str, 100)) == NULL){
        raise_err(ERROR_ADDR);
      }
       stri = HostToIp(domain_name);
  }
  else {
    if (getnameinfo((struct sockaddr*)&test_sin, sizeof(test_sin), str, sizeof(str), NULL, 0, NI_NAMEREQD)){
      perror("ERROR : HOSTNAME : Could not resolve hostname in getnameinfo()");
      exit(-1);
    }
    stri = string(str);
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
  ip->saddr = inet_addr("100.10.0.10");
  ip->daddr = inet_addr("192.168.0.11");
  // memcpy(&ip->iph_destip, dest->h_addr, dest->h_length);

  tcp->source = htons(2234);
  tcp->dest = htons(port_numb);
  tcp->seq = htonl(1);
  tcp->ack_seq = random();
  tcp->doff = 5;
  tcp->syn = 1;
  tcp->ack = 0;
  tcp->window = htons(32767);
  tcp->check = 0; // Done by kernel
  tcp->rst = 0;
  tcp->urg_ptr = 0;
  // IP checksum calculation
  ip->check = csum((unsigned short *) buffer, (sizeof(struct iphdr) + sizeof(struct tcphdr)));

  if(setsockopt(s_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0){
    perror("ERROR : An error occured in setsockopt()");
    exit(-1);
  }

  cout << endl << "Interesting ports on " << domain_name << " (" << "stri" <<"):" << endl;
  cout << "PORT   " << "  STATE" << endl;

  for (int i = 0; i < 20; i++) {
    if(sendto(s_socket, buffer, ip->tot_len, 0,(struct sockaddr *)&sin, sizeof(sin)) < 0){
      perror("ERROR : An error occured in sendto()");
      exit(-1);
    }
    else {
      printf("OK\n");
    }
    sleep(2);
  }

  close(s_socket);
  return 0;
}