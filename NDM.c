#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <netdb.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <errno.h>


uint16_t checksum(void *b, int32_t len) // copied from habr
{
    uint16_t *buf = (uint16_t *)b;
    uint32_t sum = 0;
    uint16_t result;

    for (; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(uint8_t*)buf;
    
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <IP>\n", argv[0]);
        return 1;
    }

    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); // socket for sending ICMP
    if (fd == -1)
    {
        perror("Can't create ICMP socket");
        return 1;
    }

    int packet_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); // socket for recieving ethernet frame
    if (packet_fd == -1) {
        fprintf(stderr, "Can't create packet socket");
        close(fd);
        return 1;
    }

    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    if (setsockopt(packet_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv))) {
        fprintf(stderr, "setsockopt timeout failed");
        close(fd);
        close(packet_fd);
        return 1;
    }

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    // man: inet_pton - convert IPv4 and IPv6 addresses from text to binary form
    // The sin_port and sin_addr members are stored in network byte order.
    if (inet_pton(AF_INET, argv[1], &dest.sin_addr) != 1) {
        fprintf(stderr, "Invalid IP address");
        close(fd);
        close(packet_fd);
        return 1;
    }

    char send_buf[64] = {0}; 
    struct icmphdr *icmph = (struct icmphdr*)send_buf;
    icmph->type = ICMP_ECHO;
    icmph->code = 0;
    icmph->checksum = 0;
    icmph->un.echo.sequence = htons(1);
    icmph->un.echo.id = htons(getpid());
    icmph->checksum = checksum(icmph, sizeof(*icmph));
    
    if (sendto(fd, send_buf, sizeof(*icmph), 0, (struct sockaddr *)&dest, sizeof(dest)) == -1) {
        fprintf(stderr, "sendto failed");
        close(fd);
        close(packet_fd);
        return 1;
    }

    unsigned char recv_buf[2048];
    int reply_received = 0;
    
    while (!reply_received) {
        ssize_t recv_len = recv(packet_fd, recv_buf, sizeof(recv_buf), 0);
        if (recv_len < 0) {
            fprintf(stderr, "recvfrom failed");
            close(fd);
            close(packet_fd);
            return 1;
        }

        if (recv_len < (ssize_t)(sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr))) {
            continue;
        }

        struct ethhdr *eth = (struct ethhdr*)recv_buf;

        if (ntohs(eth->h_proto) != ETH_P_IP) { // IP packet?
            continue;
        }

        struct iphdr *ip = (struct iphdr*)(recv_buf + sizeof(struct ethhdr));
        
        if (ip->protocol != IPPROTO_ICMP) { // ICMP packet?
            continue;
        }

        size_t ip_header_len = ip->ihl * 4;
        if (ip_header_len < sizeof(struct iphdr)) {
            continue;
        }

        struct icmphdr *icmp_recv = (struct icmphdr*)(recv_buf + sizeof(struct ethhdr) + ip_header_len);
        
        if (icmp_recv->type == ICMP_ECHOREPLY && icmp_recv->code == 0) {
            if (ntohs(icmp_recv->un.echo.id) == getpid() && 
                ntohs(icmp_recv->un.echo.sequence) == 1) {
                unsigned short saved_checksum = icmp_recv->checksum;
                icmp_recv->checksum = 0;
                unsigned short calculated = checksum(icmp_recv, sizeof(struct icmphdr));
                
                if (saved_checksum == calculated) {
                    printf("Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                           eth->h_source[0], eth->h_source[1], eth->h_source[2],
                           eth->h_source[3], eth->h_source[4], eth->h_source[5]);
                    reply_received = 1;
                } else {
                    fprintf(stderr, "Invalid ICMP checksum\n");
                }
            }
        }
    }

    close(fd);
    close(packet_fd);
    return 0;
}