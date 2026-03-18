#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>

#define MAX_BANNER_LEN 1024
#define DEFAULT_TIMEOUT 1000

pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    char ip[16];
    int start_port;
    int end_port;
    int timeout_ms;
    int thread_idx;
    int num_threads;
} scan_args_t;

// Function to set socket to non-blocking
int set_nonblock(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

// Function to scan a single port with timeout
void scan_port(const char *ip, int port, int timeout_ms) {
    int sock;
    struct sockaddr_in target;
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    set_nonblock(sock);

    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    inet_pton(AF_INET, ip, &target.sin_addr);

    // Attempt to connect
    int res = connect(sock, (struct sockaddr *)&target, sizeof(target));
    if (res < 0 && errno != EINPROGRESS) {
        close(sock);
        return;
    }

    if (res == 0) {
        // Connected immediately
    } else {
        fd_set fdset;
        struct timeval tv;
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);
        
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        res = select(sock + 1, NULL, &fdset, NULL, &tv);
        if (res <= 0) { // Timeout or error
            close(sock);
            return;
        } else {
            int so_error;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
            if (so_error != 0) {
                close(sock);
                return;
            }
        }
    }

    // Port is open! 
    // Set socket back to blocking with receive timeout for banner grabbing
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);

    struct timeval recv_tv;
    recv_tv.tv_sec = timeout_ms / 1000;
    recv_tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&recv_tv, sizeof(recv_tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&recv_tv, sizeof(recv_tv));

    // Banner grabbing
    char banner[MAX_BANNER_LEN];
    memset(banner, 0, MAX_BANNER_LEN);

    // Send generic HTTP payload to trigger standard services to respond
    const char *payload = "HEAD / HTTP/1.0\r\n\r\n";
    send(sock, payload, strlen(payload), 0);
    
    // Read response
    int bytes = recv(sock, banner, MAX_BANNER_LEN - 1, 0);
    
    pthread_mutex_lock(&print_mutex);
    printf("[+] Port %d is OPEN\n", port);
    if (bytes > 0) {
        // Clean up non-printable characters for safe output
        for (int i = 0; i < bytes; i++) {
            if (banner[i] == '\r' || banner[i] == '\n') banner[i] = ' ';
            else if (banner[i] < 32 || banner[i] > 126) banner[i] = '.';
        }
        printf("    Banner: %s\n", banner);
    }
    pthread_mutex_unlock(&print_mutex);

    close(sock);
}

// Thread worker function
void* worker_thread(void *arg) {
    scan_args_t *args = (scan_args_t *)arg;
    for (int port = args->start_port + args->thread_idx; port <= args->end_port; port += args->num_threads) {
        scan_port(args->ip, port, args->timeout_ms);
    }
    pthread_exit(NULL);
}

void print_usage(char *prog) {
    printf("Usage: %s -t <IP> -p <start_port-end_port> [-c threads] [-w timeout_ms]\n", prog);
    printf("\nOptions:\n");
    printf("  -t  Target IP address\n");
    printf("  -p  Port range (e.g., 1-1024)\n");
    printf("  -c  Number of concurrent threads (default: 1)\n");
    printf("  -w  Socket timeout in ms (default: %d)\n", DEFAULT_TIMEOUT);
}

int main(int argc, char *argv[]) {
    char target_ip[16] = {0};
    int start_port = 0, end_port = 0;
    int num_threads = 1;
    int timeout_ms = DEFAULT_TIMEOUT;

    int opt;
    // Parse arguments
    while ((opt = getopt(argc, argv, "t:p:c:w:h")) != -1) {
        switch (opt) {
            case 't':
                strncpy(target_ip, optarg, 15);
                break;
            case 'p':
                if (sscanf(optarg, "%d-%d", &start_port, &end_port) != 2) {
                    fprintf(stderr, "Invalid port range format.\n");
                    return EXIT_FAILURE;
                }
                break;
            case 'c':
                num_threads = atoi(optarg);
                break;
            case 'w':
                timeout_ms = atoi(optarg);
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (strlen(target_ip) == 0 || start_port <= 0 || end_port <= 0 || start_port > end_port) {
        fprintf(stderr, "Error: Missing or invalid required arguments.\n\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (num_threads <= 0) num_threads = 1;

    printf("Starting scan on %s (Ports: %d-%d) with %d threads.\n", target_ip, start_port, end_port, num_threads);

    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    scan_args_t *args = malloc(num_threads * sizeof(scan_args_t));

    // Spawn threads
    for (int i = 0; i < num_threads; i++) {
        strncpy(args[i].ip, target_ip, 15);
        args[i].start_port = start_port;
        args[i].end_port = end_port;
        args[i].timeout_ms = timeout_ms;
        args[i].thread_idx = i;
        args[i].num_threads = num_threads;

        if (pthread_create(&threads[i], NULL, worker_thread, &args[i]) != 0) {
            perror("Failed to create thread");
            free(threads);
            free(args);
            return EXIT_FAILURE;
        }
    }

    // Join threads
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    free(threads);
    free(args);
    printf("Scan complete.\n");

    return EXIT_SUCCESS;
}
