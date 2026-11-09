#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>

#define MAX_THREADS 100
#define VERSION "1.0.0"

int verbose = 0;
int ping_only = 0;
int scan_all_ports = 0;
int custom_ports_count = 0;
int custom_ports[100];

typedef struct {
    char target_ip[100];
    int port;
} scan_task_t;

void print_help(const char* prog_name) {
    printf("VIPERSCAN v%s - Custom Network Scanner\n\n", VERSION);
    printf("Usage:\n");
    printf("  %s <target> [start_port end_port] [options]\n", prog_name);
    printf("  %s -v\n\n", prog_name);
    printf("Options:\n");
    printf("  -help    Show this help message\n");
    printf("  -v       If target specified: Verbose mode (shows closed ports too)\n");
    printf("           If used alone: Show tool version\n");
    printf("  -sn      Ping Scan (Host discovery only)\n");
    printf("  -p-      Scan all 65535 ports\n");
    printf("  -p       Scan specific ports (e.g., -p 80,443)\n\n");
    printf("Examples:\n");
    printf("  vscan 127.0.0.1 1 1024\n");
    printf("  vscan google.com -p 80,443 -v\n");
}

void* scan_port(void* arg) {
    scan_task_t* task = (scan_task_t*)arg;
    int sock;
    struct sockaddr_in server_addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        free(task);
        pthread_exit(NULL);
    }

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(task->port);
    inet_pton(AF_INET, task->target_ip, &server_addr.sin_addr);

    if (verbose) {
        printf("[*] Checking port %d/TCP...\n", task->port);
    }

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
        struct servent *se = getservbyport(htons(task->port), "tcp");
        printf("[+] Port %d/TCP is OPEN   --> Service: %s\n", 
               task->port, se ? se->s_name : "unknown");
    } else {
        if (verbose) {
            printf("[-] Port %d/TCP is closed\n", task->port);
        }
    }

    close(sock);
    free(task);
    pthread_exit(NULL);
}

int run_port_scan(const char* target_ip, int start, int end) {
    pthread_t threads[MAX_THREADS];
    int thread_count = 0;

    for (int port = start; port <= end; port++) {
        scan_task_t* task = (scan_task_t*)malloc(sizeof(scan_task_t));
        strcpy(task->target_ip, target_ip);
        task->port = port;

        if (pthread_create(&threads[thread_count], NULL, scan_port, (void*)task) == 0) {
            thread_count++;
        }

        if (thread_count >= MAX_THREADS) {
            for (int i = 0; i < thread_count; i++) {
                pthread_join(threads[i], NULL);
            }
            thread_count = 0;
        }
    }

    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    return 0;
}

int main(int argc, char* argv[]) {
    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);

    if (argc < 2) {
        print_help("vscan");
        return 1;
    }

    if (argc == 2 && strcmp(argv[1], "-v") == 0) {
        printf("VIPERSCAN version %s\n", VERSION);
        return 0;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-help") == 0) {
            print_help("vscan");
            return 0;
        }
    }

    char* target = argv[1];
    if (target[0] == '-') {
        printf("[!] Error: Target host must be specified first.\n");
        print_help("vscan");
        return 1;
    }

    int start_port = 1;
    int end_port = 1000;
    int options_start_index = 2;

    if (argc >= 4 && atoi(argv[2]) > 0 && atoi(argv[3]) > 0) {
        start_port = atoi(argv[2]);
        end_port = atoi(argv[3]);
        options_start_index = 4;
    }

    for (int i = options_start_index; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-sn") == 0) {
            ping_only = 1;
        } else if (strcmp(argv[i], "-p-") == 0) {
            scan_all_ports = 1;
            start_port = 1;
            end_port = 65535;
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            char* token = strtok(argv[i + 1], ",");
            while (token != NULL && custom_ports_count < 100) {
                custom_ports[custom_ports_count++] = atoi(token);
                token = strtok(NULL, ",");
            }
            i++;
        }
    }

    printf("--------------------------------------------------\n");
    printf("   🐍 VIPERSCAN v%s — Custom Network Scanner\n", VERSION);
    printf("--------------------------------------------------\n");

    struct hostent *he;
    char target_ip[100];
    if ((he = gethostbyname(target)) == NULL) {
        herror("[!] DNS Error");
        return 1;
    }
    struct in_addr **addr_list = (struct in_addr **)he->h_addr_list;
    strcpy(target_ip, inet_ntoa(*addr_list[0]));

    printf("[*] Target Host: %s (%s)\n", target, target_ip);
    if (verbose) printf("[*] Verbose mode: ENABLED\n");

    if (ping_only) {
        printf("[*] Mode: Ping Scan (-sn)\n");
        printf("--------------------------------------------------\n");
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in server_addr;
        struct timeval timeout = {1, 0};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(80);
        inet_pton(AF_INET, target_ip, &server_addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0 || verbose) {
            printf("[+] Host %s seems to be ALIVE.\n", target_ip);
        } else {
            printf("[-] Host %s could not be reached via standard ports.\n", target_ip);
        }
        close(sock);
    } else if (custom_ports_count > 0) {
        printf("[*] Scanning specific ports: %d custom ports\n", custom_ports_count);
        printf("--------------------------------------------------\n");
        pthread_t threads[MAX_THREADS];
        int thread_count = 0;

        for (int i = 0; i < custom_ports_count; i++) {
            scan_task_t* task = (scan_task_t*)malloc(sizeof(scan_task_t));
            strcpy(task->target_ip, target_ip);
            task->port = custom_ports[i];

            if (pthread_create(&threads[thread_count], NULL, scan_port, (void*)task) == 0) {
                thread_count++;
            }

            if (thread_count >= MAX_THREADS) {
                for (int j = 0; j < thread_count; j++) {
                    pthread_join(threads[j], NULL);
                }
                thread_count = 0;
            }
        }
        for (int i = 0; i < thread_count; i++) {
            pthread_join(threads[i], NULL);
        }
    } else {
        printf("[*] Scanning range: %d - %d\n", start_port, end_port);
        printf("--------------------------------------------------\n");
        run_port_scan(target_ip, start_port, end_port);
    }

    gettimeofday(&end_time, NULL);
    double elapsed_time = (end_time.tv_sec - start_time.tv_sec) + 
                          (end_time.tv_usec - start_time.tv_usec) / 1000000.0;

    printf("--------------------------------------------------\n");
    printf("[*] Scan complete. Time elapsed: %.2f seconds.\n", elapsed_time);
    return 0;
}
