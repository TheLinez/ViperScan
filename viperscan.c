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
#define VERSION "1.1.0"

int verbose = 0;
int ping_only = 0;
int scan_all_ports = 0;
int custom_ports_count = 0;
int custom_ports[100];

char global_target_ip[100];
int current_port_index = 0;
int total_ports_to_scan = 0;
int* ports_queue = NULL;

char output_filename[256] = "";
FILE* output_file = NULL;

pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;

void print_help(const char* prog_name) {
    printf("VIPERSCAN v%s\n\n", VERSION);
    printf("Usage:\n");
    printf("  %s <target> [start_port end_port] [options]\n", prog_name);
    printf("  %s -v\n\n", prog_name);
    printf("Options:\n");
    printf("  -help    Show this help message\n");
    printf("  -v       Verbose mode (shows closed ports too / tool version)\n");
    printf("  -sn      Ping Scan (Host discovery only)\n");
    printf("  -p-      Scan all 65535 ports\n");
    printf("  -p       Scan specific ports (e.g., -p 80,443)\n");
    printf("  -oN      Save scan results to a text file (e.g., -oN res.txt)\n\n");
}

void* worker_thread(void* arg) {
    int port;
    struct sockaddr_in server_addr;
    struct timeval timeout;

    timeout.tv_sec = 0;
    timeout.tv_usec = 500000;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    inet_pton(AF_INET, global_target_ip, &server_addr.sin_addr);

    while (1) {
        pthread_mutex_lock(&queue_mutex);
        if (current_port_index >= total_ports_to_scan) {
            pthread_mutex_unlock(&queue_mutex);
            break;
        }
        port = ports_queue[current_port_index++];
        pthread_mutex_unlock(&queue_mutex);

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        server_addr.sin_port = htons(port);

        if (verbose) {
            printf("[*] Checking port %d/TCP...\n", port);
        }

        if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
            struct servent *se = getservbyport(htons(port), "tcp");
            
            pthread_mutex_lock(&file_mutex);
            printf("[+] Port %d/TCP is OPEN   --> Service: %s\n", 
                   port, se ? se->s_name : "unknown");
            
            if (output_file != NULL) {
                fprintf(output_file, "[+] Port %d/TCP is OPEN   --> Service: %s\n", 
                        port, se ? se->s_name : "unknown");
                fflush(output_file);
            }
            pthread_mutex_unlock(&file_mutex);
        } else {
            if (verbose) {
                printf("[-] Port %d/TCP is closed\n", port);
            }
        }
        close(sock);
    }
    return NULL;
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
        } else if (strcmp(argv[i], "-oN") == 0 && i + 1 < argc) {
            strncpy(output_filename, argv[i + 1], sizeof(output_filename) - 1);
            i++;
        }
    }

    if (strlen(output_filename) > 0) {
        output_file = fopen(output_filename, "w");
        if (output_file == NULL) {
            printf("[!] Error: Could not create output file %s\n", output_filename);
            return 1;
        }
        fprintf(output_file, "# VIPERSCAN v%s Scan Report\n", VERSION);
        fprintf(output_file, "# Target: %s\n\n", target);
    }

    printf("--------------------------------------------------\n");
    printf("   🐍 VIPERSCAN v%s\n", VERSION);
    printf("--------------------------------------------------\n");

    struct hostent *he;
    if ((he = gethostbyname(target)) == NULL) {
        herror("[!] DNS Error");
        if (output_file != NULL) fclose(output_file);
        return 1;
    }
    struct in_addr **addr_list = (struct in_addr **)he->h_addr_list;
    strcpy(global_target_ip, inet_ntoa(**addr_list));

    printf("[*] Target Host: %s (%s)\n", target, global_target_ip);
    if (verbose) printf("[*] Verbose mode: ENABLED\n");
    if (output_file != NULL) printf("[*] Output file: %s\n", output_filename);

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
        inet_pton(AF_INET, global_target_ip, &server_addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
            printf("[+] Host %s seems to be ALIVE.\n", global_target_ip);
            if (output_file != NULL) fprintf(output_file, "[+] Host %s seems to be ALIVE.\n", global_target_ip);
        } else {
            printf("[-] Host %s could not be verified via standard TCP ports.\n", global_target_ip);
            if (output_file != NULL) fprintf(output_file, "[-] Host %s could not be verified.\n", global_target_ip);
        }
        close(sock);
    } else {
        if (custom_ports_count > 0) {
            total_ports_to_scan = custom_ports_count;
            ports_queue = (int*)malloc(total_ports_to_scan * sizeof(int));
            for (int i = 0; i < custom_ports_count; i++) {
                ports_queue[i] = custom_ports[i];
            }
            printf("[*] Scanning specific ports: %d custom ports\n", total_ports_to_scan);
        } else {
            total_ports_to_scan = end_port - start_port + 1;
            ports_queue = (int*)malloc(total_ports_to_scan * sizeof(int));
            for (int i = 0; i < total_ports_to_scan; i++) {
                ports_queue[i] = start_port + i;
            }
            printf("[*] Scanning range: %d - %d\n", start_port, end_port);
        }
        printf("--------------------------------------------------\n");

        pthread_t threads[MAX_THREADS];
        for (int i = 0; i < MAX_THREADS; i++) {
            pthread_create(&threads[i], NULL, worker_thread, NULL);
        }

        for (int i = 0; i < MAX_THREADS; i++) {
            pthread_join(threads[i], NULL);
        }

        free(ports_queue);
    }

    gettimeofday(&end_time, NULL);
    double elapsed_time = (end_time.tv_sec - start_time.tv_sec) + 
                          (end_time.tv_usec - start_time.tv_usec) / 1000000.0;

    printf("--------------------------------------------------\n");
    printf("[*] Scan complete. Time elapsed: %.2f seconds.\n", elapsed_time);
    
    if (output_file != NULL) {
        fprintf(output_file, "\n# Scan complete. Time elapsed: %.2f seconds.\n", elapsed_time);
        fclose(output_file);
    }
    
    return 0;
}
