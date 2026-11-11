/* ============================================================
 *  ViperScan v1.2.0  (optimized build)
 *  - getaddrinfo() DNS
 *  - banner grabbing (2-phase)
 *  - multithreaded poll engine: workers x 512 sockets
 *  - atomic queue, /etc/services cache, RST-close (no TIME_WAIT)
 * ============================================================ */
#define _GNU_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdatomic.h>
#include <limits.h>
#include <errno.h>
#include <stdarg.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>

#define VERSION                   "1.2.0"
#define DEFAULT_PROBES            2048
#define MAX_PROBES                32768
#define PROBES_PER_WORKER         512
#define MAX_WORKERS               64
#define POLL_TICK_MS              2
#define WORKER_STACK              (256 * 1024)
#define DEFAULT_TIMEOUT_MS        500
#define DEFAULT_BANNER_TIMEOUT_MS 1200
#define TIMEOUT_MIN_MS            10
#define TIMEOUT_MAX_MS            60000
#define BANNER_MAX                256
#define BANNER_THREADS_MAX        64

/* ---------------- globals ---------------- */
static int verbose = 0;
static int ping_only = 0;
static int banner_grab = 1;
static int timeout_ms = DEFAULT_TIMEOUT_MS;
static int banner_timeout_ms = DEFAULT_BANNER_TIMEOUT_MS;
static int concurrency = DEFAULT_PROBES;

static const char *target_host = "";
static char global_target_ip[INET_ADDRSTRLEN] = "";

static int *ports_queue = NULL;
static int total_ports_to_scan = 0;
static atomic_int queue_pos = 0;
static atomic_int scanned_count = 0;
static atomic_int open_count = 0;
static atomic_int workers_done = 0;
static atomic_int banner_pos = 0;

static int *custom_ports = NULL;
static int custom_ports_count = 0;
static int custom_ports_cap = 0;

static char output_filename[256] = "";
static FILE *output_file = NULL;

static int *open_ports = NULL;
static int open_n = 0, open_cap = 0;

static char *svc_cache[65536];
static struct sockaddr_in tgt;
static uint64_t scan_t0 = 0;

static volatile sig_atomic_t stop_flag = 0;

static pthread_mutex_t io_mutex   = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t open_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ---------------- output ---------------- */
static void report(const char *fmt, ...) {
    va_list ap;
    pthread_mutex_lock(&io_mutex);
    va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    if (output_file) {
        va_start(ap, fmt); vfprintf(output_file, fmt, ap); va_end(ap);
        fflush(output_file);
    }
    pthread_mutex_unlock(&io_mutex);
}

static void verb(const char *fmt, ...) {
    if (!verbose) return;
    va_list ap;
    pthread_mutex_lock(&io_mutex);
    va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    pthread_mutex_unlock(&io_mutex);
}

static void on_sigint(int sig) { (void)sig; stop_flag = 1; }

static uint64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

/* ---------------- help ---------------- */
static void print_help(const char *prog) {
    printf("VIPERSCAN v%s - fast multithreaded TCP port scanner\n\n", VERSION);

    printf("USAGE:\n");
    printf("  %s <target> [start_port end_port] [options]\n", prog);
    printf("  %s <target> -p <list> [options]\n", prog);
    printf("  %s <target> -p- [options]\n", prog);
    printf("  %s <target> -sn\n", prog);
    printf("  %s -v | --version\n", prog);
    printf("  %s -help\n\n", prog);

    printf("TARGET:\n");
    printf("  IPv4 (192.168.1.1) or domain (example.com), resolved via getaddrinfo()\n");
    printf("  Target must always be the FIRST argument.\n\n");

    printf("PORT SELECTION:\n");
    printf("  (none)                 scan ports 1-1000 (default)\n");
    printf("  <start> <end>          positional range, e.g. 1 1024\n");
    printf("  -p <list>              ports/ranges: -p 22,80,443,8000-8100\n");
    printf("  -p-                    scan all 65535 ports\n");
    printf("  -sn                    ping scan only: probe 80/443/22\n");
    printf("  note: -p overrides -p- and the positional range\n\n");

    printf("SPEED & TIMEOUTS:\n");
    printf("  -t <num>               probes in flight (default %d, max %d)\n",
           DEFAULT_PROBES, MAX_PROBES);
    printf("                         spread over ceil(t/%d) workers, max %d threads\n",
           PROBES_PER_WORKER, MAX_WORKERS);
    printf("  --timeout <ms>         connect timeout, %d..%d ms (default %d)\n",
           TIMEOUT_MIN_MS, TIMEOUT_MAX_MS, DEFAULT_TIMEOUT_MS);
    printf("  --banner-timeout <ms>  banner read timeout, ms (default %d)\n",
           DEFAULT_BANNER_TIMEOUT_MS);
    printf("  --no-banner            skip the banner phase\n");
    printf("  throughput = probes / timeout  (e.g. 8192 / 0.15s = ~54000 ports/s)\n\n");

    printf("OUTPUT & INFO:\n");
    printf("  -v                     verbose: closed / filtered ports too (SLOW)\n");
    printf("  -oN <file>             save scan report to a text file\n");
    printf("  -h, -help, --help      show this help\n");
    printf("  -v (no target), --version   show version and exit\n\n");

    printf("BANNER GRABBING:\n");
    printf("  Runs as a second phase, only on ports found open.\n");
    printf("  Reads first bytes: SSH-2.0-OpenSSH_8.9p1, 220 vsFTPd...\n");
    printf("  On HTTP ports sends 'HEAD / HTTP/1.0' and extracts Server:.\n");
    printf("  TLS ports (443, 993, 995, 8443...) are skipped - handshake needed.\n\n");

    printf("EXAMPLES:\n");
    printf("  %s 192.168.1.1\n", prog);
    printf("      default scan, ports 1-1000\n");
    printf("  %s 192.168.1.1 -p- -t 8192 --timeout 150\n", prog);
    printf("      full LAN sweep, ~2 seconds\n");
    printf("  %s 192.168.1.1 -p- -t 16384 --timeout 100\n", prog);
    printf("      max aggression, own network only\n");
    printf("  %s example.com -p- -t 4096 --timeout 1000 -oN res.txt\n", prog);
    printf("      external host, no false 'closed'\n");
    printf("  %s example.com -p 22,80,443 --banner-timeout 2000\n", prog);
    printf("      banners of known ports\n");
    printf("  %s 192.168.1.1 -sn\n\n", prog);

    printf("NOTES:\n");
    printf("  * closed = RST received, filtered = timeout\n");
    printf("  * sockets are RST-closed (SO_LINGER 0) -> no TIME_WAIT buildup\n");
    printf("  * fd limit is raised automatically; if not: ulimit -n 65535\n");
    printf("  * do NOT use -v on fast scans, console I/O becomes the bottleneck\n");
    printf("  * low --timeout on remote hosts causes false 'filtered' results\n");
    printf("  * Ctrl+C stops the scan and still writes the report footer\n");
    printf("  * scan only hosts you own or are authorized to test\n\n");

    printf("EXIT CODES:\n");
    printf("  0  success   1  bad arguments / DNS failure / resource error\n");
}

/* ---------------- args helpers ---------------- */
static int parse_int(const char *s, int *out) {
    if (!s || !*s) return 0;
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || *end != '\0' || v < INT_MIN || v > INT_MAX) return 0;
    *out = (int)v;
    return 1;
}

static int cmp_int(const void *a, const void *b) {
    int x = *(const int *)a, y = *(const int *)b;
    return (x > y) - (x < y);
}

static int add_port(int port) {
    if (port < 1 || port > 65535) {
        fprintf(stderr, "[!] Invalid port: %d\n", port);
        return 0;
    }
    if (custom_ports_count == custom_ports_cap) {
        int ncap = custom_ports_cap ? custom_ports_cap * 2 : 64;
        int *tmp = realloc(custom_ports, (size_t)ncap * sizeof(int));
        if (!tmp) { perror("[!] realloc"); return 0; }
        custom_ports = tmp;
        custom_ports_cap = ncap;
    }
    custom_ports[custom_ports_count++] = port;
    return 1;
}

static int parse_ports(const char *spec) {
    char *copy = strdup(spec);
    if (!copy) { perror("[!] strdup"); return 0; }

    char *save = NULL;
    int ok = 1;
    for (char *tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        char *dash = strchr(tok, '-');
        if (dash) {
            *dash = '\0';
            int a, b;
            if (!parse_int(tok, &a) || !parse_int(dash + 1, &b) || a > b) {
                fprintf(stderr, "[!] Bad port range: %s-%s\n", tok, dash + 1);
                ok = 0; break;
            }
            for (int p = a; p <= b; p++) if (!add_port(p)) { ok = 0; break; }
            if (!ok) break;
        } else {
            int p;
            if (!parse_int(tok, &p)) {
                fprintf(stderr, "[!] Bad port: '%s'\n", tok);
                ok = 0; break;
            }
            if (!add_port(p)) { ok = 0; break; }
        }
    }
    free(copy);
    if (!ok || custom_ports_count == 0) return 0;

    qsort(custom_ports, (size_t)custom_ports_count, sizeof(int), cmp_int);
    int uniq = 1;
    for (int i = 1; i < custom_ports_count; i++)
        if (custom_ports[i] != custom_ports[uniq - 1])
            custom_ports[uniq++] = custom_ports[i];
    custom_ports_count = uniq;
    return 1;
}

/* ---------------- service cache ---------------- */
static void build_service_cache(void) {
    setservent(1);
    struct servent *se;
    while ((se = getservent()) != NULL) {
        if (!se->s_name || !se->s_proto) continue;
        if (strcmp(se->s_proto, "tcp") != 0) continue;
        int p = ntohs((uint16_t)se->s_port);
        if (p > 0 && p < 65536 && !svc_cache[p]) svc_cache[p] = strdup(se->s_name);
    }
    endservent();
}

static const char *svc(int port) {
    return (port > 0 && port < 65536 && svc_cache[port]) ? svc_cache[port] : "unknown";
}

static void free_service_cache(void) {
    for (int i = 0; i < 65536; i++) {
        free(svc_cache[i]);
        svc_cache[i] = NULL;
    }
}

/* ---------------- fd limit ---------------- */
static int tune_fd_limit(int want) {
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) return want;
    rlim_t need = (rlim_t)want + 64;
    if (rl.rlim_cur < need) {
        struct rlimit nr = rl;
        nr.rlim_cur = need;
        if (nr.rlim_max < need) nr.rlim_max = need;   /* нужен root */
        if (setrlimit(RLIMIT_NOFILE, &nr) == 0) rl = nr;
    }
    if (rl.rlim_cur != RLIM_INFINITY && need > rl.rlim_cur) {
        int cap = (rl.rlim_cur > 128) ? (int)rl.rlim_cur - 64 : 16;
        if (cap < 16) cap = 16;
        fprintf(stderr, "[!] fd limit: -t clamped to %d (try: ulimit -n 65535)\n", cap);
        return cap;
    }
    return want;
}

static void push_open(int port) {
    if (open_n == open_cap) {
        int nc = open_cap ? open_cap * 2 : 64;
        int *t = realloc(open_ports, (size_t)nc * sizeof(int));
        if (!t) return;
        open_ports = t; open_cap = nc;
    }
    open_ports[open_n++] = port;
}

/* ---------------- DNS ---------------- */
static int resolve_target(const char *host, char *ip_out, size_t ipsz) {
    struct addrinfo hints, *res = NULL, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    int rc = getaddrinfo(host, NULL, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "[!] DNS Error: %s: %s\n", host, gai_strerror(rc));
        return 0;
    }
    int found = 0, saw_v6 = 0;
    for (p = res; p; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)p->ai_addr;
            if (inet_ntop(AF_INET, &sa->sin_addr, ip_out, (socklen_t)ipsz)) { found = 1; break; }
        } else if (p->ai_family == AF_INET6) saw_v6 = 1;
    }
    freeaddrinfo(res);
    if (!found) {
        if (saw_v6)
            fprintf(stderr, "[!] %s resolves to IPv6 only (AAAA). IPv6 not supported yet.\n", host);
        else
            fprintf(stderr, "[!] No usable address found for %s\n", host);
    }
    return found;
}

/* ---------------- single connect (ping + banner phase) ---------------- */
/* 0 = open, -1 = closed(RST), -2 = filtered(timeout), -3 = other */
static int tcp_connect(int sock, const struct sockaddr *addr, socklen_t alen, int ms) {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) flags = 0;
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) return -3;

    int result = -3;
    int rc = connect(sock, addr, alen);
    if (rc == 0) {
        result = 0;
    } else if (errno == EINPROGRESS) {
        struct pollfd pfd;
        pfd.fd = sock; pfd.events = POLLOUT; pfd.revents = 0;
        rc = poll(&pfd, 1, ms);
        if (rc == 0) result = -2;
        else if (rc < 0) result = -3;
        else {
            int err = 0; socklen_t elen = sizeof(err);
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &elen) == -1) result = -3;
            else if (err == 0)            result = 0;
            else if (err == ECONNREFUSED) result = -1;
            else                          result = -3;
        }
    } else if (errno == ECONNREFUSED) {
        result = -1;
    }
    fcntl(sock, F_SETFL, flags);
    return result;
}

/* ---------------- banner grabbing ---------------- */
static int is_tls_port(int port) {
    switch (port) {
        case 443: case 465: case 636: case 989: case 990:
        case 992: case 993: case 995: case 5061: case 8443: return 1;
        default: return 0;
    }
}

static int is_http_port(int port) {
    switch (port) {
        case 80: case 81: case 3000: case 5000: case 7000:
        case 8000: case 8008: case 8080: case 8081: case 8888: return 1;
        default: return 0;
    }
}

static void copy_trim(char *dst, size_t dstsz, const char *src) {
    size_t i = 0;
    for (; src[i] && i < dstsz - 1; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '\r' || c == '\n') break;
        dst[i] = (c < 32 || c == 127) ? '.' : (char)c;
    }
    while (i > 0 && (dst[i - 1] == ' ' || dst[i - 1] == '\t')) i--;
    dst[i] = '\0';
}

static int recv_timeout(int sock, char *buf, size_t bufsz, int ms) {
    struct pollfd pfd;
    pfd.fd = sock; pfd.events = POLLIN; pfd.revents = 0;
    int rc = poll(&pfd, 1, ms);
    if (rc <= 0) return -1;
    ssize_t n = recv(sock, buf, bufsz - 1, 0);
    if (n <= 0) return -1;
    buf[n] = '\0';
    return (int)n;
}

static int grab_banner(int sock, int port, const char *host, char *out, size_t outsz) {
    out[0] = '\0';
    if (!banner_grab) return 0;
    if (is_tls_port(port)) return 0;

    char buf[2048];
    int n = recv_timeout(sock, buf, sizeof(buf), banner_timeout_ms);

    if (n <= 0 && is_http_port(port)) {
        char req[512];
        int rl = snprintf(req, sizeof(req),
                          "HEAD / HTTP/1.0\r\nHost: %s\r\n"
                          "User-Agent: ViperScan/%s\r\nAccept: */*\r\n\r\n",
                          host, VERSION);
        if (send(sock, req, (size_t)rl, MSG_NOSIGNAL) > 0)
            n = recv_timeout(sock, buf, sizeof(buf), banner_timeout_ms);
    }
    if (n <= 0) return 0;

    if (strncmp(buf, "HTTP/", 5) == 0) {
        char *s = buf;
        while ((s = strchr(s, '\n')) != NULL) {
            s++;
            if (strncasecmp(s, "Server:", 7) == 0) {
                s += 7;
                while (*s == ' ' || *s == '\t') s++;
                copy_trim(out, outsz, s);
                return out[0] != '\0';
            }
        }
    }
    copy_trim(out, outsz, buf);
    return out[0] != '\0';
}

/* ============================================================
 *  FAST ENGINE: workers x slots, non-blocking connect + poll
 * ============================================================ */
typedef struct {
    int      fd;
    int      port;
    uint64_t deadline;
} probe_t;

static void probe_close(probe_t *p) {
    if (p->fd >= 0) {
        struct linger lg;
        lg.l_onoff = 1; lg.l_linger = 0;      /* RST вместо FIN -> нет TIME_WAIT */
        setsockopt(p->fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
        close(p->fd);
        p->fd = -1;
    }
    p->port = 0;
    p->deadline = 0;
}

static void record_open(int port) {
    atomic_fetch_add_explicit(&open_count, 1, memory_order_relaxed);
    pthread_mutex_lock(&open_mutex);
    push_open(port);
    pthread_mutex_unlock(&open_mutex);
    report("[+] Port %5d/TCP OPEN  --> %s\n", port, svc(port));
}

static void *worker_thread(void *arg) {
    int batch = *(int *)arg;

    probe_t *slots = calloc((size_t)batch, sizeof(probe_t));
    struct pollfd *pfds = calloc((size_t)batch, sizeof(struct pollfd));
    int *map = calloc((size_t)batch, sizeof(int));
    if (!slots || !pfds || !map) {
        free(slots); free(pfds); free(map);
        atomic_fetch_add(&workers_done, 1);
        return NULL;
    }
    for (int i = 0; i < batch; i++) slots[i].fd = -1;

    int live = 0, pending = -1, drained = 0;

    for (;;) {
        if (stop_flag) break;

        /* 1. забиваем свободные слоты новыми портами */
        for (int i = 0; i < batch && live < batch; i++) {
            if (slots[i].fd >= 0) continue;

            int port;
            if (pending >= 0) {
                port = pending;
            } else {
                if (drained) break;
                int pos = atomic_fetch_add_explicit(&queue_pos, 1, memory_order_relaxed);
                if (pos >= total_ports_to_scan) { drained = 1; break; }
                port = ports_queue[pos];
            }

            int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (fd < 0) { pending = port; break; }   /* fd кончились -> повторим */
            pending = -1;

            int syncnt = 1;                          /* не даём ядру ретраить SYN */
            setsockopt(fd, IPPROTO_TCP, TCP_SYNCNT, &syncnt, sizeof syncnt);

            struct sockaddr_in a = tgt;
            a.sin_port = htons((uint16_t)port);

            uint64_t now = mono_ms();
            int rc = connect(fd, (struct sockaddr *)&a, sizeof a);

            if (rc == 0) {                           /* мгновенный коннект */
                atomic_fetch_add_explicit(&scanned_count, 1, memory_order_relaxed);
                slots[i].fd = fd; slots[i].port = port;
                record_open(port);
                probe_close(&slots[i]);
                continue;
            }
            if (errno != EINPROGRESS) {              /* RST / unreachable сразу */
                atomic_fetch_add_explicit(&scanned_count, 1, memory_order_relaxed);
                verb("[-] Port %5d/TCP closed\n", port);
                close(fd);
                continue;
            }

            slots[i].fd = fd;
            slots[i].port = port;
            slots[i].deadline = now + (uint64_t)timeout_ms;
            live++;
        }

        /* 2. всё? */
        if (live == 0 && pending < 0 && drained) break;
        if (live == 0) {
            struct timespec ts = {0, 1000000};       /* 1 ms, ждём fd */
            nanosleep(&ts, NULL);
            continue;
        }

        /* 3. один poll на всю пачку */
        int nf = 0;
        for (int i = 0; i < batch; i++) {
            if (slots[i].fd < 0) continue;
            pfds[nf].fd = slots[i].fd;
            pfds[nf].events = POLLOUT;
            pfds[nf].revents = 0;
            map[nf] = i;
            nf++;
        }
        int rc = poll(pfds, (nfds_t)nf, POLL_TICK_MS);
        uint64_t now = mono_ms();

        if (rc > 0) {
            for (int k = 0; k < nf; k++) {
                if (pfds[k].revents == 0) continue;
                int i = map[k];
                int err = 0; socklen_t el = sizeof(err);
                if (getsockopt(slots[i].fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0) err = errno;
                atomic_fetch_add_explicit(&scanned_count, 1, memory_order_relaxed);
                if (err == 0) record_open(slots[i].port);
                else verb("[-] Port %5d/TCP %s\n", slots[i].port,
                          err == ECONNREFUSED ? "closed" : "unreachable/error");
                probe_close(&slots[i]);
                live--;
            }
        }

        /* 4. таймауты */
        for (int i = 0; i < batch; i++) {
            if (slots[i].fd < 0) continue;
            if (slots[i].deadline > now) continue;
            atomic_fetch_add_explicit(&scanned_count, 1, memory_order_relaxed);
            verb("[-] Port %5d/TCP filtered (timeout)\n", slots[i].port);
            probe_close(&slots[i]);
            live--;
        }
    }

    for (int i = 0; i < batch; i++) probe_close(&slots[i]);
    free(slots); free(pfds); free(map);
    atomic_fetch_add(&workers_done, 1);
    return NULL;
}

static void run_scan(void) {
    memset(&tgt, 0, sizeof(tgt));
    tgt.sin_family = AF_INET;
    inet_pton(AF_INET, global_target_ip, &tgt.sin_addr);

    concurrency = tune_fd_limit(concurrency);

    int nthreads = (concurrency + PROBES_PER_WORKER - 1) / PROBES_PER_WORKER;
    if (nthreads < 1) nthreads = 1;
    if (nthreads > MAX_WORKERS) nthreads = MAX_WORKERS;
    int batch = (concurrency + nthreads - 1) / nthreads;
    if (batch < 1) batch = 1;

    printf("[*] Engine: %d workers x %d slots = %d probes in flight\n",
           nthreads, batch, nthreads * batch);
    printf("--------------------------------------------------\n");

    pthread_t *th = calloc((size_t)nthreads, sizeof(pthread_t));
    int *batches = calloc((size_t)nthreads, sizeof(int));
    if (!th || !batches) {
        perror("[!] calloc");
        free(th); free(batches);
        return;
    }

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, WORKER_STACK);

    scan_t0 = mono_ms();
    int created = 0;
    for (int i = 0; i < nthreads; i++) {
        batches[i] = batch;
        if (pthread_create(&th[i], &attr, worker_thread, &batches[i]) != 0) {
            perror("[!] pthread_create");
            break;
        }
        created++;
    }
    pthread_attr_destroy(&attr);

    if (created == 0) { free(th); free(batches); return; }

    int progress_shown = 0;
    while (atomic_load(&workers_done) < created && !stop_flag) {
        struct timespec ts = {0, 200 * 1000000};
        nanosleep(&ts, NULL);
        uint64_t now = mono_ms();
        double el = (double)(now - scan_t0) / 1000.0;
        int done = atomic_load(&scanned_count);
        fprintf(stderr, "\r[*] %d/%d | %.0f p/s | open: %d | tmo: %d ms   ",
                done, total_ports_to_scan, el > 0 ? done / el : 0.0,
                atomic_load(&open_count), timeout_ms);
        progress_shown = 1;
    }

    for (int i = 0; i < created; i++) pthread_join(th[i], NULL);
    if (progress_shown) fprintf(stderr, "\n");

    free(th);
    free(batches);
}

/* ---------------- banner phase ---------------- */
static void *banner_worker(void *arg) {
    (void)arg;
    for (;;) {
        if (stop_flag) break;
        int pos = atomic_fetch_add(&banner_pos, 1);
        if (pos >= open_n) break;
        int port = open_ports[pos];

        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;
        struct sockaddr_in a = tgt;
        a.sin_port = htons((uint16_t)port);
        if (tcp_connect(fd, (struct sockaddr *)&a, sizeof a, timeout_ms) == 0) {
            char banner[BANNER_MAX];
            if (grab_banner(fd, port, target_host, banner, sizeof banner) && banner[0])
                report("    | %5d/TCP banner: %s\n", port, banner);
        }
        close(fd);
    }
    return NULL;
}

static void banner_phase(void) {
    if (!banner_grab || open_n == 0 || stop_flag) return;
    qsort(open_ports, (size_t)open_n, sizeof(int), cmp_int);

    printf("--------------------------------------------------\n");
    printf("[*] Banner phase: %d open ports\n", open_n);

    int n = (open_n < BANNER_THREADS_MAX) ? open_n : BANNER_THREADS_MAX;
    pthread_t *th = calloc((size_t)n, sizeof(pthread_t));
    if (!th) return;
    int created = 0;
    for (int i = 0; i < n; i++) {
        if (pthread_create(&th[i], NULL, banner_worker, NULL) != 0) break;
        created++;
    }
    for (int i = 0; i < created; i++) pthread_join(th[i], NULL);
    free(th);
}

/* ---------------- ping scan ---------------- */
static void do_ping_scan(void) {
    static const int probe_ports[] = {80, 443, 22};
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, global_target_ip, &addr.sin_addr);

    int alive = 0;
    for (size_t i = 0; i < sizeof(probe_ports) / sizeof(probe_ports[0]); i++) {
        addr.sin_port = htons((uint16_t)probe_ports[i]);
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        int rc = tcp_connect(sock, (struct sockaddr *)&addr, sizeof addr, timeout_ms);
        close(sock);
        if (rc == 0) {
            report("[+] Host %s is ALIVE (port %d open).\n", global_target_ip, probe_ports[i]);
            alive = 1; break;
        }
        if (rc == -1) {
            report("[+] Host %s is ALIVE (port %d sent RST).\n", global_target_ip, probe_ports[i]);
            alive = 1; break;
        }
    }
    if (!alive)
        report("[-] Host %s did not answer on 80/443/22 (down or filtered).\n", global_target_ip);
}

/* ---------------- main ---------------- */
int main(int argc, char *argv[]) {
    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);

    if (argc < 2) { print_help("vscan"); return 1; }

    if (argc == 2 && (!strcmp(argv[1], "-v") || !strcmp(argv[1], "--version"))) {
        printf("VIPERSCAN version %s\n", VERSION);
        return 0;
    }
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-help") || !strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            print_help("vscan");
            return 0;
        }
    }

    const char *target = argv[1];
    if (target[0] == '-') {
        fprintf(stderr, "[!] Error: Target host must be specified first.\n");
        return 1;
    }
    target_host = target;

    int start_port = 1, end_port = 1000, opt_start = 2;
    int a, b;
    if (argc >= 4 && parse_int(argv[2], &a) && parse_int(argv[3], &b)) {
        if (a < 1 || b > 65535 || a > b) {
            fprintf(stderr, "[!] Invalid port range: %d-%d\n", a, b);
            return 1;
        }
        start_port = a; end_port = b; opt_start = 4;
    }

    for (int i = opt_start; i < argc; i++) {
        const char *arg = argv[i];
        if (!strcmp(arg, "-v"))               verbose = 1;
        else if (!strcmp(arg, "-sn"))         ping_only = 1;
        else if (!strcmp(arg, "--no-banner")) banner_grab = 0;
        else if (!strcmp(arg, "-p-"))         { start_port = 1; end_port = 65535; }
        else if (!strcmp(arg, "-p") && i + 1 < argc) {
            if (!parse_ports(argv[++i])) return 1;
        }
        else if (!strcmp(arg, "-oN") && i + 1 < argc) {
            snprintf(output_filename, sizeof(output_filename), "%s", argv[++i]);
        }
        else if (!strcmp(arg, "-t") && i + 1 < argc) {
            if (!parse_int(argv[++i], &concurrency) || concurrency < 1) {
                fprintf(stderr, "[!] Bad value for -t\n"); return 1;
            }
            if (concurrency > MAX_PROBES) {
                fprintf(stderr, "[!] -t clamped to %d\n", MAX_PROBES);
                concurrency = MAX_PROBES;
            }
        }
        else if (!strcmp(arg, "--timeout") && i + 1 < argc) {
            if (!parse_int(argv[++i], &timeout_ms) ||
                timeout_ms < TIMEOUT_MIN_MS || timeout_ms > TIMEOUT_MAX_MS) {
                fprintf(stderr, "[!] --timeout must be %d..%d ms\n",
                        TIMEOUT_MIN_MS, TIMEOUT_MAX_MS);
                return 1;
            }
        }
        else if (!strcmp(arg, "--banner-timeout") && i + 1 < argc) {
            if (!parse_int(argv[++i], &banner_timeout_ms) ||
                banner_timeout_ms < TIMEOUT_MIN_MS || banner_timeout_ms > TIMEOUT_MAX_MS) {
                fprintf(stderr, "[!] --banner-timeout must be %d..%d ms\n",
                        TIMEOUT_MIN_MS, TIMEOUT_MAX_MS);
                return 1;
            }
        }
        else {
            fprintf(stderr, "[!] Unknown or incomplete option: %s\n", arg);
            return 1;
        }
    }

    if (output_filename[0]) {
        output_file = fopen(output_filename, "w");
        if (!output_file) {
            fprintf(stderr, "[!] Error: could not create output file %s\n", output_filename);
            return 1;
        }
        time_t now = time(NULL);
        char tbuf[64];
        strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(output_file, "# VIPERSCAN v%s Scan Report\n", VERSION);
        fprintf(output_file, "# Target: %s\n# Date:   %s\n\n", target, tbuf);
    }

    signal(SIGINT, on_sigint);
    signal(SIGPIPE, SIG_IGN);

    if (!resolve_target(target, global_target_ip, sizeof(global_target_ip))) {
        if (output_file) fclose(output_file);
        return 1;
    }
    build_service_cache();

    printf("--------------------------------------------------\n");
    printf("   VIPERSCAN v%s\n", VERSION);
    printf("--------------------------------------------------\n");
    printf("[*] Target Host: %s (%s)\n", target, global_target_ip);
    printf("[*] Probes: %d | Connect timeout: %d ms | Banner: %s\n",
           concurrency, timeout_ms, banner_grab ? "ON" : "OFF");
    if (verbose)     printf("[*] Verbose mode: ENABLED\n");
    if (output_file) printf("[*] Output file: %s\n", output_filename);

    if (ping_only) {
        printf("[*] Mode: Ping Scan (-sn)\n");
        printf("--------------------------------------------------\n");
        do_ping_scan();
    } else {
        if (custom_ports_count > 0) {
            total_ports_to_scan = custom_ports_count;
            ports_queue = malloc((size_t)total_ports_to_scan * sizeof(int));
            if (!ports_queue) { perror("[!] malloc"); return 1; }
            memcpy(ports_queue, custom_ports, (size_t)total_ports_to_scan * sizeof(int));
            printf("[*] Scanning specific ports: %d ports\n", total_ports_to_scan);
        } else {
            total_ports_to_scan = end_port - start_port + 1;
            ports_queue = malloc((size_t)total_ports_to_scan * sizeof(int));
            if (!ports_queue) { perror("[!] malloc"); return 1; }
            for (int i = 0; i < total_ports_to_scan; i++) ports_queue[i] = start_port + i;
            printf("[*] Scanning range: %d - %d\n", start_port, end_port);
        }

        run_scan();
        banner_phase();

        free(ports_queue);
        free(open_ports);
    }

    free(custom_ports);
    free_service_cache();

    gettimeofday(&end_time, NULL);
    double elapsed = (end_time.tv_sec - start_time.tv_sec) +
                     (end_time.tv_usec - start_time.tv_usec) / 1000000.0;

    printf("--------------------------------------------------\n");
    if (stop_flag) printf("[!] Interrupted by user (Ctrl+C).\n");
    if (!ping_only)
        printf("[*] Scanned: %d ports | Open: %d\n",
               atomic_load(&scanned_count), atomic_load(&open_count));
    printf("[*] Scan complete. Time elapsed: %.2f seconds.\n", elapsed);

    if (output_file) {
        if (!ping_only)
            fprintf(output_file, "\n# Scanned: %d ports | Open: %d\n",
                    atomic_load(&scanned_count), atomic_load(&open_count));
        fprintf(output_file, "# Scan complete. Time elapsed: %.2f seconds.\n", elapsed);
        fclose(output_file);
    }
    return 0;
}
