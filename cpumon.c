/*
    Build with GLIBC: "gcc cpumon.c -s -Wall -Wpedantic -Wextra -o cpumon -lpthread -O3 -fomit-frame-pointer -s -fno-unwind-tables -fno-asynchronous-unwind-tables"
    Build with MUSL: "musl-gcc cpumon.c -s -Wall -Wpedantic -Wextra -o cpumon -lpthread -O3 -fomit-frame-pointer -s -fno-unwind-tables -fno-asynchronous-unwind-tables -static"
    Usage: cpumon [<time in seconds=[1;60]>]
*/

#define _POSIX_C_SOURCE 200809
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <glob.h>

// Cloned from util-linux
static inline int char_to_val(int c)
{
	int cl;

	cl = tolower(c);
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (cl >= 'a' && cl <= 'f')
		return cl + (10 - 'a');
	else
		return -1;
}

// Adapted from "int cpumask_parse(const char *str, cpu_set_t *set, size_t setsize)" in util-linux
static int count_cpumask_threads(const char *str)
{
	int len = strlen(str);
	if (str[len - 1] == '\n')
		--len;
	const char *ptr = str + len - 1;
	if (len > 1 && !memcmp(str, "0x", 2L))
		str += 2;

    unsigned threads = 0;
	while (ptr >= str) {
		if (*ptr == ',')
			ptr--;
		const char val = char_to_val(*ptr);
		if (val == (char) -1)
			return 0;
		if (val & 1)
			++threads;
		if (val & 2)
			++threads;
		if (val & 4)
			++threads;
		if (val & 8)
			++threads;
		ptr--;
	}
	return threads;
}

static unsigned get_local_capacity(const char* const thread_siblings_path)
{
    FILE* const thread_siblings = fopen(thread_siblings_path, "r");
    if (thread_siblings == NULL)
    {
        fprintf(stderr, "Failed to open \"%s\", errno=%d\n", thread_siblings_path, errno);
        return 0;
    }
    const int CPUSET_LEN = 2048 * 7;
    char buffer[CPUSET_LEN];
    if (fgets(buffer, CPUSET_LEN, thread_siblings) == 0)
    {
        fprintf(stderr, "Failed to read \"%s\", errno=%d\n", thread_siblings_path, errno);
        fclose(thread_siblings);
        return 0;
    }
    fclose(thread_siblings);
    unsigned threads = count_cpumask_threads(buffer);
    unsigned capacity = 0;
    if (threads > 0)
    {
        capacity += 100;
        --threads;
    }
    capacity -= threads * ((100 - /* HT scale */ 26) / 2);
    return capacity;
}

static unsigned get_capacity()
{
    glob_t result;
    if (glob("/sys/devices/system/cpu/cpu[0-9]*/topology/thread_siblings", GLOB_NOSORT, NULL, &result) != 0)
    {
        fprintf(stderr, "Failed to get processor topology, errno=%d\n", errno);
        return 0;
    }
    unsigned capacity = 0;
    for (size_t i = 0;i != result.gl_pathc;++i)
    {
        const unsigned local_capacity = get_local_capacity(result.gl_pathv[i]);
        capacity += local_capacity;
    }
    globfree(&result);
    return capacity;
}

static unsigned get_local_frequency(const char* const cur_freq_path)
{
    FILE* const cur_freq = fopen(cur_freq_path, "r");
    if (cur_freq == NULL)
    {
        fprintf(stderr, "Failed to open \"%s\", errno=%d\n", cur_freq_path, errno);
        return 0;
    }
    unsigned frequency;
    if (fscanf(cur_freq, "%u", &frequency) != 1)
    {
        fprintf(stderr, "Failed to read \"%s\", errno=%d\n", cur_freq_path, errno);
        fclose(cur_freq);
        return 0;
    }
    fclose(cur_freq);
    return frequency;
}

static unsigned get_frequency()
{
    glob_t result;
    if (glob("/sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_cur_freq", GLOB_NOSORT, NULL, &result) != 0)
    {
        fprintf(stderr, "Failed to get processor frequency, errno=%d\n", errno);
        return 0;
    }
    unsigned frequency = 0;
    unsigned count = 0;
    for (size_t i = 0;i != result.gl_pathc;++i)
    {
        const unsigned local_frequency = get_local_frequency(result.gl_pathv[i]);
        frequency += local_frequency;
        if (local_frequency != 0)
            ++count;
    }
    globfree(&result);
    if (frequency == 0)
        return 0;
    frequency = (frequency + count - 1) / count;
    return frequency;
}

static unsigned get_frequency_limit()
{
    glob_t result;
    if (glob("/sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_max_freq", GLOB_NOSORT, NULL, &result) != 0)
        return 0;
    unsigned frequency = 0;
    unsigned count = 0;
    for (size_t i = 0;i != result.gl_pathc;++i)
    {
        const unsigned local_frequency = get_local_frequency(result.gl_pathv[i]);
        frequency += local_frequency;
        if (local_frequency != 0)
            ++count;
    }
    globfree(&result);
    if (frequency == 0)
        return 0;
    frequency = (frequency + count - 1) / count;
    return frequency;
}

// Matches PID_MAX_LIMIT for now
#define PID_MAX 4 * 1024 * 1024
// We probably won't hit this
#define NR_CPUS 2048
// We probably won't hit this
#define NR_CPU_NODES 1024

struct procinfo {
    unsigned time;
    unsigned diff;
    const char* name;
};

static struct procinfo g_procs[PID_MAX];
static pid_t g_used_pids[PID_MAX];
static volatile unsigned g_used_pids_count;
static unsigned long long g_cpu_subscription[NR_CPUS];
static unsigned short g_cpu_nodes[NR_CPU_NODES];
static volatile unsigned short g_cpu_max_index;
static volatile unsigned short g_node_max_index;
static pthread_t g_subscription_thread;
static pthread_t g_frequency_thread;
static pthread_t g_used_time_thread;
static volatile sig_atomic_t g_stop;

static const unsigned MIN_TIME = 2000;
static const unsigned MIN_USED_TIME = 32;

static int read_name(const pid_t pid, char* const stat_path)
{
    if (g_procs[pid].name != NULL)
        return 0;
    char buffer[PATH_MAX + 1];
    const char* const stat_dir = dirname(stat_path);
    if (snprintf(buffer, sizeof(buffer), "%s/cmdline", stat_dir) >= PATH_MAX + 1)
    {
        fprintf(stderr, "Path too long for cmdline: %s\n", stat_dir);
        return 0;
    }
    const int cmdline = open(buffer, O_RDONLY);
    ssize_t bytes;
    if (cmdline >= 0)
    {
        bytes = read(cmdline, buffer, PATH_MAX);
        close(cmdline);
        if (bytes > 0)
        {
            char* ptr;
            for (;;)
            {
                ptr = memchr(buffer, '\0', bytes - 1);
                if (ptr == NULL)
                {
                    break;
                }
                *ptr = ' ';
            }
        }
        else
        {
            bytes = 0;
        }
    }
    else
    {
        bytes = 0;
    }
    if (bytes == 0)
    {
        if (snprintf(buffer, sizeof(buffer), "%s/comm", stat_dir) >= PATH_MAX + 1)
        {
            fprintf(stderr, "Path too long for comm: %s\n", stat_dir);
            return 0;
        }
        const int comm = open(buffer, O_RDONLY);
        if (comm >= 0)
        {
            bytes = read(comm, buffer, PATH_MAX);
            close(comm);
            if (bytes > 0)
            {
                char* ptr;
                for (;;)
                {
                    ptr = memchr(buffer, '\0', bytes - 1);
                    if (ptr == NULL)
                    {
                        break;
                    }
                    *ptr = ' ';
                }
                if (buffer[bytes - 1] == '\n')
                {
                    --bytes;
                }

                if (bytes < PATH_MAX)
                {
                    buffer[bytes++] = '*';
                }
            }
            else
            {
                bytes = 0;
            }
        }
    }
    buffer[bytes] = '\0';
    g_procs[pid].name = strdup(buffer);
    return 1;
}

static int get_local_time(char* const stat_path)
{
    FILE* const time = fopen(stat_path, "r");
    if (time == NULL)
        return 0;
    pid_t pid;
    unsigned long utime, stime;
    if (fscanf(time, "%d (%*[^)]) %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu", &pid, &utime, &stime) != 3)
    {
        rewind(time);
        if (fscanf(time, "%d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu", &pid, &utime, &stime) != 3)
        {
            if (errno == ESRCH)
            {
                fclose(time);
                return 0;
            }
            fprintf(stderr, "Failed to read \"%s\", errno=%d\n", stat_path, errno);
            fclose(time);
            return -1;
        }
    }
    fclose(time);
    if (pid < 0)
    {
        fprintf(stderr, "Invalid negative PID %d detected\n", pid);
        return -1;
    }
    if (pid >= PID_MAX)
    {
        fprintf(stderr, "PID %d is too large\n", pid);
        return -1;
    }
    const unsigned total_time = utime + stime;
    if (total_time == 0)
        return 0;
    unsigned last_total_time = g_procs[pid].time;
    g_procs[pid].time = total_time;
    if (last_total_time != 0)
    {
        unsigned delta = g_procs[pid].diff + (total_time - last_total_time);
        if (delta >= MIN_USED_TIME)
        {
            if (read_name(pid, stat_path) != 0)
            {
                if (g_used_pids_count >= PID_MAX)
                {    
                    fputs("Used pids table overflow", stderr);
                    return -1;
                }
                g_used_pids[g_used_pids_count++] = pid;
            }
        }
        g_procs[pid].diff = delta;
        return delta;
    }
    return 0;
}

static int get_cpu_nodes()
{
    glob_t result;
    if (glob("/sys/devices/system/cpu/cpu[0-9]*/node[0-9]*", GLOB_NOSORT, NULL, &result) != 0)
    {
        fprintf(stderr, "Failed to get CPU nodes, errno=%d\n", errno);
        return -1;
    }

    // This is done for safety so that unmapped nodes will fail when accessing them since 0xFFFF is larger than NR_CPU_NODES
    memset(g_cpu_nodes, 0xFF, NR_CPU_NODES * sizeof(unsigned short));

    for (size_t i = 0;i != result.gl_pathc;++i)
    {
        const char* const path = result.gl_pathv[i];
        unsigned short cpu, node;
        if (sscanf(path, "/sys/devices/system/cpu/cpu%hu/node%hu", &cpu, &node) != 2)
        {
            fprintf(stderr, "Failed to parse CPU node from \"%s\", errno=%d\n", path, errno);
            continue;
        }

        if (cpu >= NR_CPUS)
        {
            fprintf(stderr, "Invalid CPU index %hu from \"%s\"\n", cpu, path);
            continue;
        }

        if (node >= NR_CPU_NODES)
        {
            fprintf(stderr, "Invalid CPU node index %hu from \"%s\"\n", node, path);
            continue;
        }

        g_cpu_nodes[cpu] = node;
        if (g_node_max_index < node)
        {
            g_node_max_index = node;
        }
    }

    globfree(&result);
    return 0;
}

static int get_used_time()
{
    glob_t result;
    if (glob("/proc/[0-9]*/stat", GLOB_NOSORT, NULL, &result) != 0)
    {
        fprintf(stderr, "Failed to get process list, errno=%d\n", errno);
        return -1;
    }
    for (size_t i = 0;i != result.gl_pathc;++i)
    {
        int local_time = get_local_time(result.gl_pathv[i]);
        if (local_time < 0)
        {
            globfree(&result);
            return -1;
        }
    }
    globfree(&result);
    return 0;
}

static int diff_comparer(const void* const a, const void* const b)
{
    return g_procs[*(const int* const)b].diff - g_procs[*(const int* const)a].diff;
}

static void dump_top(const unsigned clock_scale)
{
    if (g_used_pids_count == 0)
        return;
    qsort(g_used_pids, g_used_pids_count, sizeof(pid_t), &diff_comparer);
    const unsigned TOP_N = 5;
    unsigned pids_count = g_used_pids_count;
    if (pids_count > TOP_N)
        pids_count = TOP_N;
    for (unsigned i = 0;i < pids_count;i++)
    {
        const pid_t pid = g_used_pids[i];
        const unsigned delta = g_procs[pid].diff;
        const unsigned usage = (delta + clock_scale - 1) / clock_scale;
        if (usage > 0)
        {
            const char* name = g_procs[pid].name;
            if (name == NULL)
                name = "";
            printf("- system.cpu.used_by \"%u %d \\\"", usage, pid);
            for (;;)
            {
                char chr = *name++;
                if (chr == '\0')
                    break;
                if (chr == '\n')
                {
                    puts("\\n");
                    continue;
                }
                if (chr == '"')
                    putchar('\\');
                putchar(chr);
            }
            puts("\\\"\"");
        }
    }
}

static const int TIME_S = 60;

static int update_schedstat(FILE* const schedstat)
{
    for (;;)
    {
        const int SCHEDSTAT_LINE_LEN = 1024;
        char buffer[SCHEDSTAT_LINE_LEN];
        if (fgets(buffer, SCHEDSTAT_LINE_LEN, schedstat) == NULL)
        {
            if (errno == 0)
            {
                break;
            }

            fprintf(stderr, "Failed to read /proc/schedstat, errno=%d\n", errno);
            return -1;
        }
        unsigned short cpu;
        unsigned long long run_time;
        unsigned long long wait_time;
        if (sscanf(buffer, "cpu%hu %*u %*u %*u %*u %*u %*u %llu %llu %*u\n", &cpu, &run_time, &wait_time) != 3)
        {
            continue;
        }

        if (cpu >= NR_CPUS)
        {
            fprintf(stderr, "Invalid CPU index %hu\n", cpu);
            return -1;
        }

        g_cpu_subscription[cpu] = run_time + wait_time - g_cpu_subscription[cpu];
        if (g_cpu_max_index < cpu)
        {
            g_cpu_max_index = cpu;
        }
    }

    return 0;
}

static int handle_subscription_loadavg(const int time_s)
{
    struct timespec end;
    if (clock_gettime(CLOCK_MONOTONIC_COARSE, &end) != 0)
    {
        fprintf(stderr, "Failed to get start time for subscription, errno=%d\n", errno);
        return -1;
    }
    const useconds_t INTERVAL_MS = 17;
    unsigned long long runnable_sum = 0;
    unsigned runnable_ratio = 0;
    const unsigned capacity = get_capacity();
    if (capacity == 0)
        return -1;
    struct timespec last = end;
    end.tv_sec += time_s;
    end.tv_nsec -= INTERVAL_MS * 1000000LL;
    while (g_stop == 0)
    {
        FILE *loadavg = fopen("/proc/loadavg", "r");
        if (loadavg == NULL)
        {
            fprintf(stderr, "Failed to open /proc/loadavg, errno=%d\n", errno);
            return -1;
        }
        int runnable;
        if (fscanf(loadavg, "%*f %*f %*f %d", &runnable) != 1)
        {
            fprintf(stderr, "Failed to read /proc/loadavg, errno=%d\n", errno);
            fclose(loadavg);
            return -1;
        }
        fclose(loadavg);
        if (runnable == 0)
        {
            fputs("Unexpected zero runnable queue", stderr);
            return -1;
        }
        runnable_sum += runnable - 1;
        runnable_ratio++;
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC_COARSE, &now) != 0)
        {
            fprintf(stderr, "Failed to get current time (now) for subscription, errno=%d\n", errno);
            return -1;
        }
        long long remaining = ((long long)(now.tv_sec - end.tv_sec)) * 1000000LL + (now.tv_nsec - end.tv_nsec) / 1000;
        if (remaining >= 0)
            break;
        long long diff = INTERVAL_MS * 1000000LL - ((long long)(now.tv_sec - last.tv_sec)) * 1000000000LL - (now.tv_nsec - last.tv_nsec);
        if (diff > 0)
        {
            struct timespec slp;
            slp.tv_sec = diff / 1000000000LL;
            slp.tv_nsec = diff % 1000000000LL;
            if (nanosleep(&slp, NULL) != 0)
            {
                return errno == EINTR ? -1 : 0;
            }
            if (clock_gettime(CLOCK_MONOTONIC_COARSE, &last) != 0)
            {
                fprintf(stderr, "Failed to get current time (last) for subscription, errno=%d\n", errno);
                return -1;
            }
        }
        else
        {
            last = now;
        }
    }
    if (runnable_ratio != 0)
    {
        const unsigned subscription = ((runnable_sum * 10000 + runnable_ratio - 1) / runnable_ratio + capacity - 1) / capacity;
        printf("- system.cpu.subscription %u\n", subscription);
    }

    return 0;
}

static int handle_frequency(const int time_s)
{
    struct timespec end;
    if (clock_gettime(CLOCK_MONOTONIC_COARSE, &end) != 0)
    {
        fprintf(stderr, "Failed to get start time for frequency, errno=%d\n", errno);
        return -1;
    }
    const useconds_t INTERVAL_MS = 500;
    const unsigned frequency_limit = get_frequency_limit();
    if (frequency_limit != 0)
        printf("- system.cpu.frequency_limit %u\n", frequency_limit);
    unsigned long long frequency_sum = 0;
    unsigned frequency_ratio = 0;
    struct timespec last = end;
    end.tv_sec += time_s;
    end.tv_nsec -= INTERVAL_MS * 1000000LL;
    while (g_stop == 0)
    {
        if (frequency_limit != 0)
        {
            const unsigned frequency = get_frequency();
            if (frequency == 0)
            {
                return -1;
            }
            frequency_sum += frequency;
            frequency_ratio++;
        }
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC_COARSE, &now) != 0)
        {
            fprintf(stderr, "Failed to get current time (now) for frequency, errno=%d\n", errno);
            return -1;
        }
        const long long remaining = ((long long)(now.tv_sec - end.tv_sec)) * 1000000LL + (now.tv_nsec - end.tv_nsec) / 1000;
        if (remaining >= 0)
            break;
        long long diff = INTERVAL_MS * 1000000LL - ((long long)(now.tv_sec - last.tv_sec)) * 1000000000LL - (now.tv_nsec - last.tv_nsec);
        if (diff > 0)
        {
            struct timespec slp;
            slp.tv_sec = diff / 1000000000LL;
            slp.tv_nsec = diff % 1000000000LL;
            if (nanosleep(&slp, NULL) != 0)
            {
                return errno == EINTR ? -1 : 0;
            }
            if (clock_gettime(CLOCK_MONOTONIC_COARSE, &last) != 0)
            {
                fprintf(stderr, "Failed to get current time (last) for frequency, errno=%d\n", errno);
                return -1;
            }
        }
        else
        {
            last = now;
        }
    }
    if (frequency_ratio != 0 && frequency_limit != 0)
    {
        const unsigned frequency = (frequency_sum + frequency_ratio - 1) / frequency_ratio;
        printf("- system.cpu.frequency %u\n", frequency);
        const unsigned frequency_scale = ((frequency_sum * 100 + frequency_ratio - 1) / frequency_ratio + frequency_limit - 1) / frequency_limit;
        printf("- system.cpu.frequency_scale %u\n", frequency_scale);
    }
    return 0;
}

static int handle_used_time(const int time_s)
{
    struct timespec end;
    if (clock_gettime(CLOCK_MONOTONIC_COARSE, &end) != 0)
    {
        fprintf(stderr, "Failed to get start time for used time, errno=%d\n", errno);
        return -1;
    }
    const useconds_t INTERVAL_MS = MIN_TIME / 2;
    struct timespec last = end;
    end.tv_sec += time_s;
    end.tv_nsec -= INTERVAL_MS * 1000000LL;
    while (g_stop == 0)
    {
        if (get_used_time() < 0)
        {
            return -1;
        }
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC_COARSE, &now) != 0)
        {
            fprintf(stderr, "Failed to get time (now) for used time, errno=%d\n", errno);
            return -1;
        }
        const long long remaining = ((long long)(now.tv_sec - end.tv_sec)) * 1000000LL + (now.tv_nsec - end.tv_nsec) / 1000;
        if (remaining >= 0)
            break;
        long long diff = INTERVAL_MS * 1000000LL - ((long long)(now.tv_sec - last.tv_sec)) * 1000000000LL - (now.tv_nsec - last.tv_nsec);
        if (diff > 0)
        {
            struct timespec slp;
            slp.tv_sec = diff / 1000000000LL;
            slp.tv_nsec = diff % 1000000000LL;
            if (nanosleep(&slp, NULL) != 0)
            {
                return errno == EINTR ? -1 : 0;
            }
            if (clock_gettime(CLOCK_MONOTONIC_COARSE, &last) != 0)
            {
                fprintf(stderr, "Failed to get current time (last) for used time, errno=%d\n", errno);
                return -1;
            }
        }
        else
        {
            last = now;
        }
    }
    if (get_used_time() < 0)
    {
        return -1;
    }

    return 0;
}

static int handle_subscription(const int time_s)
{
    FILE *schedstat = fopen("/proc/schedstat", "r");
    if (schedstat == NULL)
    {
        if (errno == ENOENT)
        {
            return handle_subscription_loadavg(time_s);
        }

        fprintf(stderr, "Failed to open /proc/schedstat, errno=%d\n", errno);
        return -1;
    }

    if (get_cpu_nodes() != 0)
    {
        fclose(schedstat);
        return -1;
    }

    if (update_schedstat(schedstat) != 0)
    {
        fclose(schedstat);
        return -1;
    }
    struct timespec slp;
    slp.tv_sec = time_s;
    slp.tv_nsec = 0;
    if (nanosleep(&slp, NULL) != 0)
    {
        fclose(schedstat);
        return errno == EINTR ? -1 : 0;
    }

    g_cpu_max_index = 0; // If CPU count is down we should not take into account old CPUs
    rewind(schedstat);
    if (update_schedstat(schedstat) != 0)
    {
        fclose(schedstat);
        return -1;
    }
    fclose(schedstat);

    const unsigned cpus = g_cpu_max_index + 1;
    unsigned long long node_subscription[cpus];
    memset(node_subscription, 0, cpus * sizeof(unsigned long long));

    const unsigned nodes = g_node_max_index + 1;
    unsigned short node_cpus[nodes];
    memset(node_cpus, 0, nodes * sizeof(unsigned short));

    const unsigned long long interval = 1000000ULL * time_s;
    const unsigned long long scale = interval * 1000;
    unsigned long long total_cpu_subscription = 0;
    for (unsigned short cpu = 0;cpu < cpus;++cpu)
    {
        const unsigned long long cpu_subscription = g_cpu_subscription[cpu];
        const unsigned subscription = (cpu_subscription * 100 + scale - 1) / scale;
        printf("- system.cpu.subscription[%hu] %u\n", cpu, subscription);

        char path[PATH_MAX + 1];
        int ret = snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%hu/topology/thread_siblings", cpu);
        if (ret <= 0 || ret >= PATH_MAX + 1)
        {
            fprintf(stderr, "Failed to generate cpu%hu topology path\n", cpu);
            return -1;
        }

        const unsigned cpu_capacity = get_local_capacity(path);
        if (cpu_capacity == 0)
        {
            fprintf(stderr, "Failed to get cpu%hu capacity, errno=%d\n", cpu, errno);
            return -1;
        }

        const unsigned long long relative_cpu_subscription = (cpu_subscription * 100 + cpu_capacity - 1) / cpu_capacity;
        total_cpu_subscription += relative_cpu_subscription;

        unsigned short node = g_cpu_nodes[cpu];
        if (node >= nodes)
        {
            fprintf(stderr, "Invalid CPU %hu node index %hu\n", cpu, node);
            return -1;
        }

        node_subscription[node] += relative_cpu_subscription;
        ++node_cpus[node];
    }

    const unsigned long long total_scale = cpus * scale;
    const unsigned total_subscription = (total_cpu_subscription * 100 + total_scale - 1) / total_scale;
    printf("- system.cpu.subscription %u\n", total_subscription);

    for (unsigned short node = 0;node < nodes;++node)
    {
        const unsigned long long node_scale = scale * node_cpus[node];
        const unsigned subscription = (node_subscription[node] * 100 + node_scale - 1) / node_scale;
        printf("- system.cpu_node.subscription[%hu] %u\n", node, subscription);
    }

    return 0;
}

static void empty_handler(int signum)
{
    (void)signum;
}

static void* subscription_routine(void* time_s)
{
    return (void*)(long)handle_subscription(*((const int*)time_s));
}

static void* frequency_routine(void* time_s)
{
    return (void*)(long)handle_frequency(*((const int*)time_s));
}

static void* used_time_routine(void* time_s)
{
    return (void*)(long)handle_used_time(*((const int*)time_s));
}

static void term_handler(int signum)
{
    (void)signum;
    if (g_stop)
    {
        return;
    }

    g_stop = 1;
    if (g_subscription_thread)
    {
        pthread_kill(g_subscription_thread, SIGALRM);
    }

    if (g_frequency_thread)
    {
        pthread_kill(g_frequency_thread, SIGALRM);
    }

    if (g_used_time_thread)
    {
        pthread_kill(g_used_time_thread, SIGALRM);
    }
}

int main(int argc, char* argv[])
{
    int time_s = TIME_S;
    if (argc == 2 && argv[1] != NULL)
    {
        time_s = atoi(argv[1]);
        if (time_s < 1 || time_s > TIME_S)
        {
            fprintf(stderr, "The specified time %d is out of range\n", time_s);
            return -1;
        }        
    }

    struct sigaction term_sa = {0};
    term_sa.sa_handler = &term_handler;
    if (sigaction(SIGTERM, &term_sa, NULL) != 0)
    {
        fprintf(stderr, "Failed to set SIGTERM handler, errno=%d\n", errno);
        return -1;
    }

    struct sigaction alrm_sa = {0};
    alrm_sa.sa_handler = &empty_handler;
    if (sigaction(SIGALRM, &alrm_sa, NULL) != 0)
    {
        fprintf(stderr, "Failed to set SIGALRM handler, errno=%d\n", errno);
        return -1;
    }

// Start threads and join them
    if (pthread_create(&g_subscription_thread, NULL, subscription_routine, &time_s) != 0)
    {
        fprintf(stderr, "Failed to create subscription monitoring thread, errno=%d\n", errno);
        return -1;
    }
    if (pthread_create(&g_frequency_thread, NULL, frequency_routine, &time_s))
    {
        fprintf(stderr, "Failed to create frequency monitoring thread, errno=%d\n", errno);
        return -1;
    }
    if (pthread_create(&g_used_time_thread, NULL, used_time_routine, &time_s))
    {
        fprintf(stderr, "Failed to create used time monitoring thread, errno=%d\n", errno);
        return -1;
    }

    void* subscription_result;
    if (pthread_join(g_subscription_thread, &subscription_result) != 0)
    {
        fprintf(stderr, "Failed to join subscription monitoring thread, errno=%d\n", errno);
        return -1;
    }
    void* frequency_result;
    if (pthread_join(g_frequency_thread, &frequency_result) != 0)
    {
        fprintf(stderr, "Failed to join frequency monitoring thread, errno=%d\n", errno);
        return -1;
    }
    void* used_time_result;
    if (pthread_join(g_used_time_thread, &used_time_result) != 0)
    {
        fprintf(stderr, "Failed to join used time monitoring thread, errno=%d\n", errno);
        return -1;
    }

    const int subscription_result_code = (int)(long)subscription_result;
    if (subscription_result_code != 0)
    {
        return subscription_result_code;
    }    
    const int frequency_result_code = (int)(long)frequency_result;
    if (frequency_result_code != 0)
    {
        return frequency_result_code;
    }    
    const int used_time_result_code = (int)(long)used_time_result;
    if (used_time_result_code != 0)
    {
        return used_time_result_code;
    }    

    const unsigned clock_scale = sysconf(_SC_CLK_TCK) * time_s / 100;
    dump_top(clock_scale);
    return 0;
}
