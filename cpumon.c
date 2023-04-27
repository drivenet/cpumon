/*
    Build with "gcc -O3 cpumon.c -s -Wall -Wpedantic -Wextra -o cpumon -lpthread"
    Usage: cpumon [<time in seconds=[5;60]>]
*/

#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <glob.h>
#include <sys/types.h>

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
int count_cpumask_threads(const char *str)
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
    char buffer[CPUSET_LEN + 1];
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

struct procinfo {
    unsigned time;
    unsigned diff;
    const char* name;
};

static struct procinfo g_procs[PID_MAX];
static pid_t g_used_pids[PID_MAX];
static unsigned g_used_pids_count;

static const unsigned MIN_TIME = 1800;
static const unsigned MIN_USED_TIME = 32;

static int read_name(const pid_t pid, char* const stat_path)
{
    if (g_procs[pid].name != NULL)
        return 0;
    char buffer[PATH_MAX + 1];
    const char* const stat_dir = dirname(stat_path);
    strncpy(buffer, stat_dir, PATH_MAX);
    strncat(buffer, "/cmdline", PATH_MAX);
    buffer[PATH_MAX] = '\0';
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
        strncpy(buffer, stat_dir, PATH_MAX);
        strncat(buffer, "/comm", PATH_MAX);
        buffer[PATH_MAX] = '\0';
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
                if (g_used_pids_count < PID_MAX)
                {    
                    g_used_pids[g_used_pids_count++] = pid;
                }
                else
                {
                    fputs("Used pids table overflow", stderr);
                    abort();
                }
            }
        }
        g_procs[pid].diff = delta;
        return delta;
    }
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
    size_t i;
    for (i = 0;i != result.gl_pathc;++i)
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

/*
static void free_names()
{
    pid_t pid;
    for (pid = 0;pid != PID_MAX;pid++)
    {
        char* name = g_procs[pid].name;
        if (name != NULL)
        {
            free(name);
            g_procs[pid].name = NULL;
        }
    }
}
*/

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

int handle_subscription(const int time_s)
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
    printf("- system.cpu.capacity %u\n", capacity);
    struct timespec last = end;
    end.tv_sec += time_s;
    end.tv_nsec -= INTERVAL_MS * 1000000;
    unsigned step;
    for (step = 0;;step++)
    {
        FILE *loadavg = fopen("/proc/loadavg", "r");
        if (loadavg == NULL)
        {
            fprintf(stderr, "Failed to open /proc/loadavg, errno=%d\n", errno);
            //free_names();
            return -1;
        }
        int runnable;
        if (fscanf(loadavg, "%*f %*f %*f %d", &runnable) != 1)
        {
            fprintf(stderr, "Failed to read /proc/loadavg, errno=%d\n", errno);
            fclose(loadavg);
            //free_names();
            return -1;
        }
        fclose(loadavg);
        if (runnable == 0)
        {
            fputs("Unexpected zero runnable queue", stderr);
            //free_names();
            return -1;
        }
        runnable_sum += runnable - 1;
        runnable_ratio++;
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC_COARSE, &now) != 0)
        {
            fprintf(stderr, "Failed to get current time (now) for subscription, errno=%d\n", errno);
            //free_names();
            return -1;
        }
        long long remaining = ((long long)(now.tv_sec - end.tv_sec)) * 1000000 + (now.tv_nsec - end.tv_nsec) / 1000;
        if (remaining >= 0)
            break;
        long long diff = INTERVAL_MS * 1000 - ((long long)(now.tv_sec - last.tv_sec)) * 1000000 - (now.tv_nsec - last.tv_nsec) / 1000;
        if (diff > 0)
        {
            usleep(diff);
            if (clock_gettime(CLOCK_MONOTONIC_COARSE, &last) != 0)
            {
                fprintf(stderr, "Failed to get current time (last) for subscription, errno=%d\n", errno);
                //free_names();
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
        const unsigned runnable = (runnable_sum * 100 + runnable_ratio - 1) / runnable_ratio;
        printf("- system.cpu.runnable %u\n", runnable);
        const unsigned subscription = ((runnable_sum * 10000 + runnable_ratio - 1) / runnable_ratio + capacity - 1) / capacity;
        printf("- system.cpu.subscription %u\n", subscription);
    }
    //free_names();
    return 0;
}

int handle_frequency(const int time_s)
{
    struct timespec end;
    if (clock_gettime(CLOCK_MONOTONIC_COARSE, &end) != 0)
    {
        fprintf(stderr, "Failed to get start time for frequency, errno=%d\n", errno);
        return -1;
    }
    const useconds_t INTERVAL_MS = 1337;
    const unsigned frequency_limit = get_frequency_limit();
    if (frequency_limit != 0)
        printf("- system.cpu.frequency_limit %u\n", frequency_limit);
    unsigned long long frequency_sum = 0;
    unsigned frequency_ratio = 0;
    struct timespec last = end;
    end.tv_sec += time_s;
    end.tv_nsec -= INTERVAL_MS * 1000000;
    unsigned step;
    for (step = 0;;step++)
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
        const long long remaining = ((long long)(now.tv_sec - end.tv_sec)) * 1000000 + (now.tv_nsec - end.tv_nsec) / 1000;
        if (remaining >= 0)
            break;
        const long long diff = INTERVAL_MS * 1000 - ((long long)(now.tv_sec - last.tv_sec)) * 1000000 - (now.tv_nsec - last.tv_nsec) / 1000;
        if (diff > 0)
        {
            usleep(diff);
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
    if (frequency_ratio != 0)
    {
        const unsigned frequency = (frequency_sum + frequency_ratio - 1) / frequency_ratio;
        printf("- system.cpu.frequency %u\n", frequency);
        const unsigned frequency_scale = ((frequency_sum * 100 + frequency_ratio - 1) / frequency_ratio + frequency_limit - 1) / frequency_limit;
        printf("- system.cpu.frequency_scale %u\n", frequency_scale);
    }
    return 0;
}

int handle_used_time(const int time_s)
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
    end.tv_nsec -= INTERVAL_MS * 1000000;
    unsigned step;
    for (step = 0;;step++)
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
        const long long remaining = ((long long)(now.tv_sec - end.tv_sec)) * 1000000 + (now.tv_nsec - end.tv_nsec) / 1000;
        if (remaining >= 0)
            break;
        const long long diff = INTERVAL_MS * 1000 - ((long long)(now.tv_sec - last.tv_sec)) * 1000000 - (now.tv_nsec - last.tv_nsec) / 1000;
        if (diff > 0)
        {
            usleep(diff);
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

void* subscription_routine(void* time_s)
{
    return (void*)(long)handle_subscription(*((const int*)time_s));
}

void* frequency_routine(void* time_s)
{
    return (void*)(long)handle_frequency(*((const int*)time_s));
}

void* used_time_routine(void* time_s)
{
    return (void*)(long)handle_used_time(*((const int*)time_s));;
}

int main(int argc, char* argv[])
{
    int time_s = TIME_S;
    if (argc == 2 && argv[1] != NULL)
    {
        time_s = atoi(argv[1]);
        if (time_s < 5 || time_s > TIME_S)
        {
            fprintf(stderr, "The specified time %d is out of range\n", time_s);
            return -1;
        }        
    }
// Start threads and join them
    pthread_t subscription_thread;
    if (pthread_create(&subscription_thread, NULL, subscription_routine, &time_s) != 0)
    {
        fprintf(stderr, "Failed to create subscription monitoring thread, errno=%d", errno);
        return -1;
    }
    pthread_t frequency_thread;
    if (pthread_create(&frequency_thread, NULL, frequency_routine, &time_s))
    {
        fprintf(stderr, "Failed to create frequency monitoring thread, errno=%d", errno);
        return -1;
    }
    pthread_t used_time_thread;
    if (pthread_create(&used_time_thread, NULL, used_time_routine, &time_s))
    {
        fprintf(stderr, "Failed to create used time monitoring thread, errno=%d", errno);
        return -1;
    }
    void* subscription_result;
    if (pthread_join(subscription_thread, &subscription_result) != 0)
    {
        fprintf(stderr, "Failed to join subscription monitoring thread, errno=%d", errno);
        return -1;
    }
    const int subscription_result_code = (int)(long)subscription_result;
    if (subscription_result_code != 0)
    {
        return subscription_result_code;
    }    
    void* frequency_result;
    if (pthread_join(frequency_thread, &frequency_result) != 0)
    {
        fprintf(stderr, "Failed to join frequency monitoring thread, errno=%d", errno);
        return -1;
    }
    const int frequency_result_code = (int)(long)frequency_result;
    if (frequency_result_code != 0)
    {
        return frequency_result_code;
    }    
    void* used_time_result;
    if (pthread_join(used_time_thread, &used_time_result) != 0)
    {
        fprintf(stderr, "Failed to join used time monitoring thread, errno=%d", errno);
        return -1;
    }
    const int used_time_result_code = (int)(long)used_time_result;
    if (used_time_result_code != 0)
    {
        return used_time_result_code;
    }    
    const unsigned clock_scale = sysconf(_SC_CLK_TCK) * time_s / 100;
    dump_top(clock_scale);
    //free_names();
    return 0;
}
