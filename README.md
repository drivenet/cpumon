# cpumon
## What it is and why it was created?
This is a simple tool to monitor CPU subscription.

Often, when someone says that "we need to monitor CPU utilization", the resulting metric is expected to provide an estimate of a remaining capacity of CPU to cope with load.
In Linux, the often-used load average is [misleading when estimating CPU capacity](https://www.brendangregg.com/blog/2017-08-08/linux-load-averages.html), because it takes into account the time that is spent on I/O, which usually does not take much of CPU time.
The "% utilization" on the other hand, while providing important details like system/user/interrupts/hypervisor usage does not properly properly handle CPU topologies like SMT, considering all threads/cores are equal, while [they are not](https://community.intel.com/t5/Intel-oneAPI-Math-Kernel-Library/HyperThreading-and-CPU-usage/m-p/1134675#M25930).
There is also [eBPF-based CPU monitoring](https://www.brendangregg.com/ebpf.html), which provides detailed results, but they are not that easy to interpret across different machines and even workload types, also the setup is nontrivial.

This solution presents an alternative that monitors OS per-CPU scheduling queues via [`/proc/schedstat`](https://www.kernel.org/doc/html/latest/scheduler/sched-stats.html) (the preferred way, but not available in VMs) or global scheduling queue via [`/proc/loadavg`](https://www.kernel.org/doc/html/latest/filesystems/proc.html#kernel-data) as a fallback (mostly used for VMs).
It also monitors CPU usage by specific processes over time, reporting top CPU consuming processes (subscription, PID and command line), along with CPU frequency changes.

The only argument that can be passed to the tool is time in seconds to monitor (5-60).
The resulting output is compatible with the [`zabbix_sender`](https://www.zabbix.com/documentation/current/en/manpages/zabbix_sender) reporting utility, but can be interpreted by any tool.
It can be run by any scheduler like `cron` or `systemd`, for example to monitor each minute with chunks of 10 seconds (thus sending 6 samples per minute to aid locating more exact CPU spikes):
```bash
*/1 * * * * nice bash -c 'for _ in {0..5}; do /usr/local/bin/cpumon 10 | zabbix_sender -c /etc/zabbix/zabbix_agentd.conf -i - > /dev/null; done
```
Since it performs runtime sampling, it consumes some CPU (mostly kernel time used to report the scheduling metrics and process information), that take about 2% (user + system) of one core on modern CPUs. Given that a server usually has tens of such cores, the overhead is negligible.

Below is an example of output on a real system (command lines for the `system.cpu.used_by` are edited for brevity):
```text
$ time cpumon 5
- system.cpu.frequency_limit 3700000
- system.cpu.frequency 3158635
- system.cpu.frequency_scale 86
- system.cpu.subscription[0] 9
- system.cpu.subscription[1] 7
- system.cpu.subscription[2] 7
- system.cpu.subscription[3] 10
- system.cpu.subscription[4] 20
- system.cpu.subscription[5] 14
- system.cpu.subscription[6] 9
- system.cpu.subscription[7] 9
- system.cpu.subscription[8] 8
- system.cpu.subscription[9] 11
- system.cpu.subscription[10] 8
- system.cpu.subscription[11] 7
- system.cpu.subscription[12] 10
- system.cpu.subscription[13] 11
- system.cpu.subscription[14] 16
- system.cpu.subscription[15] 11
- system.cpu.subscription[16] 8
- system.cpu.subscription[17] 9
- system.cpu.subscription[18] 9
- system.cpu.subscription[19] 9
- system.cpu.subscription[20] 72
- system.cpu.subscription[21] 21
- system.cpu.subscription[22] 19
- system.cpu.subscription[23] 16
- system.cpu.subscription[24] 20
- system.cpu.subscription[25] 20
- system.cpu.subscription[26] 20
- system.cpu.subscription[27] 24
- system.cpu.subscription[28] 18
- system.cpu.subscription[29] 18
- system.cpu.subscription[30] 3
- system.cpu.subscription[31] 3
- system.cpu.subscription[32] 1
- system.cpu.subscription[33] 1
- system.cpu.subscription[34] 2
- system.cpu.subscription[35] 1
- system.cpu.subscription[36] 1
- system.cpu.subscription[37] 3
- system.cpu.subscription[38] 1
- system.cpu.subscription[39] 1
- system.cpu.subscription[40] 9
- system.cpu.subscription[41] 8
- system.cpu.subscription[42] 9
- system.cpu.subscription[43] 8
- system.cpu.subscription[44] 8
- system.cpu.subscription[45] 12
- system.cpu.subscription[46] 11
- system.cpu.subscription[47] 14
- system.cpu.subscription[48] 19
- system.cpu.subscription[49] 6
- system.cpu.subscription[50] 8
- system.cpu.subscription[51] 10
- system.cpu.subscription[52] 11
- system.cpu.subscription[53] 9
- system.cpu.subscription[54] 7
- system.cpu.subscription[55] 10
- system.cpu.subscription[56] 8
- system.cpu.subscription[57] 8
- system.cpu.subscription[58] 12
- system.cpu.subscription[59] 5
- system.cpu.subscription[60] 16
- system.cpu.subscription[61] 15
- system.cpu.subscription[62] 14
- system.cpu.subscription[63] 14
- system.cpu.subscription[64] 13
- system.cpu.subscription[65] 11
- system.cpu.subscription[66] 14
- system.cpu.subscription[67] 15
- system.cpu.subscription[68] 12
- system.cpu.subscription[69] 16
- system.cpu.subscription[70] 3
- system.cpu.subscription[71] 4
- system.cpu.subscription[72] 4
- system.cpu.subscription[73] 3
- system.cpu.subscription[74] 3
- system.cpu.subscription[75] 3
- system.cpu.subscription[76] 2
- system.cpu.subscription[77] 2
- system.cpu.subscription[78] 1
- system.cpu.subscription[79] 1
- system.cpu.subscription 16
- system.cpu.used_by "298 92679 \"qemu-system-x86_64 ...\""
- system.cpu.used_by "165 1731741 \"/usr/lib/jvm/java-17-openjdk-amd64/bin/java ...\""
- system.cpu.used_by "38 93522 \"/opt/mongodb/6.0.15/mongod ...\""
- system.cpu.used_by "24 96314 \"/opt/mongodb/6.0.15/mongod ...\""
- system.cpu.used_by "19 1732266 \"/usr/lib/jvm/java-17-openjdk-amd64/bin/java ...\""
```
