#!/usr/bin/python
#Usage: To get user function time by attaching uprobe and uretprobe to instrument function entry and exit time.
#sheenam@sheenam:/usr/share/bcc/tools$ sudo ./functime.py -s /proc/20856/root/usr/share/bcc/tools/if-else -fn goNum
#TIME      PID    LATms           FNAME
#22:03:57  20856  0.014978           goNum 
#22:03:58  20856  0.007614           goNum 
#22:03:59  20856  0.008696           goNum 
#22:04:00  20856  0.013339           goNum 

from __future__ import print_function
from bcc import BPF
from time import strftime
import argparse

examples = """examples:
    ./functime           # time functime calls
    ./functime -p 181    # only trace PID 181
"""
parser = argparse.ArgumentParser(
    description="Show time for user function",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid", help="trace this PID only", type=int,
    default=-1)
parser.add_argument("-s", "--shared", nargs="?",
        help="specify file path")
parser.add_argument("-fn", "--fn", nargs="?",
        help="specify function name")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
name = args.shared if args.shared else "not valid file path"
fname = args.fn if args.fn else "Please enter the function name"
# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
struct val_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u64 ts;
    char fn[80];
};
struct data_t {
    u32 pid;
    u64 delta;
    char comm[TASK_COMM_LEN];
};
BPF_HASH(start, u32, struct val_t);
BPF_PERF_OUTPUT(events);
int do_entry(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;
    struct val_t val = {};
    u32 pid = bpf_get_current_pid_tgid();
    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        bpf_probe_read(&val.fn, sizeof(val.fn),
                       (void *)PT_REGS_PARM1(ctx));
        val.pid = bpf_get_current_pid_tgid();
        val.ts = bpf_ktime_get_ns();
        start.update(&pid, &val);
    }
    return 0;
}
int do_return(struct pt_regs *ctx) {
    struct val_t *valp;
    struct data_t data = {};
    u64 delta;
    u32 pid = bpf_get_current_pid_tgid();
    u64 tsp = bpf_ktime_get_ns();
    valp = start.lookup(&pid);
    if (valp == 0)
        return 0;       // missed start
    bpf_probe_read(&data.comm, sizeof(data.comm), valp->comm);
    data.pid = valp->pid;
    data.delta = tsp - valp->ts;
    events.perf_submit(ctx, &data, sizeof(data));
    start.delete(&pid);
    return 0;
}
"""
if args.ebpf:
    print(bpf_text)
    exit()

b = BPF(text=bpf_text)
b.attach_uprobe(name=name, sym=fname, fn_name="do_entry", pid=args.pid)
b.attach_uretprobe(name=name, sym=fname, fn_name="do_return",
                   pid=args.pid)

# header
print("%-9s %-6s %s %18s" % ("TIME", "PID", "LATms", "FNAME"))

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("%-9s %-6d %s %15s " % (strftime("%H:%M:%S"), event.pid,
         (float(event.delta) / 1000000), fname))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
