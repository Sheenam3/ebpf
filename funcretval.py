#!/usr/bin/python
#
# Using uretprobe
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: funcretval [-s filepath] [-fn function_name]
#sheenam@sheenam:/usr/share/bcc/tools$ sudo ./funcretval -s /proc/20856/root/usr/share/bcc/tools/if-else -fn goNum
#TIME      PID    RETVAL
#21:15:41  20856  9
#21:15:42  20856  9
#21:15:43  20856  2
#21:15:46  20856  7
#21:15:47  20856  3

from __future__ import print_function
from bcc import BPF
from time import strftime
import argparse

parser = argparse.ArgumentParser(
        description="Print entered bash commands from all running shells",
        formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-fn", "--fn", nargs="?",
        help="specify function name")
parser.add_argument("-s", "--shared", nargs="?",
        const="/lib/libreadline.so", type=str,
        help="specify the location of libreadline.so library.\
              Default is /lib/libreadline.so")
args = parser.parse_args()

name = args.shared if args.shared else "/bin/bash"
fname = args.fn if args.fn else "*"
# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

struct str_t {
    u64 pid;
    char str[80];
    int retval;
};

BPF_PERF_OUTPUT(events);

int printret(struct pt_regs *ctx) {
    struct str_t data  = {};
    u32 pid;
    /*if (!PT_REGS_RC(ctx))
        return 0;*/
    pid = bpf_get_current_pid_tgid();
    data.pid = pid;
    data.retval = PT_REGS_RC(ctx);
    bpf_probe_read(&data.str, sizeof(data.str), (void *)PT_REGS_RC(ctx));
    events.perf_submit(ctx,&data,sizeof(data));

    return 0;
};
"""

b = BPF(text=bpf_text)
b.attach_uretprobe(name=name, sym=fname, fn_name="printret")

# header
print("%-9s %-6s %s" % ("TIME", "PID", "RETVAL"))

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("%-9s %-6d %s" % (strftime("%H:%M:%S"), event.pid,
                            event.retval))

b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()



