#!/usr/bin/env python3

"""
Captures and prints TTY activity on the host system using BPF probes.

If you run this using STDOUT, it will cause a feedback loop where each
TTY event creates many new events on STDOUT. I have plans to explicitly
blacklist the TTY device running the script, but until then it's
important to redirect STDOUT and STDERR for optimal behavior:

sudo python3 parrotty.py &> log

See also https://github.com/iovisor/bcc/blob/master/tools/ttysnoop.py
"""

__author__ = "Joe Granville"
__date__ = "20250519"
__license__ = "MIT"
__version__ = "0.1.0"
__email__ = "jwgranville@gmail.com"
__status__ = "Proof-of-concept"

from ctypes import (
    POINTER, Structure, cast, c_char, c_int, c_uint, c_ulonglong
)
import signal
import sys
import time

from bcc import BPF

EVENT_TYPES = [
    "OUTPUT",
    "INPUT"
]

class Event(Structure):
    _fields_ = [
        ("rawtime", c_ulonglong),
        ("cgid", c_ulonglong),
        ("inode", c_ulonglong),
        ("pidtgid", c_ulonglong),
        ("nsid", c_ulonglong),
        ("comm", c_char * 16),
        ("buf", c_char * 4096),
        ("len", c_uint), # Bytes, not encoded characters; change name?
        ("etype", c_int)
    ]

bpf_text = """
#include <asm/page.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/sched.h>
#include <linux/tty.h>
#include <uapi/linux/ptrace.h>

#define RINGBUF_PAGES 1 << 8

enum event_type_t {
    OUTPUT,
    INPUT
};

struct event_t {
    u64 rawtime;
    u64 cgid;
    u64 inode;
    u64 pidtgid;
    u64 nsid;
    char comm[TASK_COMM_LEN];
    char buf[PAGE_SIZE];
    u32 len;
    enum event_type_t etype;
};

BPF_RINGBUF_OUTPUT(events, RINGBUF_PAGES);

int kprobe__tty_write(
    struct pt_regs *ctx, struct kiocb *iocb, struct iov_iter *from
) {
    u64 rawtime = bpf_ktime_get_ns();
    
    if (from->iter_type != ITER_IOVEC && from->iter_type != ITER_UBUF)
        return 0;

    if (from->data_source != WRITE)
        return 0;

    const char __user *buf = NULL;
    size_t count = 0;
    
    if (from->iter_type == ITER_IOVEC) {
        struct kvec *vec = NULL;
        bpf_probe_read_kernel(&vec, sizeof(vec), &from->kvec);
        bpf_probe_read_kernel(&buf, sizeof(buf), &vec->iov_base);
        bpf_probe_read_kernel(&count, sizeof(count), &vec->iov_len);
    } else if (from->iter_type == ITER_UBUF) {
        bpf_probe_read_kernel(&buf, sizeof(buf), &from->ubuf);
        bpf_probe_read_kernel(&count, sizeof(count), &from->count);
    }
    
    if (!buf || count == 0) {
        return 0;
    }
    
    struct event_t *data = events.ringbuf_reserve(
        sizeof(struct event_t)
    );
    if (!data)
        return 0;
    
    int size = count < PAGE_SIZE - 1 ? count : PAGE_SIZE - 1;
    if (bpf_probe_read_user(&data->buf, size, buf)) {
        events.ringbuf_discard(data, 0);
        return 0;
    }
    if (size < PAGE_SIZE)
        data->buf[size] = 0;
        
    struct task_struct *task = (struct task_struct *)
                               (bpf_get_current_task());
    struct nsproxy *ns = NULL;
    bpf_probe_read_kernel(&ns, sizeof(ns), &task->nsproxy);

    struct pid_namespace *pidns = NULL;
    bpf_probe_read_kernel(
        &pidns, sizeof(pidns), &ns->pid_ns_for_children
    );

    bpf_probe_read_kernel(
        &data->nsid, sizeof(data->nsid), &pidns->ns.inum
    );
    
    data->rawtime = rawtime;
    data->cgid = bpf_get_current_cgroup_id();
    data->inode = iocb->ki_filp->f_inode->i_ino;
    data->pidtgid = bpf_get_current_pid_tgid();
    data->etype = INPUT;
    bpf_get_current_comm(&data->comm, TASK_COMM_LEN);
    data->len = size;

    events.ringbuf_submit(data, 0);
    return 0;
}

int kprobe__n_tty_receive_buf_common(
    struct pt_regs *ctx,
    struct tty_struct *tty,
    const unsigned char *cp,
    char *fp,
    int count
) {    
    u64 rawtime = bpf_ktime_get_ns();
    
    if (cp == 0) {
        return 0;
    }
    
    struct event_t *data = events.ringbuf_reserve(
        sizeof(struct event_t)
    );
    if (!data)
        return 0;
    
    int size = count < PAGE_SIZE - 1 ? count : PAGE_SIZE - 1;
    if (bpf_probe_read_kernel(&data->buf, size, cp)) {
        events.ringbuf_discard(data, 0);
        return 0;
    }
    data->buf[size] = 0;
    
    struct inode *ino = NULL;
        
    if (tty && tty->driver_data) {
        struct file *f = (struct file *)tty->driver_data;
        if (f)
            ino = f->f_inode;
    }
    
    struct task_struct *task = (struct task_struct *)
                               (bpf_get_current_task());
    struct nsproxy *ns = NULL;
    bpf_probe_read_kernel(&ns, sizeof(ns), &task->nsproxy);

    struct pid_namespace *pidns = NULL;
    bpf_probe_read_kernel(
        &pidns, sizeof(pidns), &ns->pid_ns_for_children
    );

    bpf_probe_read_kernel(
        &data->nsid, sizeof(data->nsid), &pidns->ns.inum
    );
    
    data->rawtime = rawtime;
    data->cgid = bpf_get_current_cgroup_id();
    data->inode = ino ? ino->i_ino : 0;
    data->pidtgid = bpf_get_current_pid_tgid();
    data->etype = OUTPUT;
    bpf_get_current_comm(&data->comm, TASK_COMM_LEN);
    data->len = size;

    events.ringbuf_submit(data, 0);
    return 0;
}
"""

def printevent(event, currenttime):
    print(
        "<"
        f"{EVENT_TYPES[event.etype]} "
        f"pid={event.pidtgid >> 32} "
        f"tid={event.pidtgid & 0xFFFFFFFF} "
        f"time={currenttime} "
        f"rawtime={event.rawtime} "
        f"cgid={event.cgid} "
        f"inode={event.inode} "
        f"pidtgid={event.pidtgid} "
        f"nsid={event.nsid} "
        f"comm={event.comm} "
        f"len={event.len}"
        ">"
    )
    print(repr(event.buf[:event.len]))
    sys.stdout.flush()

def calculateclockoffset():
    wallclocktime = time.time_ns()
    monotonictime = time.monotonic_ns()
    return wallclocktime - monotonictime, wallclocktime

UPDATE_INTERVAL = 6e10
DRIFT_THRESHOLD = 1e6

def calibratetimefactory():
    clockoffset, lastupdate = calculateclockoffset()
    def calibratetime(rawtime, wallclocktime):
        nonlocal clockoffset, lastupdate
        calibratedtime = rawtime + clockoffset
        drift = abs(wallclocktime - calibratedtime)
        if (wallclocktime > lastupdate + UPDATE_INTERVAL or
            drift > DRIFT_THRESHOLD):
            clockoffset, lastupdate = calculateclockoffset()
        return calibratedtime
    return calibratetime

if __name__ == "__main__":            
    calibratetime = calibratetimefactory()
    
    running = True
        
    def handleevent(cpu, data, size):
        global running
        try:
            if running:
                wallclocktime = time.time_ns()
                event = cast(data, POINTER(Event)).contents
                rawtime = event.rawtime
                currenttime = calibratetime(rawtime, wallclocktime)
                printevent(event, currenttime)
        except KeyboardInterrupt:
            running = False
    
    def handleinterrupt(sig, frame):
        global running
        running = False
        
    signal.signal(signal.SIGINT, handleinterrupt)
    signal.signal(signal.SIGTERM, handleinterrupt)
    
    b = BPF(text=bpf_text)
    
    b["events"].open_ring_buffer(handleevent)
    
    while running:
        try:
            b.ring_buffer_poll()
        except KeyboardInterrupt:
            running = False

"""
In an ordinary, non-virtualized server, what is a typical worst-case
workload for tty_write and n_tty_receive_buf_common? How many users? How
much automatic activity? At 100+ users @ 10-100 calls/sec, can we keep
up? What is the optimal size for the output buffer?

Add a starting message to indicate when the process is ready to capture
TTY events, after the probe has successfully compiled and attached

Add a blacklist; blacklist the calling Python process by default to
sever feedback loop

Would it be better to have a single spool process serving all BPF
probes, or dedicated spools for each conceptually related task? Are
there performance impacts to sharing or separating the output buffer?

Change printevent - encapsulate the serialization of the recorded and
computed attributes
"""