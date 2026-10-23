#!/usr/bin/env python3
"""Split perf-script samples of the proxy under the write syscalls.

Usage: writev_split.py perf-script.txt.gz [...]
Each sample whose stack holds a write-side syscall (writev, write, sendto,
sendmsg) is put in one bucket: the leaf-most frame that matches a bucket wins,
so a sample spent in conntrack under ip_rcv counts as netfilter. Prints the
buckets as percent of all proxy samples and of write-syscall samples.
"""
import gzip, re, sys
from collections import Counter

WRITE = re.compile(r"__x64_sys_(writev|write|sendto|sendmsg)\b|ksys_write\b|do_writev\b")
READ = re.compile(r"__x64_sys_(recvfrom|read|readv|recvmsg)\b")
BUCKETS = [
    ("wakeup (receiver task)", r"try_to_wake_up|ttwu_|select_task_rq|enqueue_task|__wake_up_common|sock_def_readable|ep_poll_callback|ep_autoremove|resched_curr|native_send_call_func|x2apic_send_IPI|__smp_call"),
    ("netfilter/conntrack", r"nf_hook_slow|nf_conntrack|ipt_do_table|nft_do_chain|nf_nat|nf_ct_|ipv4_conntrack|iptable_"),
    ("loopback receive (peer's TCP rx)", r"tcp_v4_rcv|tcp_v4_do_rcv|tcp_rcv_established|tcp_data_queue|tcp_ack|ip_rcv|ip_local_deliver|ip_protocol_deliver|__netif_receive_skb|process_backlog|net_rx_action|tcp_event_data_recv|tcp_queue_rcv|__inet_lookup|tcp_validate_incoming"),
    ("tx: TCP/IP output + loopback xmit", r"__tcp_transmit_skb|tcp_write_xmit|__tcp_push_pending|tcp_push|ip_queue_xmit|__ip_queue_xmit|ip_output|ip_finish_output|ip_local_out|__dev_queue_xmit|dev_hard_start_xmit|loopback_xmit|__netif_rx|netif_rx|tcp_options_write|tcp_v4_send_check|tcp_rate_skb_sent|tcp_event_new_data_sent|skb_clone|tcp_schedule_loss_probe|sk_reset_timer|mod_timer"),
    ("tcp_sendmsg: copy + skb alloc", r"tcp_sendmsg|_copy_from_iter|copy_user|rep_movs|skb_page_frag_refill|tcp_stream_alloc_skb|__alloc_skb|kmem_cache_alloc|__kmalloc|sk_stream_alloc|skb_do_copy|memcpy|sk_page_frag|lock_sock|release_sock|__release_sock"),
    ("softirq glue", r"do_softirq|__local_bh_enable_ip|handle_softirqs|__do_softirq|irq_exit"),
    ("syscall entry/exit + mitigations", r"entry_SYSCALL|do_syscall_64|syscall_exit|syscall_enter|__x64_sys_|do_writev|vfs_writev|vfs_write|sock_write_iter|sock_sendmsg|__sys_sendto|import_iovec|fdget|__fget|swapgs|__x86_indirect_thunk|__x86_return_thunk|clear_bhb_loop|mds_clear|srso_|retbleed|fpregs|switch_fpu|exit_to_user_mode|arch_exit_to_user|rseq"),
]
BUCKETS = [(n, re.compile(p)) for n, p in BUCKETS]

def samples(path):
    opener = gzip.open if path.endswith(".gz") else open
    stack = []
    with opener(path, "rt", errors="replace") as fh:
        for line in fh:
            if not line.strip():
                if stack:
                    yield stack
                stack = []
            elif line[0] in " \t":
                parts = line.split(None, 1)
                if len(parts) == 2:
                    stack.append(parts[1].rsplit(" (", 1)[0].split("+0x")[0])
            # sample header lines are skipped; frames follow leaf first
    if stack:
        yield stack

for path in sys.argv[1:]:
    total = writes = reads = 0
    split = Counter()
    for frames in samples(path):
        total += 1
        joined = "\n".join(frames)
        if READ.search(joined) and not WRITE.search(joined):
            reads += 1
            continue
        if not WRITE.search(joined):
            continue
        writes += 1
        for f in frames:  # leaf first
            hit = next((n for n, rx in BUCKETS if rx.search(f)), None)
            if hit:
                split[hit] += 1
                break
        else:
            split["other kernel"] += 1
    print(f"== {path}")
    print(f"samples {total}; under write syscalls {writes} ({100*writes/max(total,1):.1f}%); under read syscalls {reads} ({100*reads/max(total,1):.1f}%)")
    for name, _ in BUCKETS + [("other kernel", None)]:
        n = split[name]
        print(f"  {name:<36} {100*n/max(total,1):5.1f}% of proxy  {100*n/max(writes,1):5.1f}% of write")
