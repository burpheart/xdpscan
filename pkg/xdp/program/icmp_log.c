// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>


// 定义 ring buffer (linux 5.7+)  or perf buffer ，最大容量可以根据需求调整
/*
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16MB 的 ring buffer
} ringbuf SEC(".maps");
*/


// 低版本内核使用 perf buffer
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1);  // 1核 CPU 的 perf buffer
} perf_map SEC(".maps");



// ICMP 协议号
#define IPPROTO_ICMP 1

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 仅处理 IPv4 包
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // 仅处理 ICMP 包 (协议号 1)
    if (ip->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    // 将源 IP 地址写入 ring buffer
    __u32 src_ip = ip->saddr;
    //void *ringbuf_entry = bpf_ringbuf_reserve(&ringbuf, sizeof(src_ip), 0);
    //if (!ringbuf_entry)
    //    return XDP_PASS;  // 如果 ring buffer 已满，继续处理其他包
    // 将数据写入 ring buffer
    //__builtin_memcpy(ringbuf_entry, &src_ip, sizeof(src_ip));
    //bpf_ringbuf_submit(ringbuf_entry, 0);
    bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU, &src_ip, sizeof(src_ip));

    return XDP_PASS;  // 继续传递数据包 也可以丢弃?
}

char _license[] SEC("license") = "GPL";
