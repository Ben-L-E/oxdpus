/*
 * Copyright (c) Sematext Group, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 */

#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

#ifdef asm_volatile_goto
#undef asm_volatile_goto
#endif
#define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/types.h>
#include "maps.h"

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

/* helper functions called from eBPF programs */
static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
	        (void *) BPF_FUNC_trace_printk;

/* macro for printing debug info to the tracing pipe, useful just for
 debugging purposes and not recommended to use in production systems.

 use `sudo cat /sys/kernel/debug/tracing/trace_pipe` to read debug info.
 */
#define printt(fmt, ...)                                                   \
            ({                                                             \
                char ____fmt[] = fmt;                                      \
                bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
            })

SEC("xdp/xdp_ip_filter")
int xdp_ip_filter(struct xdp_md *ctx) {
    void *end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    u32 ip_src;
    u64 offset;
    u16 eth_type;

    struct ethhdr *eth = data;
    offset = sizeof(*eth);

    if (data + offset > end) {
        return XDP_ABORTED;
    }
    eth_type = eth->h_proto;

    /* handle VLAN tagged packet */
    if (eth_type == htons(ETH_P_8021Q) || eth_type == htons(ETH_P_8021AD)) {
	struct vlan_hdr *vlan_hdr;

	vlan_hdr = (void *)eth + offset;
	offset += sizeof(*vlan_hdr);
	if ((void *)eth + offset > end)
		return false;
	eth_type = vlan_hdr->h_vlan_encapsulated_proto; 
   }

    /* let's only handle IPv4 addresses */
    if (eth_type == ntohs(ETH_P_IPV6)) {
        return XDP_PASS;
    }

    struct iphdr *iph = data + offset;
    offset += sizeof(struct iphdr);
    /* make sure the bytes you want to read are within the packet's range before reading them */
    if (iph + 1 > end) {
        return XDP_ABORTED;
    }
    ip_src = iph->saddr;

    if (bpf_map_lookup_elem(&blacklist1, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist2, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist3, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist4, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist5, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist6, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist7, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist8, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist9, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist10, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist11, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist12, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist13, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist14, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist15, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist16, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist17, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist18, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist19, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist20, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist21, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist22, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist23, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist24, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist25, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist26, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist27, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist28, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist29, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist30, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist31, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist32, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist33, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist34, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist35, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist36, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist37, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist38, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist39, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist40, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist41, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist42, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist43, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist44, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist45, &ip_src)) {
        return XDP_DROP;
    }
    else if (bpf_map_lookup_elem(&blacklist46, &ip_src)) {
        return XDP_DROP;
    }
    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
