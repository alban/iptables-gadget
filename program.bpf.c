// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 The Inspektor Gadget authors */

#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#define GADGET_TYPE_TRACING
#include <gadget/sockets-map.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

// Defined in:
// https://github.com/torvalds/linux/blob/v6.6/include/uapi/linux/if.h#L33
#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

// Defined in:
// https://github.com/torvalds/linux/blob/v6.6/include/uapi/linux/netfilter/nf_tables.h#L5

#ifndef NFT_NAME_MAXLEN
#define NFT_NAME_MAXLEN 256
#define NFT_TABLE_MAXNAMELEN NFT_NAME_MAXLEN
#define NFT_CHAIN_MAXNAMELEN NFT_NAME_MAXLEN
#endif

#define NFT_COMMENT_MAXNAMELEN NFT_NAME_MAXLEN

struct event {
  gadget_timestamp timestamp;
  __u32 pid;
  __u8 comm[TASK_COMM_LEN];

  char ifname_in[IFNAMSIZ];
  char ifname_out[IFNAMSIZ];
  char tablename[NFT_TABLE_MAXNAMELEN];
  char chainname[NFT_CHAIN_MAXNAMELEN];
  char comment[NFT_COMMENT_MAXNAMELEN];
  long long unsigned int netns_in;
  long long unsigned int netns_out;
  long long unsigned int rulenum;
  int ifindex_in;
  int ifindex_out;
};

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(iptables_gadget, events, event);

// bpf/bpf_tracing.h only defines PT_REGS_PARMx up to 5.
#ifndef PT_REGS_PARM6
#if defined(bpf_target_x86)
#define PT_REGS_PARM6(x) ((x)->r9)
#elif defined(bpf_target_arm64)
#define PT_REGS_PARM5(x) (((PT_REGS_ARM64 *)(x))->regs[5])
#else
#error "Please define PT_REGS_PARM6 for your architecture"
#endif
#endif

// nf_log_trace prototype:
// https://github.com/torvalds/linux/blob/v6.6/net/netfilter/nf_log.c#L234
//
// 	void nf_log_trace(struct net *net,			// arg1
//			  u_int8_t pf,				// arg2
//			  unsigned int hooknum,			// arg3
//			  const struct sk_buff *skb,		// arg4
//			  const struct net_device *in,		// arg5
//			  const struct net_device *out,		// arg6
//			  const struct nf_loginfo *loginfo,	// arg7
//			  const char *fmt,			// arg8
//			  ...)
//
// nf_log_trace calls:
// https://github.com/torvalds/linux/blob/v6.6/net/ipv4/netfilter/ip_tables.c#L209
//
//	nf_log_trace(net, AF_INET, hook, skb, in, out, &trace_loginfo,
//		     "TRACE: %s:%s:%s:%u ",			// arg8
//		     tablename,					// arg9
//		     chainname,					// arg10
//		     comment,					// arg11
//		     rulenum);					// arg12
//
// tablename:
// chainname: "PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"
// comment: "rule", "return", "policy"
// rulenum: index
SEC("kprobe/nf_log_trace")
int kprobe_nf_log_trace(struct pt_regs *ctx) {
  struct net *net = (struct net *)PT_REGS_PARM1(ctx);
  u_int8_t pf = PT_REGS_PARM2(ctx);
  unsigned int hooknum = PT_REGS_PARM3(ctx);
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM4(ctx);
  struct net_device *in = (struct net_device *)PT_REGS_PARM5(ctx);
  struct net_device *out = (struct net_device *)PT_REGS_PARM6(ctx);
  char **tablename_ptr = (char **)((char *)(PT_REGS_SP(ctx)) + 24);
  char *tablename;
  char **chainname_ptr = (char **)((char *)(PT_REGS_SP(ctx)) + 32);
  char *chainname;
  char **comment_ptr = (char **)((char *)(PT_REGS_SP(ctx)) + 40);
  char *comment;
  unsigned int *rulenum_ptr = (unsigned int *)((char *)PT_REGS_SP(ctx) + 48);
  unsigned int rulenum;
  struct event *event;
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u8 comm[TASK_COMM_LEN];
  int ret;

  event = gadget_reserve_buf(&events, sizeof(*event));
  if (!event)
    return 0;

  /* common event data */
  event->timestamp = bpf_ktime_get_boot_ns();
  event->pid = pid_tgid >> 32;
  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  /* nf_log_trace event data */

  if (in != 0) {
    event->netns_in = BPF_CORE_READ(in, nd_net.net, ns.inum);
    event->ifindex_in = BPF_CORE_READ(in, ifindex);
    bpf_probe_read_kernel(&event->ifname_in, IFNAMSIZ, in->name);
  }

  if (out != 0) {
    event->netns_out = BPF_CORE_READ(out, nd_net.net, ns.inum);
    event->ifindex_out = BPF_CORE_READ(out, ifindex);
    bpf_probe_read_kernel(&event->ifname_out, IFNAMSIZ, out->name);
  }

  bpf_probe_read_kernel(&tablename, sizeof(void *), tablename_ptr);
  bpf_probe_read_kernel_str(&event->tablename, NFT_TABLE_MAXNAMELEN, tablename);

  bpf_probe_read_kernel(&chainname, sizeof(void *), chainname_ptr);
  bpf_probe_read_kernel_str(&event->chainname, NFT_CHAIN_MAXNAMELEN, chainname);

  bpf_probe_read_kernel(&comment, sizeof(void *), comment_ptr);
  bpf_probe_read_kernel_str(&event->comment, NFT_COMMENT_MAXNAMELEN, comment);

  bpf_probe_read_kernel(&event->rulenum, sizeof(long long unsigned int),
                        rulenum_ptr);

  /* emit event */
  gadget_submit_buf(ctx, &events, event, sizeof(*event));

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
