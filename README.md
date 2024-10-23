## Benchmarking memaslap-memcached like this

```cmake
(client)               taskset 0xFF memaslap -s 192.168.200.1 -c 512 -T 8 -n 1 -w 600k -t 120s --stat_freq 10s | sed -r "s/\x1B\[[0-9;]*[a-zA-Z]//g" > memaslap_vanilla.txt

(client)               taskset 0xFF memaslap -s 192.168.200.1 -c 512 -T 8 -n 1 -w 600k -t 120s --stat_freq 10s | sed -r "s/\x1B\[[0-9;]*[a-zA-Z]//g" > memaslap_vanilla_bpf_attach.txt

(client)           taskset 0xFF memaslap -s 192.168.200.1 -c 512 -T 8 -n 1 -w 600k -t 120s --stat_freq 10s | sed -r "s/\x1B\[[0-9;]*[a-zA-Z]//g" > memaslap_absorb.txt

(server)            taskset 0xFF memcached -t 8 -m 42000 -l 0.0.0.0
```

## I modifed absorb kernel in only this place 

```cmake
#include <linux/if_ether.h>  // For Ethernet header structure
#include <linux/ip.h>        // For IP header structure
#include <linux/netfilter.h> // For BPF_OK and error handling


static inline int absorb_bpf_tc_ingress(struct sk_buff *skb) {
	// Set up pointers to the start and end of the data
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)(skb->data + skb->len); // Calculate the end of the data

	// Check for invalid Ethernet header and drop the packet
	if (data + sizeof(struct ethhdr) > data_end) {
		return -1; // Drop packet
	}

	struct ethhdr *eth = data;

	// If not IPv4, continue processing
	if (eth->h_proto != __constant_htons(ETH_P_IP)) {
		return 0; // Continue processing
	}

	// Check for invalid IP header
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
		return -1; // Drop packet
	}

	struct iphdr *ip = (struct iphdr *)(data + sizeof(struct ethhdr));
	__be32 src_ip = ip->saddr; // Get source IP

	// Accept packets from 192.168.100.10
	if (src_ip == __constant_htonl(0xC0A8640A)) {
		return 0; // ACCEPT packet
	}

	return 0; // ACCEPT packet
}

TC_INDIRECT_SCOPE int cls_bpf_classify(struct sk_buff *skb,
				       const struct tcf_proto *tp,
				       struct tcf_result *res)
{
	struct cls_bpf_head *head = rcu_dereference_bh(tp->root);
	bool at_ingress = skb_at_tc_ingress(skb);
	struct cls_bpf_prog *prog;
	int ret = -1;

	list_for_each_entry_rcu(prog, &head->plist, link) {
		int filter_res;

		qdisc_skb_cb(skb)->tc_classid = prog->res.classid;

		if (tc_skip_sw(prog->gen_flags)) {
			filter_res = prog->exts_integrated ? TC_ACT_UNSPEC : 0;
		} else if (at_ingress) {
			/* It is safe to push/pull even if skb_shared() */
			__skb_push(skb, skb->mac_len);
			bpf_compute_data_pointers(skb);
//			filter_res = bpf_prog_run(prog->filter, skb);
			filter_res = absorb_bpf_tc_ingress(skb);
			__skb_pull(skb, skb->mac_len);
		} else {
			bpf_compute_data_pointers(skb);
			filter_res = bpf_prog_run(prog->filter, skb);
		}
		if (unlikely(!skb->tstamp && skb->mono_delivery_time))
			skb->mono_delivery_time = 0;

		if (prog->exts_integrated) {
			res->class   = 0;
			res->classid = TC_H_MAJ(prog->res.classid) |
				       qdisc_skb_cb(skb)->tc_classid;

			ret = cls_bpf_exec_opcode(filter_res);
			if (ret == TC_ACT_UNSPEC)
				continue;
			break;
		}

		if (filter_res == 0)
			continue;
		if (filter_res != -1) {
			res->class   = 0;
			res->classid = filter_res;
		} else {
			*res = prog->res;
		}

		ret = tcf_exts_exec(skb, &prog->exts, res);
		if (ret < 0)
			continue;

		break;
	}

	return ret;
}
```


Note: I think these results are real results. But my bpf program is super small, and they numbers I am getting are almost same. But everytime the vanilla vs vanill-bpf, there is more overhead in vanilla-bpf. But for the kernel-absorb case, sometimes, I get slightly better result sometimes slightly worse than them.
