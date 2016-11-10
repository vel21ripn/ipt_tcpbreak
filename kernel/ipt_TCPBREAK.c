/*
 *	"TCPBREAK" (RFC 862) target extension for Xtables
 *	Sample module for "Writing your own Netfilter Modules"
 *	Copyright © Jan Engelhardt, 2008-2011
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License; either
 *	version 2 of the License, or any later version, as published by the
 *	Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/route.h>
#include "ipt_TCPBREAK.h"

#if 0
#include "print_tcp_skb.c"
#endif

static inline struct net *par_net(const struct xt_action_param *par)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
        return par->net;
#else
        return dev_net((par->in != NULL) ? par->in : par->out);
#endif
}

/* 
 * ip_local_out with nf_hook NF_INET_POST_ROUTING
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)

static int ip_output2(struct sk_buff *skb)
{
        int err;
        struct iphdr *iph = ip_hdr(skb);

        iph->tot_len = htons(skb->len);
        ip_send_check(iph);
        err = nf_hook(NFPROTO_IPV4, NF_INET_POST_ROUTING,
			skb, NULL, skb_dst(skb)->dev,
			dst_output);
	if (likely(err == 1))
		err = dst_output(skb);

	return err;
}
#else
static int ip_output2(struct net *net, struct sk_buff *skb)
{
        int err;
        struct iphdr *iph = ip_hdr(skb);

        iph->tot_len = htons(skb->len);
        ip_send_check(iph);
        err = nf_hook(NFPROTO_IPV4, NF_INET_POST_ROUTING,
			net, NULL, skb, NULL, skb_dst(skb)->dev,
			dst_output);
	if (likely(err == 1))
		err = dst_output(net, NULL, skb);

	return err;
}
#endif
/*
 * copy nf_conntrack_attach
 */

static void nf_ct_attach2(struct sk_buff *nskb, const struct sk_buff *skb,int rev)
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;

	ct = nf_ct_get(skb, &ctinfo);
	ctinfo = (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) ^ rev ?
			IP_CT_RELATED_REPLY : IP_CT_RELATED;

	nskb->nfct = &ct->ct_general;
	nskb->nfctinfo = ctinfo;
	nf_conntrack_get(nskb->nfct);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
#define	NF_SEND_RESET(par, oldskb, hook, rev) nf_send_reset(oldskb, hook, rev)
#define IP_ROUTE_ME_HARDER(par,skb,atype) ip_route_me_harder(skb, atype)
#define IP_LOCAL_OUT(par, newskb) ip_local_out( newskb) 
#define IP_OUTPUT(par, newskb) ip_output2( newskb) 
#else
#define	NF_SEND_RESET(par, oldskb, hook, rev) nf_send_reset(par_net(par), oldskb, hook, rev)
#define IP_ROUTE_ME_HARDER(par,skb,atype) ip_route_me_harder(par_net(par), skb, atype)
#define IP_LOCAL_OUT(par, newskb) ip_local_out(par_net(par), newskb->sk, newskb) 
#define IP_OUTPUT(par, newskb) ip_output2(par_net(par), newskb) 
#endif

#define F_TCP_ACK 1
#define F_TCP_RST 2

#define XT_STATE_BIT(ctinfo) (1 << ((ctinfo)%IP_CT_IS_REPLY+1))
#define XT_STATE_INVALID (1 << 0)
#define XT_STATE_UNTRACKED (1 << (IP_CT_NUMBER + 1))
#define IS_ESTABLISHED (XT_STATE_BIT(IP_CT_ESTABLISHED))

static struct sk_buff *send_tcpv4_packet(struct sk_buff *oldskb,
		struct iphdr  *oldip,struct tcphdr *oldtcp,
		const struct xt_action_param *par, int rev,
		int id, int seq, int a_seq, u8 tflag, char *msgbuf, size_t msglen)
{
	struct sk_buff *newskb= NULL;
	struct iphdr  *newip;
	struct tcphdr *newtcp;

	newskb = alloc_skb(LL_MAX_HEADER + sizeof(struct iphdr) + 
			sizeof(struct tcphdr) + msglen , GFP_ATOMIC);

	if (newskb == NULL)
			return NULL;

	skb_reserve(newskb, LL_MAX_HEADER);
	newskb->protocol = IPPROTO_TCP;

	nf_reset(newskb);
	skb_init_secmark(newskb);
	skb_shinfo(newskb)->gso_size = 0;
	skb_shinfo(newskb)->gso_segs = 0;
	skb_shinfo(newskb)->gso_type = 0;

	skb_reset_network_header(newskb);
	newip = (void *)skb_put(newskb, sizeof(*newip));

	skb_reset_transport_header(newskb);
	newtcp = (void *)skb_put(newskb, sizeof(*newtcp));

	memset(newtcp,0,sizeof(struct tcphdr));

	newip->version  = oldip->version;
	newip->ihl      = sizeof(*newip) / 4;
	newip->tos      = oldip->tos;
	newip->id       = htons(id);
	newip->frag_off = htons(IP_DF);
	newip->protocol = oldip->protocol;
	newip->check    = 0;
	newip->tot_len  = htons(newskb->len);
	newtcp->doff   = sizeof(struct tcphdr) / 4;
	if (rev) {
		newip->saddr    = oldip->daddr;
		newip->daddr    = oldip->saddr;
		newtcp->source = oldtcp->dest;
		newtcp->dest   = oldtcp->source;
	} else {
		newip->saddr    = oldip->saddr;
		newip->daddr    = oldip->daddr;
		newtcp->source = oldtcp->source;
		newtcp->dest   = oldtcp->dest;
	}

	newtcp->seq      = seq;
	newtcp->ack_seq  = a_seq;
	newtcp->ack	 = (tflag & F_TCP_ACK) != 0 ;
	newtcp->rst	 = (tflag & F_TCP_RST) != 0 ;

	newskb->ip_summed = CHECKSUM_NONE;
	newskb->csum_start = (unsigned char *)newtcp - newskb->head;
	newskb->csum_offset = offsetof(struct tcphdr, check);

	memcpy(skb_put(newskb, msglen), msgbuf, msglen);

	newtcp->check = 0;
	newskb->csum = csum_partial(newtcp, sizeof(*newtcp) + msglen , 0);
	newtcp->check = tcp_v4_check(sizeof(struct tcphdr)+msglen,
			newip->saddr, newip->daddr, newskb->csum);

	if (IP_ROUTE_ME_HARDER(par, newskb, 
		par->hooknum == NF_INET_FORWARD ? RTN_UNSPEC:RTN_UNSPEC) != 0) {
		skb_dst_drop(newskb);
		kfree_skb(newskb);
		return NULL;
	}

	newip->ttl = ip4_dst_hoplimit(skb_dst(newskb));

	if (newskb->len > dst_mtu(skb_dst(newskb))) {
		skb_dst_drop(newskb);
		kfree_skb(newskb);
		return NULL;
	}
	nf_ct_attach2(newskb,oldskb,rev);
//	newskb->nf_trace = 1;
	if (par->hooknum == NF_INET_FORWARD) {
		IP_OUTPUT(par, newskb);
	} else {
		IP_LOCAL_OUT(par, newskb);
	}
	return newskb;
}

static unsigned int
tcpbreak_tg4(struct sk_buff *oldskb, const struct xt_action_param *par)
{
	const struct xt_tcpbreak_tgt *info = par->targinfo;
	struct tcphdr *oldtcp, oldtcp_buf;
	struct iphdr *oldip, oldip_buf;
	unsigned int data_len,old_len, save_seq, save_ack_seq, save_id;
	enum ip_conntrack_info ctinfo;
	struct nf_conn * ct;
	unsigned int statebit;
	char rep[1200];

	ct = nf_ct_get (oldskb, &ctinfo);

	statebit = ct ? (nf_ct_is_untracked(ct) ?
				XT_STATE_UNTRACKED:XT_STATE_BIT(ctinfo)) :
			XT_STATE_INVALID ;

	if (!(statebit & IS_ESTABLISHED) ||
			ct->proto.tcp.state != TCP_CONNTRACK_ESTABLISHED) {
		return NF_DROP;
	}

	oldip  = ip_hdr(oldskb);
	oldtcp = skb_header_pointer(oldskb, par->thoff,
		 sizeof(*oldtcp), &oldtcp_buf);

	if (oldtcp == NULL || 
	    ntohs(oldip->tot_len) <= sizeof(*oldtcp) ||
	    oldtcp->rst || oldtcp->syn || !oldtcp->ack)
		return NF_DROP;

	/* save headers L3 and L4 */
	memcpy(&oldip_buf,oldip,sizeof(oldip_buf));
	memcpy(&oldtcp_buf,oldtcp,sizeof(oldtcp_buf));
	save_seq = oldtcp->seq;
	save_ack_seq = oldtcp->ack_seq;
	save_id = htons(oldip->id);

	switch(info->mode) {
	  case 'L':
		data_len = snprintf(rep,sizeof rep,
				"HTTP/1.0 302 Moved\r\nLocation: %s\r\n\r\n",
				info->location);
		break;
	  case 'R':
		data_len = strlen(info->location);
		if (data_len > sizeof rep) data_len = sizeof rep;
		strncpy(rep,info->location,data_len);
		break;
	  default:
		data_len = 0;
	}

	old_len = oldskb->len - oldip->ihl*4 - oldtcp->doff * 4;

	send_tcpv4_packet(oldskb, &oldip_buf, &oldtcp_buf, par, 0,
			save_id + 1, save_seq, 0, F_TCP_RST, rep, 0);
	if (data_len)
		send_tcpv4_packet(oldskb, &oldip_buf, &oldtcp_buf, par, 1,
			save_id + 1, save_ack_seq, 
			htonl(ntohl(save_seq)+old_len),
			F_TCP_ACK, rep, data_len);

	send_tcpv4_packet(oldskb, &oldip_buf, &oldtcp_buf, par, 1,
			save_id + 1, htonl(ntohl(save_ack_seq)+data_len), 
			htonl(ntohl(save_seq)+old_len),
			F_TCP_RST, rep, 0);

	if(timer_pending(&ct->timeout)) {
		unsigned long newtime = jiffies + 15*HZ;
		if (newtime - ct->timeout.expires >= HZ)
			mod_timer_pending(&ct->timeout, newtime);
	}
	ct->proto.tcp.state = TCP_CONNTRACK_CLOSE;
	
	return NF_DROP;
}

static struct xt_target tcpbreak_tg_reg[] __read_mostly = {
	{
		.name       = "TCPBREAK",
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.proto      = IPPROTO_TCP,
		.targetsize = sizeof(struct xt_tcpbreak_tgt),
		.hooks          = (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_FORWARD),
		.table      = "filter",
		.target     = tcpbreak_tg4,
		.me         = THIS_MODULE,
	},
};

static int __init tcpbreak_tg_init(void)
{
	return xt_register_targets(tcpbreak_tg_reg, ARRAY_SIZE(tcpbreak_tg_reg));
}

static void __exit tcpbreak_tg_exit(void)
{
	return xt_unregister_targets(tcpbreak_tg_reg, ARRAY_SIZE(tcpbreak_tg_reg));
}

module_init(tcpbreak_tg_init);
module_exit(tcpbreak_tg_exit);
MODULE_AUTHOR("Vitaly Lavrov");
MODULE_DESCRIPTION("Xtables: TCP RESET response");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_TCPBREAK");
