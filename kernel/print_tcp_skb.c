static char *_c2str[16]= {
		"INV",
		"EXPECTED",
		"SEEN_REPLY",
		"ASSURED",
		"CONFRM",
		"SRCNAT",
		"DSTNAT",
		"SEQADJ",
		"SRCNATDONE",
		"DSTNATDONE",
		"DYING",
		"FIX_TMO",
		"TEMPLATE",
		"UNTRACK",
		"HELPER" };

static char *ctinfo2str(enum ip_conntrack_info ctinfo,char *buf,size_t len) {
int i,l=0;
*buf = 0;
for(i=IPS_EXPECTED_BIT; i <= IPS_HELPER_BIT; i++) {
	if(l < len && (ctinfo & (1 << i))) {
		l += snprintf(&buf[l],len - l,"%s%s",l?",":"",_c2str[i]);
	}
}
return buf;
}

static void print_tcp_tupple(const char *msg,const struct nf_conntrack_tuple *t) {
        printk("  tuple %s %u %pI4:%hu -> %pI4:%hu\n",
               msg, t->dst.protonum,
               &t->src.u3.ip, ntohs(t->src.u.all),
               &t->dst.u3.ip, ntohs(t->dst.u.all));
}

static void print_skb(char *msg,int num,const struct sk_buff *skb) {
	struct tcphdr *tcp, tcp_buf;
	struct iphdr *ip;
	enum ip_conntrack_info ctinfo = 0;
	struct nf_conn * ct;
	char cbuf[128];

	ip  = ip_hdr(skb);
	tcp = skb_header_pointer(skb, ip->ihl*4,
		 sizeof(*tcp), &tcp_buf);
	ct = nf_ct_get (skb, &ctinfo);
	if(!ip || !tcp) {
		printk("%s:%d invalid skb\n",msg,num);
		return;
	}
	if(ip->protocol != IPPROTO_TCP) {
		printk("%s:%d not TCP skb\n",msg,num);
		return;
	}
	printk("%s %u %pI4:%u->%pI4:%u len %u",msg, ip->protocol,
			&ip->saddr,htons(tcp->source),
			&ip->daddr,htons(tcp->dest),
			htons(ip->tot_len));
	printk(" skb nfct %d ",skb->nfct ? 1:0);
	if(ct) {
		printk("\n  %s ct.status %s ctinfo %x\n",
				(ctinfo) >= IP_CT_IS_REPLY ? "REV":"DIR",
				ctinfo2str(ct->status,cbuf,sizeof(cbuf)),ctinfo);
		print_tcp_tupple("N ",&ct->tuplehash[0].tuple);
		print_tcp_tupple("R ",&ct->tuplehash[1].tuple);
	} else 
		printk(" NO CT\n");
	
}
