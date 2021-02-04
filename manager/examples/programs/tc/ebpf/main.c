#include <linux/kconfig.h>
#include <linux/version.h>

#include <uapi/linux/pkt_cls.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#pragma clang diagnostic ignored "-Wframe-address"
#include <linux/netdevice.h>
#include <linux/ns_common.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <net/flow.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <uapi/linux/if.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_arp.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/icmpv6.h>
#include <linux/sctp.h>
#pragma clang diagnostic pop

#include "include/bpf.h"
#include "include/bpf_helpers.h"

// Data link layer data (L2)
struct ethernet_h_t
{
    u16 h_protocol;                   // Network layer protocol
    unsigned char h_dest[ETH_ALEN];   // Destination hardware (MAC) address
    unsigned char h_source[ETH_ALEN]; // Source hardware (MAC) address
};

/**
  * parse_l2 - Parses sk_buff to retrieve L2 data. Returns 0 on success, negative value on error.
  */
__attribute__((always_inline)) static int parse_l2(struct ethernet_h_t *h, struct __sk_buff *skb, int *offset)
{
    if (bpf_skb_load_bytes(skb, 0, &h->h_dest, ETH_ALEN) < 0)
    {
        return -1;
    }
    if (bpf_skb_load_bytes(skb, ETH_ALEN, &h->h_source, ETH_ALEN) < 0)
    {
        return -1;
    }
    if (bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), &h->h_protocol, sizeof(h->h_protocol)) < 0)
    {
        return -1;
    }

    *offset = ETH_HLEN;
    return 0;
};

SEC("classifier/egress")
int egress_cls_func(struct __sk_buff *skb)
{
    struct ethernet_h_t eth = {};
    int offset = 0;
    parse_l2(&eth, skb, &offset);
    bpf_printk("new packet captured on egress (TC) protocol: %d\n", eth.h_protocol);
    return TC_ACT_OK;
};

SEC("classifier/ingress")
int ingress_cls_func(struct __sk_buff *skb)
{
    bpf_printk("new packet captured on ingress (TC)\n");
    return TC_ACT_OK;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
