#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/skbuff.h>

#ifndef IPPROTO_L2TP
#define IPPROTO_L2TP 115
#endif

// Accurate L2TP detection function (Advanced DPI)
static bool is_l2tp_packet(struct sk_buff *skb)
{
    struct iphdr *iph;
    struct udphdr _udph, *udph;
    uint16_t l2tp_flags_ver;
    int ip_hl;
    int payload_offset;
    int payload_len;
    uint8_t version;
    bool is_control, has_length, has_seq;
    uint16_t sport, dport;

    if (!skb) return false;

    iph = ip_hdr(skb);
    if (!iph) return false;

    ip_hl = iph->ihl * 4;

    // 1. Direct L2TP over IP (Protocol 115)
    if (iph->protocol == IPPROTO_L2TP) {
        return true;
    }

    // 2. L2TP over UDP (Deep Packet Inspection)
    if (iph->protocol == IPPROTO_UDP) {
        udph = skb_header_pointer(skb, ip_hl, sizeof(_udph), &_udph);
        if (!udph) return false;

        sport = ntohs(udph->source);
        dport = ntohs(udph->dest);

        payload_offset = ip_hl + sizeof(struct udphdr);
        payload_len = ntohs(udph->len) - sizeof(struct udphdr);

        // L2TP payload must be at least 6 bytes in its smallest form
        // (2 bytes flags + 2 bytes TunnelID + 2 bytes SessionID)
        if (payload_len < 6) return false;

        // Copy the first 2 bytes of the payload (Flags and Version)
        if (skb_copy_bits(skb, payload_offset, &l2tp_flags_ver, 2) < 0) return false;

        l2tp_flags_ver = ntohs(l2tp_flags_ver);

        // Extract Version (must be 2 or 3)
        version = l2tp_flags_ver & 0x000F;
        if (version != 2 && version != 3) return false;

        // Reserved bits check: bits 2, 3, 5, 8, 9, 10, 11 must be 0
        if (l2tp_flags_ver & 0x34F0) return false;

        // Extract key flags
        is_control = (l2tp_flags_ver & 0x8000) != 0; // T bit
        has_length = (l2tp_flags_ver & 0x4000) != 0; // L bit
        has_seq    = (l2tp_flags_ver & 0x0800) != 0; // S bit

        // Control messages must have Length and Sequence bits set
        if (is_control && (!has_length || !has_seq)) return false;

        // --- Advanced DPI checks to prevent False Positives ---
        if (has_length) {
            uint16_t l2tp_len;
            // If Length bit is set, the next 2 bytes indicate the total L2TP length
            if (skb_copy_bits(skb, payload_offset + 2, &l2tp_len, 2) < 0) return false;

            l2tp_len = ntohs(l2tp_len);
            // The inner L2TP length must match the UDP payload length exactly
            if (l2tp_len != payload_len) return false;
        }

        return true;
    }

    return false;
}

// Netfilter Hook Function
static unsigned int l2tp_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    if (is_l2tp_packet(skb)) {
        struct iphdr *iph = ip_hdr(skb);

        // Differentiate log based on encapsulation type
        if (iph->protocol == IPPROTO_L2TP) {
            // L2TP over IP (Protocol 115)
            pr_info("L2TP (IP Encapsulated) Detected! SRC: %pI4, DST: %pI4\n",
                    &iph->saddr, &iph->daddr);

        } else if (iph->protocol == IPPROTO_UDP) {
            // L2TP over UDP (Port 1701 or custom)
            struct udphdr _udph, *udph;
            uint16_t port = 0;

            udph = skb_header_pointer(skb, iph->ihl * 4, sizeof(_udph), &_udph);
            if (udph) port = ntohs(udph->dest);

            pr_info("L2TP (UDP Encapsulated) Detected! SRC: %pI4, DST: %pI4, UDP_PORT: %u\n",
                    &iph->saddr, &iph->daddr, port);
        }
    }
    return NF_ACCEPT;
}

static struct nf_hook_ops nfho = {
    .hook       = l2tp_hook_func,
    .hooknum    = NF_INET_PRE_ROUTING,
    .pf         = PF_INET,
    .priority   = NF_IP_PRI_FIRST,
};

static int __init l2tp_detector_init(void) {
    return nf_register_net_hook(&init_net, &nfho);
}

static void __exit l2tp_detector_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
}

module_init(l2tp_detector_init);
module_exit(l2tp_detector_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Custom L2TP DPI Module");
MODULE_DESCRIPTION("Detects both UDP-encapsulated and IP-encapsulated L2TP traffic");
