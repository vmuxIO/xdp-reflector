#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
/* Reflect ethernet frames back to the sender */
int xdp_reflector(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end)
        return XDP_DROP;

    __u8 our_mac[ETH_ALEN] = OUR_MAC;
    if (__builtin_memcmp(eth->h_dest, our_mac, ETH_ALEN) == 0) {
        // packet is for us. Let it pass.
        return XDP_PASS; // TODO
    }

    // packet is for someone else. Send it back into the network.
    return XDP_TX;
}

char _license[] SEC("license") = "MIT";
