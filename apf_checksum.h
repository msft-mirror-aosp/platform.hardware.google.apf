/**
 * Calculate big endian 16-bit sum of a buffer (max 128kB),
 * then fold and negate it, producing a 16-bit result in [0..FFFE].
 */
u16 calc_csum(u32 sum, const u8* const buf, const s32 len) {
    s32 i;
    for (i = 0; i < len; ++i) sum += buf[i] * ((i & 1) ? 1 : 256);

    sum = (sum & 0xFFFF) + (sum >> 16);  /* max after this is 1FFFE */
    u16 csum = sum + (sum >> 16);
    return ~csum;  /* assuming sum > 0 on input, this is in [0..FFFE] */
}

static u16 fix_udp_csum(u16 csum) {
    return csum ? csum : 0xFFFF;
}

/**
 * Calculate the ipv4 header and tcp/udp layer 4 checksums.
 * (assumes IPv4 checksum field is set to partial sum of ipv4 options [likely 0])
 * (assumes L4 checksum field is set to L4 payload length on input)
 * Warning: TCP/UDP L4 checksum corrupts packet iff ipv4 options are present.
 * Warning: first IPV4_HLEN + TCP_HLEN == 40 bytes of ip4_pkt must be writable!
 * Returns 6-bit DSCP value [0..63], garbage on parse error.
 */
static int calc_ipv4_csum(u8* const ip4_pkt, const s32 len) {
    store_be16(ip4_pkt + 10, calc_csum(0xFFFF, ip4_pkt, IPV4_HLEN));

    u8 proto = ip4_pkt[9];
    u16 csum = calc_csum(proto, ip4_pkt + 12, len - 12);
    switch (proto) {
      case IPPROTO_TCP:
        store_be16(ip4_pkt + IPV4_HLEN + 16, csum);
        break;
      case IPPROTO_UDP:
        store_be16(ip4_pkt + IPV4_HLEN + 6, fix_udp_csum(csum));
        break;
    }
    return ip4_pkt[1] >> 2;  /* DSCP */
}

/**
 * Calculate the ipv6 icmp6/tcp/udp layer 4 checksums.
 * (assumes L4 checksum field is set to L4 payload length on input)
 * Warning: first IPV6_HLEN + TCP_HLEN == 60 bytes of ip6_pkt must be writable!
 * Returns 6-bit DSCP value [0..63], garbage on parse error.
 */
static int calc_ipv6_csum(u8* const ip6_pkt, const s32 len) {
    u8 proto = ip6_pkt[6];
    u16 csum = calc_csum(proto, ip6_pkt + 8, len - 8);
    switch (proto) {
      case IPPROTO_ICMPV6:
        store_be16(ip6_pkt + IPV6_HLEN + 2, csum);
        break;
      case IPPROTO_TCP:
        store_be16(ip6_pkt + IPV6_HLEN + 16, csum);
        break;
      case IPPROTO_UDP:
        store_be16(ip6_pkt + IPV6_HLEN + 6, fix_udp_csum(csum));
        break;
    }
    return (read_be16(ip6_pkt) >> 6) & 0x3F;  /* DSCP */
}

/**
 * Calculate and store packet checksums and return dscp.
 *
 * @param pkt - pointer to the start of the ethernet header of the packet.
 *     WARNING: first ETHER_HLEN + max(IPV{4,6}_HLEN) + TCP_HLEN = 74 bytes
 *              of buffer pointed to my 'pkt' pointer *MUST* be writable.
 * @param len - length of the packet.
 *
 * @return 6-bit DSCP value [0..63], garbage on parse error.
 */
int calculate_checksum_and_return_dscp(u8* const pkt, const s32 len) {
    switch (read_be16(pkt + 12)) {  /* ethertype */
      case ETH_P_IP:   return calc_ipv4_csum(pkt + ETH_HLEN, len - ETH_HLEN);
      case ETH_P_IPV6: return calc_ipv6_csum(pkt + ETH_HLEN, len - ETH_HLEN);
      default: return 0;
    }
}
