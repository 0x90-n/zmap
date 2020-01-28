/*
 * Modified from module_icmp_echo.
 */

// probe module for doing a tcp traceroute

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>

#include "../../lib/includes.h"
#include "probe_modules.h"
#include "../fieldset.h"
#include "packet.h"
#include "validate.h"

#define ICMP_SMALLEST_SIZE 5
#define ICMP_TIMXCEED_UNREACH_HEADER_SIZE 8

probe_module_t module_traceroute;
static uint32_t num_ports;

static int traceroute_global_initialize(struct state_conf *state)
{
    num_ports = state->source_port_last - state->source_port_first + 1;
    return EXIT_SUCCESS;
}

static int traceroute_init_perthread(void *buf, macaddr_t *src, macaddr_t *gw,
				    __attribute__((unused)) port_h_t dst_port,
				    __attribute__((unused)) void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);

	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header(eth_header, src, gw);

	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
	make_ip_header(ip_header, IPPROTO_TCP, len);

    struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);
    make_tcp_header(tcp_header, 80, TH_SYN);

	return EXIT_SUCCESS;
}

static int traceroute_make_packet(void *buf, UNUSED size_t *buf_len,
				 ipaddr_n_t src_ip, ipaddr_n_t dst_ip, UNUSED uint8_t ttl,
				 uint32_t *validation, int probe_num,
				 UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
    struct tcphdr *tcp_header = (struct tcphdr*)(&ip_header[1]);
    //uint32_t tcp_seq = ((uint32_t)(probe_num&0xff) << 24) | (0xffffff & validation[0]);
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint32_t tcp_seq = ((tv.tv_sec & 0xfff) << 20) | (tv.tv_usec & 0xfffff);

    ip_header->ip_src.s_addr = src_ip;
    ip_header->ip_dst.s_addr = dst_ip;
    ip_header->ip_ttl = probe_num + 1;

    ip_header->ip_id = ((uint16_t)(probe_num&0xff)<<8) | (validation[1] & 0xff);
    tcp_header->th_sport = htons(get_src_port(num_ports, probe_num, validation));
    tcp_header->th_seq = tcp_seq;
    tcp_header->th_sum = 0;
    tcp_header->th_sum =
        tcp_checksum(sizeof(struct tcphdr), ip_header->ip_src.s_addr,
             ip_header->ip_dst.s_addr, tcp_header);

	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

	return EXIT_SUCCESS;
}

static void traceroute_print_packet(FILE *fp, void *packet)
{
	struct ether_header *ethh = (struct ether_header *)packet;
	struct ip *iph = (struct ip *)&ethh[1];
    struct tcphdr *tcph = (struct tcphdr *)&iph[1];

	fprintf(fp,
        "tcp { source: %u | dest: %u | seq: %u | checksum: %#04X }\n",
        ntohs(tcph->th_sport), ntohs(tcph->th_dport),
        ntohl(tcph->th_seq), ntohs(tcph->th_sum));
	fprintf_ip_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

static int traceroute_validate_packet(const struct ip *ip_hdr, uint32_t len,
				UNUSED uint32_t *src_ip, uint32_t *validation)
{
	if (ip_hdr->ip_p != IPPROTO_ICMP) {
		return 0;
	}
	// check if buffer is large enough to contain expected icmp header
	if (((uint32_t)4 * ip_hdr->ip_hl + ICMP_SMALLEST_SIZE) > len) {
		return 0;
	}
	struct icmp *icmp_h =
	    (struct icmp *)((char *)ip_hdr + 4 * ip_hdr->ip_hl);

    // Only TTL exceeded ICMPs
    if (icmp_h->icmp_type != ICMP_TIMXCEED) {
        return 0;
    }

	if ((4 * ip_hdr->ip_hl + ICMP_TIMXCEED_UNREACH_HEADER_SIZE +
	    sizeof(struct ip)) > len) {
		return 0;
	}
	struct ip *ip_inner = (struct ip *)((char *)icmp_h + 8);
    if (((uint32_t)4*ip_hdr->ip_hl +
        ICMP_TIMXCEED_UNREACH_HEADER_SIZE + 4*ip_inner->ip_hl +
        8) > len) { // +8 is for sport,dport,seq
        return 0;
    }
    struct tcphdr *tcp_inner = (struct tcphdr *)((char*)ip_inner + 4*ip_inner->ip_hl);

    uint16_t sport = tcp_inner->th_sport;
    uint16_t dport = tcp_inner->th_dport;
    if (ntohs(dport) != 80) {
        return 0;
    }

    validate_gen(ip_inner->ip_src.s_addr, ip_inner->ip_dst.s_addr,
            (uint8_t *)validation);

    if (!check_dst_port(ntohs(sport), num_ports, validation)) {
        return 0;
    }

    if ((ip_inner->ip_id & 0xff) != (validation[1] & 0xff)) {
        return 0;
    }

    return 1;
}

static void traceroute_process_packet(const u_char *packet,
				     __attribute__((unused)) uint32_t len,
				     fieldset_t *fs,
				     __attribute__((unused))
				     uint32_t *validation)
{
	struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
	struct icmp *icmp_h =
	    (struct icmp *)((char *)ip_hdr + 4 * ip_hdr->ip_hl);
	struct ip *ip_inner = (struct ip *)((char *)icmp_h + 8);
    struct tcphdr *tcp_inner = (struct tcphdr *)((char*)ip_inner + 4*ip_inner->ip_hl);

    //validate_gen(ip_inner->ip_src.s_addr, ip_inner->ip_dst.s_addr,
    //        (uint8_t *)validation);
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint32_t sent_tv_sec = (tcp_inner->th_seq >> 20) & 0xfff;
    uint32_t sent_tv_usec = tcp_inner->th_seq & 0xfffff;

    //uint32_t now_tv_sec = fs_get_uint64_by_index(fs, 9) & 0xfff;
    //uint32_t now_tv_usec = fs_get_uint64_by_index(fs, 10);

    /*
    if (now_tv_sec < sent_tv_sec) {
        now_tv_sec += 0x1000;
    }
    uint64_t now_tv = (uint64_t)now_tv_sec*1000000 + (uint64_t)now_tv_usec;
    uint64_t sent_tv = (uint64_t)sent_tv_sec*1000000 + (uint64_t)sent_tv_usec;
    }*/

    fs_add_uint64(fs, "hop", (ip_inner->ip_id >> 8) + 1);
    fs_add_string(fs, "target", make_ip_str(ip_inner->ip_dst.s_addr), 1);
    fs_add_uint64(fs, "target_raw", (uint64_t)ip_inner->ip_dst.s_addr);
    //fs_add_uint64(fs, "rtt", (now_tv - sent_tv));
    fs_add_uint64(fs, "sent_sec", (uint64_t)sent_tv_sec);
    fs_add_uint64(fs, "sent_usec", (uint64_t)sent_tv_usec);
    fs_add_string(fs, "classification", (char *)"none", 0);
    fs_add_bool(fs, "success", 1);
}

static fielddef_t fields[] = {
    {.name = "hop", .type = "int", .desc = "hop number"},
    {.name = "target", .type = "string", .desc = "destination being tracerouted"},
    {.name = "target_raw", .type = "int", .desc = "destination being tracerouted"},
    //{.name = "rtt", .type = "int", .desc = "round trip to hop in microseconds"},
    {.name = "sent_sec", .type = "int", .desc = "time packet was sent (seconds & 0xfff)"},
    {.name = "sent_usec", .type = "int", .desc = "time packet was sent (microseconds)"},
    {.name = "classification", .type= "string", .desc = "classification (unused)"},
    {.name = "success", .type = "bool", .desc = "always 1"}};

probe_module_t module_traceroute = {.name = "traceroute",
				   .packet_length = 54,
				   .pcap_filter = "icmp and icmp[0]==11",
				   .pcap_snaplen = 96,
				   .port_args = 0,
                   .global_initialize = &traceroute_global_initialize,
				   .thread_initialize =
				       &traceroute_init_perthread,
				   .make_packet = &traceroute_make_packet,
				   .print_packet = &traceroute_print_packet,
				   .process_packet = &traceroute_process_packet,
				   .validate_packet = &traceroute_validate_packet,
				   .close = NULL,
                   .helptext = "Performs a TCP traceroute; set probe-num to the number "
                        "of hops you want to send.",
				   .output_type = OUTPUT_TYPE_STATIC,
				   .fields = fields,
				   .numfields = 7};
