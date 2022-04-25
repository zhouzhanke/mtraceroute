/* Copyright (c) 2016-2017, Rafael Almeida <rlca at dcc dot ufmg dot br>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of mtraceroute nor the names of its contributors may
 *     be used to endorse or promote products derived from this software
 *     without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "packet.h"
#include "pdu_eth.h"
#include "pdu_ipv4.h"
#include "pdu_icmpv4.h"
#include "pdu_ipv6.h"
#include "pdu_icmpv6.h"
#include "protocol_numbers.h"
#include "packet_helper.h"
#include "iface.h"
#include "probe.h"
#include "util.h"
#include "match.h"
#include "buffer.h"
#include "mt_ping.h"

#define IP_ID 54321
#define CHECKSUM 54321
#define ICMP_ID 54321

static void ping4_print(const struct probe *p)
{
    if (p->response_len == 0)
    {
        printf("*\n");
        return;
    }

    char *addr = get_ip4_src_addr(p->response);
    char *time = timespec_diff_to_str(&p->response_time, &p->sent_time);
    int ttl = get_ip4_ttl(p->probe);
    uint16_t seq_num = get_icmp4_seqnum(p->probe);
    printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%s ms\n", p->response_len,
           addr, seq_num, ttl, time);
    free(addr);
    free(time);
}

static void ping6_print(const struct probe *p)
{
    if (p->response_len == 0)
    {
        printf("*\n");
        return;
    }

    char *addr = get_ip6_src_addr(p->response);
    char *time = timespec_diff_to_str(&p->response_time, &p->sent_time);
    int ttl = get_ip6_ttl(p->probe);
    uint16_t seq_num = get_icmp6_seqnum(p->probe);
    printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%s ms\n", p->response_len,
           addr, seq_num, ttl, time);

    free(addr);
    free(time);
}

int mt_ping(struct mt *meta, const struct dst *ip_target, int number_of_pings)
{
    if (ip_target->ip_dst->type != ADDR_IPV4 &&
        ip_target->ip_dst->type != ADDR_IPV6)
        return -1;

    int probe_count = 0;
    for (probe_count = 1; probe_count <= number_of_pings; probe_count++)
    {
        printf("<<<<<新的探测循环>>>>>\n");
        struct packet *p = NULL;

        // 发送探针
        printf("发送探针...\n");
        if (ip_target->ip_dst->type == ADDR_IPV4)
        {
            p = packet_helper_echo4(ip_target->mac_dst->addr, ip_target->mac_src->addr,
                                    ip_target->ip_src->addr, ip_target->ip_dst->addr,
                                    IPV4_TTL, IP_ID + probe_count, ICMP_ID,
                                    probe_count, CHECKSUM);
            mt_send(meta, ip_target->if_index, p->buf, p->length, &match_icmp4);
        }
        else if (ip_target->ip_dst->type == ADDR_IPV6)
        {
            p = packet_helper_echo6(ip_target->mac_dst->addr, ip_target->mac_src->addr,
                                    ip_target->ip_src->addr, ip_target->ip_dst->addr,
                                    0, 0, IPV6_HOP_LIMIT, ICMP_ID, probe_count, CHECKSUM);
            mt_send(meta, ip_target->if_index, p->buf, p->length, &match_icmp6);
        }

        printf("回收探针或重发探针...\n");
        mt_wait(meta, ip_target->if_index);

        struct interface *i = mt_get_interface(meta, ip_target->if_index);
        struct probe *probe = (struct probe *)list_pop(i->probes);

        printf("打印结果...\n");
        if (ip_target->ip_dst->type == ADDR_IPV4)
        {
            ping4_print(probe);
        }
        else if (ip_target->ip_dst->type == ADDR_IPV6)
        {
            ping6_print(probe);
        }

        probe_destroy(probe);
        packet_destroy(p);
    }

    return 0;
}
