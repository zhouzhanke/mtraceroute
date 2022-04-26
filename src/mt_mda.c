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
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "args.h"
#include "packet.h"
#include "pdu_eth.h"
#include "pdu_ipv4.h"
#include "pdu_icmpv4.h"
#include "pdu_ipv6.h"
#include "pdu_icmpv6.h"
#include "pdu_udp.h"
#include "pdu_tcp.h"
#include "protocol_numbers.h"
#include "packet_helper.h"
#include "iface.h"
#include "probe.h"
#include "util.h"
#include "match.h"
#include "buffer.h"
#include "mt_mda.h"

#define MDA_ICMP_ID 0xffff
#define MDA_UDP_SPORT 53433
#define MDA_UDP_DPORT 33435
#define MDA_TCP_SPORT 53433
#define MDA_TCP_DPORT 80
#define MDA_MIN_FLOW_ID 1
#define MDA_MAX_FLOW_ID 255
#define MDA_FLOWS_AT_ONCE 16

struct flow_ttl
{
    uint8_t ttl;
    uint16_t flow_id;
    char *response;
    int response_type;
};

struct next_hop
{
    char *addr;
    struct timespec rtt;
};

static struct next_hop *next_hop_create(char *addr, struct timespec rtt)
{
    struct next_hop *nh = malloc(sizeof(*nh));
    memset(nh, 0, sizeof(*nh));
    nh->addr = addr;
    nh->rtt = rtt;
    return nh;
}

static int next_hop_cmp(const void *a, const void *b)
{
    struct next_hop *nh1 = (struct next_hop *)a;
    struct next_hop *nh2 = (struct next_hop *)b;
    return strcmp(nh1->addr, nh2->addr);
}

static void next_hop_destroy(struct next_hop *nh)
{
    free(nh);
}

struct mda
{
    char *root;
    int max_ttl;
    int confidence;
    int flow_type;
    struct list *flow_list;
    struct mt *mt;
    struct dst *dst;
};

static struct mda *mda_create(struct mt *a, struct dst *d, int flow_type, int confidence, int max_ttl)
{
    struct mda *mda = malloc(sizeof(*mda));
    if (mda == NULL)
        return NULL;
    memset(mda, 0, sizeof(*mda));
    mda->root = strdup("root");
    mda->confidence = confidence;
    mda->max_ttl = max_ttl;
    mda->flow_type = flow_type;
    mda->flow_list = list_create();
    mda->mt = a;
    mda->dst = d;
    return mda;
}

static void mda_destroy(struct mda *mda)
{
    while (mda->flow_list->count > 0)
    {
        struct flow_ttl *f = (struct flow_ttl *)list_pop(mda->flow_list);
        free(f->response);
        free(f);
    }
    list_destroy(mda->flow_list);
    free(mda->root);
    free(mda);
}

static struct addr *flow_id_to_addr(struct addr *a, int flow_id)
{
    int size = 0;
    if (a->type == ADDR_IPV4)
    {
        size = 4;
    }
    else if (a->type == ADDR_IPV6)
    {
        size = 16;
    }
    else
    {
        return NULL;
    }
    struct addr *new = addr_copy(a);
    // 目标地址末尾微量浮动???
    new->addr[size - 1] = (flow_id & 0xFF);
    return new;
}

static int get_flow_id_from_addr(uint8_t *addr, int addr_type)
{
    int flow_id = -1;
    int size = 0;
    if (addr_type == ADDR_IPV4)
        flow_id = addr[3];
    else if (addr_type == ADDR_IPV6)
        flow_id = addr[15];
    return flow_id;
}

static void mda_send(struct mda *m, uint16_t flow_id,
                     uint16_t probe_id, uint8_t ttl)
{
    struct packet *p = NULL;

    if (m->dst->ip_dst->type == ADDR_IPV4)
    {

        // extra control on IP header destination address
        if (m->flow_type == FLOW_UDP_DST)
        {

            struct addr *dst_fid = flow_id_to_addr(m->dst->ip_dst, flow_id);
            p = packet_helper_udp4(m->dst->mac_dst->addr, m->dst->mac_src->addr,
                                   m->dst->ip_src->addr, dst_fid->addr, ttl,
                                   0, MDA_UDP_SPORT, MDA_UDP_DPORT, probe_id);
            mt_send(m->mt, m->dst->if_index, p->buf, p->length, &match_udp4);
            addr_destroy(dst_fid);
        }
        // extra control on UDP header source port
        else if (m->flow_type == FLOW_UDP_SPORT)
        {

            p = packet_helper_udp4(m->dst->mac_dst->addr, m->dst->mac_src->addr,
                                   m->dst->ip_src->addr, m->dst->ip_dst->addr, ttl,
                                   0, MDA_UDP_SPORT + flow_id, MDA_UDP_DPORT, probe_id);
            mt_send(m->mt, m->dst->if_index, p->buf, p->length, &match_udp4);
        }
        // extra control on IP header destination address
        else if (m->flow_type == FLOW_ICMP_DST)
        {

            struct addr *dst_fid = flow_id_to_addr(m->dst->ip_dst, flow_id);
            p = packet_helper_echo4(m->dst->mac_dst->addr, m->dst->mac_src->addr,
                                    m->dst->ip_src->addr, dst_fid->addr, ttl,
                                    0, MDA_ICMP_ID, probe_id, 0x1234);
            mt_send(m->mt, m->dst->if_index, p->buf, p->length, &match_icmp4);
            addr_destroy(dst_fid);
        }
        // extra control on ICMP header checksum
        else if (m->flow_type == FLOW_ICMP_CHK)
        {

            p = packet_helper_echo4(m->dst->mac_dst->addr, m->dst->mac_src->addr,
                                    m->dst->ip_src->addr, m->dst->ip_dst->addr, ttl,
                                    0, MDA_ICMP_ID, probe_id, flow_id);
            mt_send(m->mt, m->dst->if_index, p->buf, p->length, &match_icmp4);
        }
        // extra control on IP header destination address
        else if (m->flow_type == FLOW_TCP_DST)
        {

            struct addr *dst_fid = flow_id_to_addr(m->dst->ip_dst, flow_id);
            p = packet_helper_tcp4(m->dst->mac_dst->addr, m->dst->mac_src->addr,
                                   m->dst->ip_src->addr, dst_fid->addr, ttl,
                                   0, MDA_TCP_SPORT, MDA_TCP_DPORT, probe_id);
            mt_send(m->mt, m->dst->if_index, p->buf, p->length, &match_tcp4);
            addr_destroy(dst_fid);
        }
        // extra control on TCP header source port
        else if (m->flow_type == FLOW_TCP_SPORT)
        {

            p = packet_helper_tcp4(m->dst->mac_dst->addr, m->dst->mac_src->addr,
                                   m->dst->ip_src->addr, m->dst->ip_dst->addr, ttl,
                                   0, MDA_TCP_SPORT + flow_id, MDA_TCP_DPORT, probe_id);
            mt_send(m->mt, m->dst->if_index, p->buf, p->length, &match_tcp4);
        }
    }
    else if (m->dst->ip_dst->type == ADDR_IPV6)
    {

        // extra control on IP header destination address
        if (m->flow_type == FLOW_ICMP_DST)
        {

            struct addr *dst_fid = flow_id_to_addr(m->dst->ip_dst, flow_id);
            p = packet_helper_echo6(m->dst->mac_dst->addr, m->dst->mac_src->addr,
                                    m->dst->ip_src->addr, dst_fid->addr, 0, 0, ttl,
                                    MDA_ICMP_ID, probe_id, 0);
            mt_send(m->mt, m->dst->if_index, p->buf, p->length, &match_icmp6);
            addr_destroy(dst_fid);
        }
        // extra control on IP header flow label
        else if (m->flow_type == FLOW_ICMP_FL)
        {

            p = packet_helper_echo6(m->dst->mac_dst->addr, m->dst->mac_src->addr,
                                    m->dst->ip_src->addr, m->dst->ip_dst->addr, 0, flow_id, ttl,
                                    MDA_ICMP_ID, probe_id, 0);

            mt_send(m->mt, m->dst->if_index, p->buf, p->length, &match_icmp6);
        }
        // extra control on IP header traffic class
        else if (m->flow_type == FLOW_ICMP_TC)
        {

            p = packet_helper_echo6(m->dst->mac_dst->addr, m->dst->mac_src->addr,
                                    m->dst->ip_src->addr, m->dst->ip_dst->addr, flow_id, 0, ttl,
                                    MDA_ICMP_ID, probe_id, 0);
            mt_send(m->mt, m->dst->if_index, p->buf, p->length, &match_icmp6);
        }
        // extra control on ICMP header checksum
        else if (m->flow_type == FLOW_ICMP_CHK)
        {

            p = packet_helper_echo6(m->dst->mac_dst->addr, m->dst->mac_src->addr,
                                    m->dst->ip_src->addr, m->dst->ip_dst->addr, 0, 0, ttl,
                                    MDA_ICMP_ID, probe_id, flow_id);
            mt_send(m->mt, m->dst->if_index, p->buf, p->length, &match_icmp6);
        }
        else if (m->flow_type == FLOW_UDP_DST)
        {

            struct addr *dst_fid = flow_id_to_addr(m->dst->ip_dst, flow_id);
            p = packet_helper_udp6(m->dst->mac_dst->addr, m->dst->mac_src->addr,
                                   m->dst->ip_src->addr, dst_fid->addr, 0, 0, ttl,
                                   MDA_UDP_SPORT, MDA_UDP_DPORT, probe_id);
            mt_send(m->mt, m->dst->if_index, p->buf, p->length, &match_udp6);
            addr_destroy(dst_fid);
        }
        else if (m->flow_type == FLOW_UDP_FL)
        {

            p = packet_helper_udp6(m->dst->mac_dst->addr, m->dst->mac_src->addr,
                                   m->dst->ip_src->addr, m->dst->ip_dst->addr, 0, flow_id, ttl,
                                   MDA_UDP_SPORT, MDA_UDP_DPORT, probe_id);
            mt_send(m->mt, m->dst->if_index, p->buf, p->length, &match_udp6);
        }
        else if (m->flow_type == FLOW_UDP_TC)
        {

            p = packet_helper_udp6(m->dst->mac_dst->addr, m->dst->mac_src->addr,
                                   m->dst->ip_src->addr, m->dst->ip_dst->addr, flow_id, 0, ttl,
                                   MDA_UDP_SPORT, MDA_UDP_DPORT, probe_id);
            mt_send(m->mt, m->dst->if_index, p->buf, p->length, &match_udp6);
        }
        // extra control on UDP header source port
        else if (m->flow_type == FLOW_UDP_SPORT)
        {

            p = packet_helper_udp6(m->dst->mac_dst->addr, m->dst->mac_src->addr,
                                   m->dst->ip_src->addr, m->dst->ip_dst->addr, 0, 0, ttl,
                                   MDA_UDP_SPORT + flow_id, MDA_UDP_DPORT, probe_id);
            mt_send(m->mt, m->dst->if_index, p->buf, p->length, &match_udp6);
        }
        else if (m->flow_type == FLOW_TCP_DST)
        {

            struct addr *dst_fid = flow_id_to_addr(m->dst->ip_dst, flow_id);
            p = packet_helper_tcp6(m->dst->mac_dst->addr, m->dst->mac_src->addr,
                                   m->dst->ip_src->addr, dst_fid->addr, 0, 0, ttl,
                                   MDA_TCP_SPORT, MDA_TCP_DPORT, probe_id);
            mt_send(m->mt, m->dst->if_index, p->buf, p->length, &match_tcp6);
            addr_destroy(dst_fid);
        }
        else if (m->flow_type == FLOW_TCP_FL)
        {

            p = packet_helper_tcp6(m->dst->mac_dst->addr, m->dst->mac_src->addr,
                                   m->dst->ip_src->addr, m->dst->ip_dst->addr, 0, flow_id, ttl,
                                   MDA_TCP_SPORT, MDA_TCP_DPORT, probe_id);
            mt_send(m->mt, m->dst->if_index, p->buf, p->length, &match_tcp6);
        }
        else if (m->flow_type == FLOW_TCP_TC)
        {

            p = packet_helper_tcp6(m->dst->mac_dst->addr, m->dst->mac_src->addr,
                                   m->dst->ip_src->addr, m->dst->ip_dst->addr, flow_id, 0, ttl,
                                   MDA_TCP_SPORT, MDA_TCP_DPORT, probe_id);
            mt_send(m->mt, m->dst->if_index, p->buf, p->length, &match_tcp6);
        }
        // extra control on TCP header source port
        else if (m->flow_type == FLOW_TCP_SPORT)
        {

            p = packet_helper_tcp6(m->dst->mac_dst->addr, m->dst->mac_src->addr,
                                   m->dst->ip_src->addr, m->dst->ip_dst->addr, 0, 0, ttl,
                                   MDA_TCP_SPORT + flow_id, MDA_TCP_DPORT, probe_id);
            mt_send(m->mt, m->dst->if_index, p->buf, p->length, &match_tcp6);
        }
    }

    packet_destroy(p);
}

static struct flow_ttl *flow_ttl_create(int ttl, uint16_t flow_id,
                                        char *resp, int type)
{
    struct flow_ttl *ft = malloc(sizeof(*ft));
    if (ft == NULL)
        return NULL;
    ft->ttl = ttl;
    ft->flow_id = flow_id;
    ft->response = strdup(resp);
    ft->response_type = type;
    return ft;
}

static void add_flow(struct mda *mda, int ttl, uint16_t flow_id,
                     char *resp, int type)
{
    struct flow_ttl *flow = flow_ttl_create(ttl, flow_id, resp, type);
    list_insert(mda->flow_list, flow);
}

static int has_flow_id(struct mda *mda, int ttl, uint16_t flow_id)
{
    struct list_item *it = NULL;
    for (it = mda->flow_list->first; it != NULL; it = it->next)
    {
        struct flow_ttl *f = (struct flow_ttl *)it->data;
        if (f->ttl == ttl && f->flow_id == flow_id)
            return 1;
    }
    return 0;
}

static int get_nth_flow_id_available(struct mda *mda, int n, int ttl)
{
    int nth = 0;
    int flow_id = 0;
    for (flow_id = MDA_MIN_FLOW_ID; flow_id <= MDA_MAX_FLOW_ID; flow_id++)
    {
        if (has_flow_id(mda, ttl, flow_id) == 0)
            nth++;
        if (nth == n)
            return flow_id;
    }
    return -1;
}

static struct list *get_interfaces_ttl(struct mda *mda, int ttl)
{
    struct list *i = list_create();
    struct list_item *it = NULL;
    for (it = mda->flow_list->first; it != NULL; it = it->next)
    {
        struct flow_ttl *f = (struct flow_ttl *)it->data;
        if (f->ttl == ttl && list_find(i, f->response, &strcmp_void) == NULL)
        {
            list_insert(i, f->response);
        }
    }
    return i;
}

static struct list *get_flows_ttl(struct mda *mda, int ttl)
{
    struct list *i = list_create();
    struct list_item *it = NULL;
    struct list *addrs = list_create();

    for (it = mda->flow_list->first; it != NULL; it = it->next)
    {
        struct flow_ttl *f = (struct flow_ttl *)it->data;
        if (f->ttl == ttl && list_find(addrs, f->response, &strcmp_void) == NULL)
        {
            list_insert(i, f);
            list_insert(addrs, f->response);
        }
    }

    list_destroy(addrs);
    return i;
}

static struct list *get_flows(struct mda *mda, int ttl, char *resp)
{
    struct list *i = list_create();
    struct list_item *it = NULL;
    for (it = mda->flow_list->first; it != NULL; it = it->next)
    {
        struct flow_ttl *f = (struct flow_ttl *)it->data;
        if (f->ttl == ttl && strcmp(f->response, resp) == 0)
        {
            list_insert(i, f);
        }
    }
    return i;
}

static void mda_read_response(struct mda *m, struct probe *p, char **src_addr,
                              struct timespec *rtt)
{

    int ttl = 0;
    int flow_id = 0;

    if (m->dst->ip_dst->type == ADDR_IPV4)
    {

        struct ipv4_hdr *ihdr = (struct ipv4_hdr *)(p->probe + ETH_H_SIZE);
        ttl = ihdr->ttl;
        int tsp_pos = ETH_H_SIZE + IPV4_H_SIZE;

        if (m->flow_type == FLOW_UDP_DST || m->flow_type == FLOW_ICMP_DST ||
            m->flow_type == FLOW_TCP_DST)
        {

            struct ipv4_hdr *pip = (struct ipv4_hdr *)(p->probe + ETH_H_SIZE);
            flow_id = get_flow_id_from_addr((uint8_t *)&pip->dst_addr, ADDR_IPV4);
        }
        else if (m->flow_type == FLOW_UDP_SPORT)
        {

            struct udp_hdr *pudp = (struct udp_hdr *)(p->probe + tsp_pos);
            flow_id = ntohs(pudp->src_port) - MDA_UDP_SPORT;
        }
        else if (m->flow_type == FLOW_ICMP_CHK)
        {

            struct icmpv4_hdr *picmp = (struct icmpv4_hdr *)(p->probe + tsp_pos);
            flow_id = ntohs(picmp->checksum);
        }
        else if (m->flow_type == FLOW_TCP_SPORT)
        {

            struct tcp_hdr *ptcp = (struct tcp_hdr *)(p->probe + tsp_pos);
            flow_id = ntohs(ptcp->src_port) - MDA_TCP_SPORT;
        }

        if (p->response_len > 0)
        {
            struct ipv4_hdr *rip = (struct ipv4_hdr *)(p->response + ETH_H_SIZE);
            *src_addr = addr_bytes_to_str(ADDR_IPV4, (uint8_t *)&rip->src_addr);

            int type = -1;
            if (rip->protocol == PROTO_ICMPV4)
            {
                type = get_icmp4_type(p->response);
            }
            add_flow(m, ttl, flow_id, *src_addr, type);

            if (rtt != NULL)
            {
                *rtt = timespec_diff(&p->response_time, &p->sent_time);
            }
        }
        else
        {
            *src_addr = strdup("*");
            add_flow(m, ttl, flow_id, *src_addr, -1);
        }
    }
    else if (m->dst->ip_dst->type == ADDR_IPV6)
    {

        struct ipv6_hdr *ihdr = (struct ipv6_hdr *)(p->probe + ETH_H_SIZE);
        ttl = ihdr->hop_limit;
        int tsp_pos = ETH_H_SIZE + IPV6_H_SIZE;

        if (m->flow_type == FLOW_UDP_DST || m->flow_type == FLOW_ICMP_DST ||
            m->flow_type == FLOW_TCP_DST)
        {

            struct ipv6_hdr *pip = (struct ipv6_hdr *)(p->probe + ETH_H_SIZE);
            flow_id = get_flow_id_from_addr((uint8_t *)&pip->dst_addr, ADDR_IPV6);
        }
        else if (m->flow_type == FLOW_UDP_FL || m->flow_type == FLOW_ICMP_FL ||
                 m->flow_type == FLOW_TCP_FL)
        {

            flow_id = ntohl(ihdr->version_tc_fl) & 0x000FFFFF;
        }
        else if (m->flow_type == FLOW_UDP_TC || m->flow_type == FLOW_ICMP_TC ||
                 m->flow_type == FLOW_TCP_TC)
        {

            flow_id = (ntohl(ihdr->version_tc_fl) & 0x0FF00000) >> 20;
        }
        else if (m->flow_type == FLOW_UDP_SPORT)
        {

            struct udp_hdr *pudp = (struct udp_hdr *)(p->probe + tsp_pos);
            flow_id = ntohs(pudp->src_port) - MDA_UDP_SPORT;
        }
        else if (m->flow_type == FLOW_ICMP_CHK)
        {

            struct icmpv6_hdr *picmp = (struct icmpv6_hdr *)(p->probe + tsp_pos);
            flow_id = ntohs(picmp->checksum);
        }
        else if (m->flow_type == FLOW_TCP_SPORT)
        {

            struct tcp_hdr *ptcp = (struct tcp_hdr *)(p->probe + tsp_pos);
            flow_id = ntohs(ptcp->src_port) - MDA_TCP_SPORT;
        }

        if (p->response_len > 0)
        {
            struct ipv6_hdr *rip = (struct ipv6_hdr *)(p->response + ETH_H_SIZE);
            *src_addr = addr_bytes_to_str(ADDR_IPV6, (uint8_t *)&rip->src_addr);

            int type = -1;
            if (rip->next_header == PROTO_ICMPV6)
            {
                type = get_icmp6_type(p->response);
            }
            add_flow(m, ttl, flow_id, *src_addr, type);

            if (rtt != NULL)
            {
                *rtt = timespec_diff(&p->response_time, &p->sent_time);
            }
        }
        else
        {
            *src_addr = strdup("*");
            add_flow(m, ttl, flow_id, *src_addr, -1);
        }
    }
}

static int is_per_packet(struct mda *mda, int flow_id, int ttl, int n)
{
    int i = 0;
    for (i = 0; i < n; i++)
    {
        mda_send(mda, flow_id, i + 1, ttl + 1);
    }

    mt_wait(mda->mt, mda->dst->if_index);

    struct list *nh = list_create();

    struct interface *inter = mt_get_interface(mda->mt, mda->dst->if_index);
    int found = 0;
    while (inter->probes->count > 0)
    {
        struct probe *probe = (struct probe *)list_pop(inter->probes);
        char *addr = NULL;
        mda_read_response(mda, probe, &addr, NULL);
        if (strcmp(addr, "*") != 0 && list_find(nh, addr, &strcmp_void) == NULL)
        {
            list_insert(nh, addr);
            found++;
        }
        else
        {
            free(addr);
        }
        probe_destroy(probe);
    }

    struct list_item *it = NULL;
    for (it = nh->first; it != NULL; it = it->next)
    {
        free(it->data);
    }

    list_destroy(nh);

    return found;
}

static int next_hops(struct mda *mda, char *addr, int ttl, struct list *flows,
                     int mda_number, int *flows_sent, struct list *nh_list)
{

    int sent = 0;
    int sent_new = 0;
    // 发送探针
    while (flows->count > 0)
    {
        struct flow_ttl *f = (struct flow_ttl *)list_pop(flows);

        // 如果已经发送增加sent计数
        if (has_flow_id(mda, ttl + 1, f->flow_id) == 1)
        {
            sent++;
        }
        // 如果不满足mda算法的数量，继续发送
        else if (sent < mda_number)
        {
            mda_send(mda, f->flow_id, f->flow_id, ttl + 1);
            sent++;
            sent_new++;
        }
    }

    *flows_sent += sent_new;

    // 回收探针或重发探针
    mt_wait(mda->mt, mda->dst->if_index);

    struct interface *inter = mt_get_interface(mda->mt, mda->dst->if_index);

    int found = 0;
    while (inter->probes->count > 0)
    {
        struct probe *probe = (struct probe *)list_pop(inter->probes);
        char *addr = NULL;
        struct timespec rtt;
        // 读取记过并存入总flow记录
        mda_read_response(mda, probe, &addr, &rtt);
        struct next_hop *nh = next_hop_create(addr, rtt);

        // 判断下一跳有几个响应目标,靠响应数量结合MDA来确定下一个循环flow的数量
        if (list_find(nh_list, nh, &next_hop_cmp) == NULL)
        {
            list_insert(nh_list, nh);
            found++;
        }
        else
        {
            free(addr);
            next_hop_destroy(nh);
        }

        probe_destroy(probe);
    }
    return found;
}

static void more_flows(struct mda *mda, char *addr, int ttl, int number_of_new_flows)
{
    // 理论上不会触发
    if (ttl == 0)
    {
        int found = 0;
        int stop = 0;
        int i = 0;
        while (found < number_of_new_flows && stop == 0)
        {
            int flow_id = get_nth_flow_id_available(mda, i, ttl);
            if (flow_id == -1)
            {
                stop = 1;
                break;
            }
            add_flow(mda, ttl, flow_id, addr, -1);
            found++;
            i++;
        }
        return;
    }

    int found = 0;
    int stop = 0;
    while (found < number_of_new_flows && stop == 0)
    {
        int missing = number_of_new_flows - found;
        int send = missing > MDA_FLOWS_AT_ONCE ? missing : MDA_FLOWS_AT_ONCE;
        int i = 0;
        for (i = 1; i <= send; i++)
        {
            int flow_id = get_nth_flow_id_available(mda, i, ttl);
            if (flow_id == -1)
            {
                stop = 1;
                break;
            }
            mda_send(mda, flow_id, flow_id, ttl);
        }

        mt_wait(mda->mt, mda->dst->if_index);

        struct interface *inter = mt_get_interface(mda->mt, mda->dst->if_index);
        while (inter->probes->count > 0)
        {
            struct probe *probe = (struct probe *)list_pop(inter->probes);
            char *resp = NULL;
            mda_read_response(mda, probe, &resp, NULL);
            if (strcmp(resp, addr) == 0)
                found++;
            free(resp);
            probe_destroy(probe);
        }
    }
}

static void mda_print(int ttl, char *addr, struct list *nh, int per_packet)
{
    if (per_packet == 1)
    {
        printf("%2d  %s (P): ", ttl, addr);
    }
    else
    {
        printf("%2d  %s: ", ttl, addr);
    }
    struct list_item *i = NULL;
    for (i = nh->first; i != NULL; i = i->next)
    {
        struct next_hop *nh = (struct next_hop *)i->data;
        char *rtt_str = timespec_to_str(&nh->rtt);
        if (strcmp(nh->addr, "*") == 0)
        {
            printf(" *");
        }
        else
        {
            printf(" %s (%s ms)", nh->addr, rtt_str);
        }
        free(rtt_str);
    }
    printf("\n");
}

static int mda(struct mda *mda)
{
    // MDA 算法结果，数量=可发现负载均衡数（目前支持128个负载均衡的计算）
    // 分为三种情况，90% 95% 99%的结果覆盖率
    int k[][3] = {
        {0, 0, 0},
        {1, 1, 1},
        {5, 6, 8},
        {9, 11, 15},
        {13, 16, 21},
        {18, 21, 28},
        {23, 27, 36},
        {28, 33, 43},
        {33, 38, 51},
        {38, 44, 58},
        {44, 51, 66},
        {50, 57, 74},
        {55, 63, 82},
        {61, 70, 90},
        {67, 76, 98},
        {73, 83, 106},
        {79, 90, 115},
        {85, 96, 123},
        {91, 103, 132},
        {97, 110, 140},
        {103, 117, 149},
        {109, 124, 157},
        {116, 131, 166},
        {122, 138, 175},
        {128, 145, 183},
        {135, 152, 192},
        {141, 159, 201},
        {148, 167, 210},
        {154, 174, 219},
        {161, 181, 228},
        {168, 189, 237},
        {174, 196, 246},
        {181, 203, 255},
        {188, 211, 264},
        {194, 218, 273},
        {201, 226, 282},
        {208, 233, 291},
        {215, 241, 300},
        {222, 248, 309},
        {229, 256, 319},
        {235, 264, 328},
        {242, 271, 337},
        {249, 279, 347},
        {256, 287, 356},
        {263, 294, 365},
        {270, 302, 375},
        {277, 310, 384},
        {285, 318, 393},
        {292, 326, 403},
        {299, 333, 412},
        {306, 341, 422},
        {313, 349, 431},
        {320, 357, 441},
        {327, 365, 450},
        {335, 373, 460},
        {342, 381, 470},
        {349, 389, 479},
        {356, 397, 489},
        {364, 405, 499},
        {371, 413, 508},
        {378, 421, 518},
        {386, 429, 528},
        {393, 437, 537},
        {400, 445, 547},
        {408, 453, 557},
        {415, 462, 566},
        {423, 470, 576},
        {430, 478, 586},
        {438, 486, 596},
        {445, 494, 606},
        {453, 502, 616},
        {460, 511, 625},
        {468, 519, 635},
        {475, 527, 645},
        {483, 535, 655},
        {490, 544, 665},
        {498, 552, 675},
        {505, 560, 685},
        {513, 569, 695},
        {521, 577, 705},
        {528, 585, 715},
        {536, 594, 725},
        {543, 602, 735},
        {551, 610, 745},
        {559, 619, 755},
        {566, 627, 765},
        {574, 635, 775},
        {582, 644, 785},
        {590, 652, 795},
        {597, 661, 805},
        {605, 669, 815},
        {613, 678, 825},
        {621, 686, 835},
        {628, 695, 845},
        {636, 703, 855},
        {644, 712, 866},
        {652, 720, 876},
        {660, 729, 886},
        {667, 737, 896},
        {675, 746, 906},
        {683, 754, 916},
        {691, 763, 927},
        {699, 772, 937},
        {707, 780, 947},
        {715, 789, 957},
        {722, 797, 968},
        {730, 806, 978},
        {738, 815, 988},
        {746, 823, 998},
        {754, 832, 1009},
        {762, 841, 1019},
        {770, 849, 1029},
        {778, 858, 1040},
        {786, 867, 1050},
        {794, 875, 1060},
        {802, 884, 1071},
        {810, 893, 1081},
        {818, 902, 1091},
        {826, 910, 1102},
        {834, 919, 1112},
        {842, 928, 1122},
        {850, 937, 1133},
        {858, 945, 1143},
        {866, 954, 1154},
        {874, 963, 1164},
        {882, 972, 1174},
        {890, 980, 1185},
        {898, 989, 1195},
        {906, 998, 1206},
    };

    // Initialize the first flows for root

    // 根据设定获取率选择初始MDA算法表
    int mda_number = k[2][mda->confidence];

    int ttl = 0;
    // 录入算法表ttl=0到flow列表, 来规避第一次循环的特殊情况
    // 创建（添加）n个struct flow_ttl实例，并插入mda->flow_list
    // struct flow_ttl成员赋值:  对应add_flow()后4个参数；
    // ft->ttl           = ttl;	0
    // ft->flow_id       = flow_id;  1 2 3 4 5 ...
    // ft->response      = strdup(resp);
    // ft->response_type = type;    -1
    for (int i = 0; i < mda_number; i++)
    {
        add_flow(mda, ttl, MDA_MIN_FLOW_ID + i, mda->root, -1);
    }

    for (ttl; ttl <= mda->max_ttl; ttl++)
    {
        // 读取特定TTL的flow列表来用作本次循环次数的依据
        struct list *addrs_ttl = get_flows_ttl(mda, ttl);

        // 执行MDA
        //取一个发送响应的IP地址  初始化时为"root"，之后为发送响应的IP
        //这里，编程者用了一技巧，就是初始状态收到了n个来自“root”的响应；
        //这样，程序执行过程就统一为“分析响应”->"发现该响应的下一跳接口"
        while (addrs_ttl->count > 0)
        {
            struct flow_ttl *flow_ttl = (struct flow_ttl *)list_pop(addrs_ttl);
            char *addr = flow_ttl->response;
            char *addr_dst = addr_to_str(mda->dst->ip_dst);

            // 当达到目标IP时不继续探测
            if (strcmp(addr, addr_dst) == 0)
            {
                free(addr_dst);
                continue;
            }
            free(addr_dst);
            if (mda->dst->ip_dst->type == ADDR_IPV4 &&
                flow_ttl->response_type == ICMPV4_TYPE_UNREACH)
            {
                continue;
            }
            else if (mda->dst->ip_dst->type == ADDR_IPV6 &&
                     flow_ttl->response_type == ICMPV6_TYPE_UNREACH)
            {
                continue;
            }

            // this->count 用来更新MDA flow数量
            // this->probe 用来输出结果
            struct list *next_hop_list = list_create();
            int flows_sent = 0;
            // 用来判断while循环的flag，应该可以改进
            int new_next_hop = 1;
            while (new_next_hop)
            {
                //返回当前TTL下addr(响应IP)对应的flow ID
                struct list *flows = get_flows(mda, ttl, addr);

                int total_next_hops = next_hop_list->count;
                if (next_hop_list->count == 0)
                    total_next_hops = 1;

                // 读取MDA算法表
                mda_number = k[total_next_hops + 1][mda->confidence];

                // 如果当前flow数量不满足MDA算法表，增加flow数量并发送探针
                if (flows->count < mda_number)
                {
                    more_flows(mda, addr, ttl, mda_number - flows->count);
                    list_destroy(flows);
                    flows = get_flows(mda, ttl, addr);
                }

                // 发送探针判断下一跳有多少个新的目标，并以此为依据读取MDA算法表
                // next_hope_list是更新MDA的依据
                // 返回结果是决定是否结束循环的依据，应该可以改进
                new_next_hop = next_hops(mda, addr, ttl, flows, mda_number, &flows_sent, next_hop_list);

                // 特殊情况下结束循环
                if (new_next_hop == 1 && next_hop_list->count == 1)
                    new_next_hop = 0;
                list_destroy(flows);
            }

            // 判断下一跳是否是per-packet负载均衡
            int per_packet = 0;
            if (next_hop_list->count > 1)
            {
                struct list *flows = get_flows(mda, ttl, addr);
                struct flow_ttl *f = (struct flow_ttl *)list_pop(flows);
                mda_number = k[2][mda->confidence];
                int result = is_per_packet(mda, f->flow_id, ttl, mda_number);
                if (result > 1)
                    per_packet = 1;
                list_destroy(flows);
            }

            // 输出结果
            mda_print(ttl, addr, next_hop_list, per_packet);

            // 清除
            while (next_hop_list->count > 0)
            {
                struct next_hop *nh = (struct next_hop *)list_pop(next_hop_list);
                free(nh->addr);
                next_hop_destroy(nh);
            }
            list_destroy(next_hop_list);
        }

        list_destroy(addrs_ttl);
    }

    return 0;
}

// 创建struct mda的一个实例，然后执行多路径探测mda
// 输入参数：struct mt；目的地址（单个地址）；置信度；流ID类型；最大TTL
int mt_mda(struct mt *a, struct dst *dst, int confidence,
           int flow_type, int max_ttl)
{

    // 获取率百分比,90%，95%，99%
    if (confidence == 90)
        confidence = 0;
    else if (confidence == 95)
        confidence = 1;
    else if (confidence == 99)
        confidence = 2;

    if (dst->ip_dst->type == ADDR_IPV4 || dst->ip_dst->type == ADDR_IPV6)
    {
        struct mda *m = mda_create(a, dst, flow_type, confidence, max_ttl);
        int result = mda(m);
        mda_destroy(m);
        return result;
    }

    return -1;
}
