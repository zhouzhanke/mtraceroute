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
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>

#include "dst.h"
#include "iface.h"
#include "util.h"
#include "link.h"
#include "args.h"
#include "mt.h"
#include "mt_nd.h"
#include "mt_mda.h"
#include "mt_ping.h"
#include "mt_traceroute.h"

#define MT_MDA 1
#define MT_PING 2
#define MT_TRACEROUTE 3

// 探针发送，被mt_mda、mt_nd、mt_ping、mt_traceroute调用
// buf ：探针包数据     fn：响应匹配函数
struct probe *mt_send(struct mt *a, int if_index, const uint8_t *buf,
                      uint32_t len, match_fn fn)
{
    printf("发送...");
    // 获得本机网络控制
    //如果if_index存在，返回对应的interface；
    //不存在，创建一struct interface实体，并初始化以下：
    // if_index、hw_addr
    // link，通过link_open创建一个RAW套接字，套接字创建失败没有处理
    // probes,一个list
    //在i上打开pcap
    //最后将i插入mt的intreface的list中
    struct interface *i = mt_get_interface(a, if_index);

    // 生成探针
    //程序  p->retries   = 0;  命令行参数怎么办呢，这个应该是重发了多少计数
    //探针响应匹配函数，也在p中
    //探针匹配回调函数赋值 p->fn = fn
    struct probe *p = probe_create(buf, len, fn);

    // 发送
    // p->sent_time在sendto时赋值
    link_write(i->link, p->probe, p->probe_len, &(p->sent_time));

    // 储存发送探针, 以便在接受时匹配
    list_insert(i->probes, p);

    // 发送间隔
    if (a->probes_count > 0)
    {
        struct timespec elapsed = timespec_diff_now(&a->last_probe_time);
        if (timespec_cmp(&elapsed, &a->send_wait) == -1)
        {
            struct timespec remaining = timespec_diff(&a->send_wait, &elapsed);
            usleep(timespec_to_ms(&remaining) * 1000);
        }
    }

    // time record
    if (a->probes_count == 0)
    {
        clock_gettime(CLOCK_REALTIME, &a->first_probe_time);
    }
    a->probes_count++;
    clock_gettime(CLOCK_REALTIME, &a->last_probe_time);

    printf("done\n");
    return p;
}

// 重发探针，记下重发次数
static void mt_retry(struct mt *a, struct interface *i, struct probe *p)
{
    link_write(i->link, p->probe, p->probe_len, &(p->sent_time));
    p->retries++;
}

// 遍历某个网口上的所有探针，并与响应相匹配
// 被本模块的mt_wait()调用
static void mt_receive(struct interface *i, const uint8_t *buf,
                       uint32_t len, struct timespec ts)
{
    struct list_item *it;
    for (it = i->probes->first; it != NULL; it = it->next)
    {
        struct probe *p = (struct probe *)it->data;
        if (p->sent_time.tv_sec > 0 && p->response_len == 0)
        {
            // 匹配探针
            probe_match(p, buf, len, &ts);
        }
    }
}

// 遍历某个网口上的所有探针，重发未响应的探针，几种情况除外，函数返回的是未收到响应的探针的计数

// 1. 匹配函数未空null；
// 2. 响应包长度大于0；
// 3. 响应超时，试图接收响应时间-探针发送时间；
// 4. 达到重发次数 	              总发送报数=1+retries
static int mt_unanswered_probes(struct mt *a, struct interface *i)
{
    printf("尝试重发...");
    struct list_item *it;
    int count = 0;
    for (it = i->probes->first; it != NULL; it = it->next)
    {
        struct probe *p = (struct probe *)it->data;
        if (p->fn == NULL)
            continue;
        if (p->response_len > 0)
            continue;
        if (probe_timeout(p, a->probe_timeout) == 0)
        {
            count++;
            continue;
        }
        if (p->retries == a->retries)
            continue;
        mt_retry(a, i, p);
        count++;
    }
    printf("done\n");
    return count;
}

// 尝试接收所有是未收到响应的探针的的响应包，前述几个例外除外
void mt_wait(struct mt *a, int if_index)
{
    // get network
    struct interface *i = mt_get_interface(a, if_index);
    do
    {
        // 增加1秒等待时间减少系统资源消耗
        sleep(1);

        struct pcap_pkthdr *header;
        const u_char *pkt_data;

        // 原本是if，更改为while
        printf("回收数据...");
        while (pcap_next_ex(i->pcap_handle, &header, &pkt_data) > 0)
        {
            struct timespec ts;
            ts.tv_sec = header->ts.tv_sec;
            ts.tv_nsec = header->ts.tv_usec * 1000;
            mt_receive(i, (uint8_t *)pkt_data, header->caplen, ts);
        }
        printf("done\n");

        // 重发探针
    } while (mt_unanswered_probes(a, i) > 0);
}

struct route *mt_get_route(struct mt *meta, const struct addr *dst)
{
    struct list_item *i = NULL;
    for (i = meta->routes->first; i != NULL; i = i->next)
    {
        struct route *r = (struct route *)i->data;
        int dst_size = (dst->type == ADDR_IPV4) ? ADDR_IPV4_SIZE : ADDR_IPV6_SIZE;
        if (buff_cmp(dst->addr, r->dst->addr, dst_size) == 0)
            return r;
    }
    // 初始化网卡
    struct route *r = route_create(dst);
    if (r == NULL)
        return NULL;
    list_insert(meta->routes, r);
    return r;
}

static int interface_pcap_open(struct interface *i)
{
    char pcap_error[PCAP_ERRBUF_SIZE];
    i->pcap_handle = pcap_open_live(i->if_name, MT_PCAP_SNAPLEN,
                                    MT_PCAP_PROMISC, MT_PCAP_MS,
                                    pcap_error);

    if (i->pcap_handle == NULL)
        goto fail;
    if (pcap_datalink(i->pcap_handle) != DLT_EN10MB)
        goto fail;
    if (pcap_setdirection(i->pcap_handle, PCAP_D_IN) != 0)
        goto fail;
    return 0;

fail:
    pcap_close(i->pcap_handle);
    return -1;
}

struct interface *mt_get_interface(struct mt *a, int if_index)
{
    struct list_item *it = NULL;
    // return network interface if exist
    for (it = a->interfaces->first; it != NULL; it = it->next)
    {
        struct interface *interface = (struct interface *)it->data;
        if (interface->if_index == if_index)
            return interface;
    }

    // otherwise create new network interface
    struct interface *i = malloc(sizeof(*i));
    if (i == NULL)
        return NULL;
    memset(i, 0, sizeof(*i));
    i->if_index = if_index;
    if_indextoname(if_index, i->if_name);
    // get mac address
    i->hw_addr = iface_hw_addr(if_index);
    // 使用socket开启网络
    i->link = link_open(if_index);
    i->probes = list_create();
    if (i->probes == NULL)
        return NULL;
    // use pcap to capture packets
    interface_pcap_open(i);

    // save
    list_insert(a->interfaces, i);
    return i;
}

static void mt_interface_destroy(struct interface *i)
{
    while (i->probes->count > 0)
    {
        struct probe *p = (struct probe *)list_pop(i->probes);
        probe_destroy(p);
    }
    list_destroy(i->probes);
    link_close(i->link);
    pcap_close(i->pcap_handle);
    addr_destroy(i->hw_addr);
    free(i);
}

struct neighbor *mt_get_neighbor(struct mt *a, const struct addr *dst, int if_index)
{

    struct list_item *i = NULL;
    for (i = a->neighbors->first; i != NULL; i = i->next)
    {
        struct neighbor *n = (struct neighbor *)i->data;
        int dst_size = (dst->type == ADDR_IPV4) ? ADDR_IPV4_SIZE : ADDR_IPV6_SIZE;
        if (buff_cmp(dst->addr, n->ip_addr->addr, dst_size) == 0)
            return n;
    }

    struct addr *gw = mt_nd(a, dst, if_index);
    if (gw != NULL)
    {
        struct neighbor *n = malloc(sizeof(*n));
        if (n == NULL)
        {
            addr_destroy(gw);
            return NULL;
        }
        memset(n, 0, sizeof(*n));

        n->ip_addr = addr_copy(dst);
        n->hw_addr = gw;
        n->if_index = if_index;

        list_insert(a->neighbors, n);
        return n;
    }

    return NULL;
}

void neighbor_destroy(struct neighbor *n)
{
    addr_destroy(n->ip_addr);
    addr_destroy(n->hw_addr);
    free(n);
}

static struct mt *mt_create(int wait, int send_wait, int retries)
{
    struct mt *a = malloc(sizeof(*a));
    if (a == NULL)
        return NULL;
    memset(a, 0, sizeof(*a));

    a->interfaces = list_create();
    a->neighbors = list_create();
    a->routes = list_create();
    a->retries = retries;
    a->probe_timeout = wait;
    a->send_wait = timespec_from_ms(send_wait);
    a->probes_count = 0;

    clock_gettime(CLOCK_REALTIME, &a->init_time);
    memset(&a->first_probe_time, 0, sizeof(a->first_probe_time));
    memset(&a->last_probe_time, 0, sizeof(a->last_probe_time));

    return a;
}

static void mt_destroy(struct mt *a)
{
    while (a->interfaces->count > 0)
    {
        struct interface *i = (struct interface *)list_pop(a->interfaces);
        mt_interface_destroy(i);
    }

    while (a->routes->count > 0)
    {
        struct route *r = (struct route *)list_pop(a->routes);
        route_destroy(r);
    }

    while (a->neighbors->count > 0)
    {
        struct neighbor *n = (struct neighbor *)list_pop(a->neighbors);
        neighbor_destroy(n);
    }

    list_destroy(a->routes);
    list_destroy(a->neighbors);
    list_destroy(a->interfaces);
    free(a);
}

int check_permissions(void)
{
    if (getuid() != 0) // 0 = root
    {
        printf("you must be root to run this program.\n");
        return 0;
    }
    return 1;
}

// 主程序入口
int main(int argc, char *argv[])
{
    // 检查是否有超级管理员权限
    if (!check_permissions())
        return 1;

    // 检查传入参数,并储存到args中
    printf("读取参数...");
    struct args *args = get_args(argc, argv);
    if (args == NULL)
        return 1;
    printf("done\n");

    // 初始化基本信息
    // interfaces, neighbors,routes
    // 缺少null错误处理
    // 发送探针时，只制定目标地址，没有指定网卡
    // default values, probe time out=1,send_wait=20,retries=2,probes_count=0
    printf("初始化基础信息...");
    struct mt *meta = mt_create(args->probe_time_out, args->send_wait, args->retries);
    printf("done\n");

    // 初始化地址和网络相关
    // interfaces, neighbors,routes 存入 mt
    // 部分信息存入 dst
    //调用addr_create_from_str创建struct addr 实例，两个成员，其一ipv4/ipv6,其二，ip地址
    //调用dst_create创建struct dst实例，主要工作是创建与IP地址对应的路由表项，struct mt中的routes list
    printf("初始化网络相关...\n");
    struct dst *address = dst_create_from_str(meta, args->dst);
    if (address == NULL)
    {
        printf("check the destination address\n");
        mt_destroy(meta);
        free(args);
        return 1;
    }
    printf("初始化网络相关...done\n");

    // 根据参数启动子程序
    if (args->c == CMD_PING)
    {
        printf("<<<<<开始ping>>>>>\n");
        mt_ping(meta, address, args->number_of_pings);
    }
    else if (args->c == CMD_MDA)
    {
        // 文中其他地方描述为flow type,不同的flow type会改变不同的数据包内容以应对不同的负载均衡
        // flow_type = 以下内容
        // FLOW_ICMP_CHK 1  // icmp-chk
        // FLOW_ICMP_DST 2  // icmp-dst
        // FLOW_ICMP_FL 3   // icmp-fl
        // FLOW_ICMP_TC 4   // icmp-tc
        // FLOW_UDP_SPORT 5 // udp-sport
        // FLOW_UDP_DST 6   // udp-dst
        // FLOW_UDP_FL 7    // udp-fl
        // FLOW_UDP_TC 8    // udp-tc
        // FLOW_TCP_SPORT 9 // tcp-sport
        // FLOW_TCP_DST 10  // tcp-dst
        // FLOW_TCP_FL 11   // tcp-fl
        // FLOW_TCP_TC 12   // tcp-tc
        // default value: max ttl = 30, confidence = 95, flow type = UDP SPORT
        printf("<<<<<开始paris-traceroute(MDA)>>>>>\n");
        mt_mda(meta, address, args->confidence, args->flow_type, args->max_ttl);
    }
    else if (args->c == CMD_TRACEROUTE)
    {
        // m = ICMP/UDP/TCP
        // default values: hops per round = 3, max ttl =30, packet type = ICMP
        printf("<<<<<开始paris-traceroute>>>>>\n");
        mt_traceroute(meta, address, args->packet_type, args->max_ttl, args->hops_per_round);
    }

    // 清理
    dst_destroy(address);
    mt_destroy(meta);
    free(args);

    // 退出
    return 0;
}
