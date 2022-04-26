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
#include <arpa/inet.h>

#include "pdu_ipv4.h"
#include "pdu_ipv6.h"
#include "checksum.h"
#include "protocol_numbers.h"
#include "pdu_udp.h"

int pdu_udp(struct packet *p, uint16_t src_port, uint16_t dst_port,
            uint16_t length, uint16_t checksum)
{

    struct udp_hdr hdr;
    memset(&hdr, 0, UDP_H_SIZE);

    hdr.src_port = htons(src_port);
    hdr.dst_port = htons(dst_port);
    hdr.length = htons(length);
    hdr.checksum = checksum;

    uint8_t tag = packet_block_append(p, PACKET_BLOCK_UDP, &hdr,
                                      UDP_H_SIZE);

    return tag;
}

int pdu_udp_length(struct packet *p, int tag)
{
    struct packet_block *b = packet_block_get(p, tag);
    if (b == NULL || b->type != PACKET_BLOCK_UDP)
        return -1;
    struct udp_hdr *hdr = (struct udp_hdr *)&p->buf[b->position];
    hdr->length = htons(p->length - b->position);
    return 0;
}

int pdu_udp_checksum(struct packet *p, int tag, int ip_tag)
{

    struct packet_block *b = packet_block_get(p, tag);
    if (b == NULL || b->type != PACKET_BLOCK_UDP)
        return -1;
    struct udp_hdr *hdr = (struct udp_hdr *)&p->buf[b->position];

    struct packet_block *ipb = packet_block_get(p, ip_tag);
    if (ipb == NULL)
        return -1;

    void *ph_ptr = NULL;
    int ph_size = 0;

    if (ipb->type == PACKET_BLOCK_IPV4)
    {
        struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)&p->buf[ipb->position];
        ph_ptr = pdu_ipv4_ph(ipv4_hdr->src_addr, ipv4_hdr->dst_addr,
                             PROTO_UDP, hdr->length);
        ph_size = IPV4_PH_SIZE;
    }
    else if (ipb->type == PACKET_BLOCK_IPV6)
    {
        struct ipv6_hdr *ipv6_hdr = (struct ipv6_hdr *)&p->buf[ipb->position];
        ph_ptr = pdu_ipv6_ph(ipv6_hdr->src_addr, ipv6_hdr->dst_addr,
                             hdr->length, PROTO_UDP);
        ph_size = IPV6_PH_SIZE;
    }
    else
    {
        return -1;
    }

    // Make sure the checksum field is 0 before calculating the checksum
    hdr->checksum = 0;

    // Create the buffer for checksum
    uint32_t len = (p->length - b->position) + ph_size;
    uint8_t *buf = malloc(len);
    memcpy(buf, ph_ptr, ph_size);
    memcpy(&buf[ph_size], hdr, len - ph_size);
    free(ph_ptr);

    hdr->checksum = checksum((uint16_t *)buf, len);
    free(buf);

    return 0;
}
