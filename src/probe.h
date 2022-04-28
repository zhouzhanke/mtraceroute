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

#ifndef __PROBE_H__
#define __PROBE_H__

#include <stdint.h>
#include <time.h>

typedef int (*match_fn)(const uint8_t *, uint32_t, const uint8_t *, uint32_t);

struct probe
{
    int if_index; // 网络
    int retries; // 已重试次数
    struct timespec sent_time; // 发送时间
    struct timespec response_time; // 回收时间
    uint8_t *probe; // 探针
    uint32_t probe_len; // 探针数据长度
    uint8_t *response; // 探针返回结果
    uint32_t response_len; // 返回数据长度
    match_fn fn; // 在发送时存入比较函数
};

struct probe *probe_create(const uint8_t *probe, uint32_t probe_len, match_fn fn);

void probe_destroy(struct probe *p);

int probe_timeout(const struct probe *p, int timeout);

int probe_match(struct probe *p, const uint8_t *buf, uint32_t len,
                const struct timespec *ts);

#endif // __PROBE_H__
