/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_kernel.h>
#include <fluent-bit/flb_pack.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "meminfo.h"

struct flb_input_plugin in_meminfo_plugin;

static int in_meminfo_collect(struct flb_input_instance *i_ins,
                          struct flb_config *config, void *in_context);

static uint64_t get_entry(const char* name, const char* buf)
{
    char* hit = strstr(buf, name);
    if (hit == NULL) {
        return 0;
    }

    long long bytes = strtoll(hit + strlen(name), NULL, 10);
    return (uint64_t) bytes;
}

static int meminfo_calc(char* proc_path, struct flb_in_meminfo_data *m_data)
{
    static FILE* fd;
    char buf[8192];
    size_t len;

    snprintf(buf, sizeof(buf), "%s/%s", proc_path, "meminfo");
    fd = fopen(buf, "r");
    if (fd != NULL) {
        len = fread(buf, 1, sizeof(buf) - 1, fd);
        fclose(fd);

        if(len > 0) {
            m_data->mem_total = get_entry("MemTotal:", buf);
            m_data->mem_free = get_entry("MemFree:", buf);
            m_data->mem_used = m_data->mem_total - m_data->mem_free;

            m_data->swap_total = get_entry("SwapTotal:", buf);
            m_data->swap_free = get_entry("SwapFree:", buf);
            m_data->swap_used = m_data->swap_total - m_data->swap_free;

            return 0;
        }
    }
    return -1;
}

static int in_meminfo_init(struct flb_input_instance *in,
                       struct flb_config *config, void *data)
{
    int ret;
    struct flb_in_meminfo_config *ctx;
    (void) data;
    const char *pval = NULL;

    /* Initialize context */
    ctx = flb_malloc(sizeof(struct flb_in_meminfo_config));
    if (!ctx) {
        return -1;
    }
    ctx->ins = in;

    /* meminfo file setting */
    pval = flb_input_get_property("proc_path", in);
    if (pval != NULL) {
        ctx->proc_path = flb_strdup(pval);
    } else {
       ctx->proc_path = DEFAULT_PROC_PATH;
    }

    /* Collection time setting */
    pval = flb_input_get_property("interval_sec", in);
    if (pval != NULL && atoi(pval) > 0) {
        ctx->interval_sec = atoi(pval);
    }
    else {
        ctx->interval_sec = DEFAULT_INTERVAL_SEC;
    }
    ctx->interval_nsec = DEFAULT_INTERVAL_NSEC;

    /* Set the context */
    flb_input_set_context(in, ctx);

    /* Set the collector */
    ret = flb_input_set_collector_time(in,
                                       in_meminfo_collect,
                                       ctx->interval_sec,
                                       ctx->interval_nsec,
                                       config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not set collector for memory input plugin");
    }

    return 0;
}

static int in_meminfo_collect(struct flb_input_instance *i_ins,
                              struct flb_config *config, void *in_context)
{
    int ret;
    int len;
    int entries = 6;/* (total,used,free) * (memory, swap) */
    struct flb_in_meminfo_config *ctx = in_context;
    struct flb_in_meminfo_data data;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    ret = meminfo_calc(ctx->proc_path, &data);
    if (ret == -1) {
        return -1;
    }

    /* Initialize local msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Pack the data */
    msgpack_pack_array(&mp_pck, 2);
    flb_pack_time_now(&mp_pck);
    msgpack_pack_map(&mp_pck, entries);

    msgpack_pack_str(&mp_pck, 9);
    msgpack_pack_str_body(&mp_pck, "Mem.total", 9);
    msgpack_pack_uint64(&mp_pck, data.mem_total);

    msgpack_pack_str(&mp_pck, 8);
    msgpack_pack_str_body(&mp_pck, "Mem.used", 8);
    msgpack_pack_uint64(&mp_pck, data.mem_used);

    msgpack_pack_str(&mp_pck, 8);
    msgpack_pack_str_body(&mp_pck, "Mem.free", 8);
    msgpack_pack_uint64(&mp_pck, data.mem_free);

    msgpack_pack_str(&mp_pck, 10);
    msgpack_pack_str_body(&mp_pck, "Swap.total", 10);
    msgpack_pack_uint64(&mp_pck, data.swap_total);

    msgpack_pack_str(&mp_pck, 9);
    msgpack_pack_str_body(&mp_pck, "Swap.used", 9);
    msgpack_pack_uint64(&mp_pck, data.swap_used);

    msgpack_pack_str(&mp_pck, 9);
    msgpack_pack_str_body(&mp_pck, "Swap.free", 9);
    msgpack_pack_uint64(&mp_pck, data.swap_free);

    ++ctx->idx;

    flb_input_chunk_append_raw(i_ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    return 0;
}

static int in_meminfo_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_in_meminfo_config *ctx = data;

    if (!ctx) {
        return 0;
    }

    /* done */
    flb_free(ctx);

    return 0;
}

struct flb_input_plugin in_meminfo_plugin = {
    .name         = "meminfo",
    .description  = "Memory info",
    .cb_init      = in_meminfo_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_meminfo_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_meminfo_exit
};
