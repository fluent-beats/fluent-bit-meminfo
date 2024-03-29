/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Etriphany
 *  ==========
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

#ifndef FLB_IN_MEMINFO_H
#define FLB_IN_MEMINFO_H

#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_utils.h>
#include <msgpack.h>

#define DEFAULT_INTERVAL_SEC  1
#define DEFAULT_INTERVAL_NSEC 0
#define DEFAULT_PROC_PATH "/proc"

struct flb_in_meminfo_data {
    uint64_t mem_total;
    uint64_t mem_used;
    uint64_t mem_free;
    uint64_t mem_available;
    uint64_t mem_cached;
    uint64_t swap_total;
    uint64_t swap_used;
    uint64_t swap_free;
};

struct flb_in_meminfo_config {
    char *proc_path;
    int interval_sec;
    int interval_nsec;
    struct flb_input_instance *ins;
};

#endif
