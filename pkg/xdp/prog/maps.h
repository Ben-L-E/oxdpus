/*
 * Copyright (c) Sematext Group, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 */

#define SEC(NAME) __attribute__((section(NAME), used))

static void *(*bpf_map_lookup_elem)(void *map, void *key) = (void *) BPF_FUNC_map_lookup_elem;

#define BUF_SIZE_MAP_NS 256
#define PIN_GLOBAL_NS 2

struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
    unsigned int pinning;
    char namespace[BUF_SIZE_MAP_NS];
};

struct bpf_map_def SEC("maps/blacklist1") blacklist1 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65536,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};


struct bpf_map_def SEC("maps/blacklist2") blacklist2 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist3") blacklist3 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist4") blacklist4 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist5") blacklist5 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist6") blacklist6 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist7") blacklist7 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist8") blacklist8 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist9") blacklist9 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist10") blacklist10 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist11") blacklist11 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist12") blacklist12 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist13") blacklist13 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist14") blacklist14 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist15") blacklist15 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist16") blacklist16 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist17") blacklist17 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist18") blacklist18 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist19") blacklist19 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist20") blacklist20 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist21") blacklist21 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist22") blacklist22 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist23") blacklist23 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist24") blacklist24 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist25") blacklist25 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist26") blacklist26 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist27") blacklist27 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist28") blacklist28 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist29") blacklist29 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist30") blacklist30 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist31") blacklist31 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist32") blacklist32 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist33") blacklist33 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist34") blacklist34 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist35") blacklist35 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist36") blacklist36 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist37") blacklist37 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist38") blacklist38 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist39") blacklist39 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist40") blacklist40 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist41") blacklist41 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist42") blacklist42 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist43") blacklist43 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist44") blacklist44 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist45") blacklist45 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/blacklist46") blacklist46 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 65535,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};
