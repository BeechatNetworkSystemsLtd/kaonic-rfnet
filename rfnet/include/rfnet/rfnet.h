/*
 * Copyright (c) 2025 Beechat Network Systems Ltd.
 *
 * SPDX-License-Identifier: MIT
 */

/*****************************************************************************/

#ifndef KAONIC_MODULES_RFNET_H__
#define KAONIC_MODULES_RFNET_H__

/*****************************************************************************/

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/*****************************************************************************/

#define RFNET_PACKET_DATA_SIZE (2048 - 16)

/*****************************************************************************/

typedef uint64_t rfnet_node_id_t;
typedef int64_t rfnet_time_t;

// clang-format off
typedef int (*rfnet_iface_tx_t)(void *ctx, void *data, size_t len);
typedef int (*rfnet_iface_rx_t)(void *ctx, void *data, size_t max_len);
typedef void (*rfnet_iface_gen_id_t)(void *ctx, rfnet_node_id_t *id);
typedef rfnet_time_t (*rfnet_iface_time_t)(void *ctx);
typedef void (*rfnet_iface_on_send_t)(void *ctx);
typedef void (*rfnet_iface_on_receive_t)(void *ctx, const void *data, size_t len);
// clang-format on

/**
 * @brief Interface for RF Network
 */
struct rfnet_iface {
    void* ctx;

    rfnet_iface_tx_t tx;
    rfnet_iface_rx_t rx;
    rfnet_iface_gen_id_t gen_id;
    rfnet_iface_time_t time;

    rfnet_iface_on_send_t on_send;
    rfnet_iface_on_receive_t on_receive;
};

struct rfnet_packet_header {
    uint16_t pattern;
    uint16_t type;
    uint32_t sequence;
    uint16_t reserved;
    uint16_t data_len;
    uint32_t crc;
};

struct rfnet_packet {
    struct rfnet_packet_header header;
    uint8_t data[RFNET_PACKET_DATA_SIZE];
};

struct rfnet_tdd {
    rfnet_time_t current_time;
    uint16_t slot_duration;
    uint16_t gap_duration;
    uint16_t peer_count;
};

/*
 * @brief Represents node structure
 */
struct rfnet_node {
    rfnet_node_id_t id;   /* Node Identifier */
    struct rfnet_tdd tdd; /* Time Division Duplex */
    uint16_t slot_index;
};

struct rfnet_peer {
    rfnet_node_id_t id;
    rfnet_time_t last_packet_time;
    uint32_t flags;
};

/**
 * @brief Structure is used for dynamic allocation of nodes
 */
struct rfnet_peer_storage {
    struct rfnet_peer* peers;
    size_t count;
};

struct rfnet_config {
    uint16_t packet_pattern;
    struct rfnet_iface iface;
    struct rfnet_peer_storage peer_storage;

    uint16_t beacon_interval;
    uint16_t slot_duration;
    uint16_t gap_duration;
};

struct rfnet_stats {
    uint16_t tx_sequence;
    uint16_t rx_sequence;

    size_t tx_bytes_count;
    size_t rx_bytes_count;
    size_t tx_speed;
    size_t rx_speed;

    size_t rx_counter;
    size_t tx_counter;

    rfnet_time_t last_speed_time;
};

struct rfnet {

    struct rfnet_config config;
    struct rfnet_node node;

    struct rfnet_packet rx_packet;
    struct rfnet_packet tx_packet;
    struct rfnet_packet net_packet;

    struct rfnet_stats stats;

    rfnet_time_t real_time;
    rfnet_time_t system_time;
    rfnet_time_t system_time_diff;

    rfnet_time_t last_beacon;
};

/*****************************************************************************/

void rfnet_init(struct rfnet* net, const struct rfnet_config* config);

void rfnet_update(struct rfnet* net);

/**
 * @brief Sends data to TX slot that will be sent on next time slot
 *
 * @param data
 * @param len
 */
int rfnet_send(struct rfnet* net, const void* data, size_t len);

int rfnet_is_tx_free(const struct rfnet* net);

void rfnet_get_stats(const struct rfnet* net, struct rfnet_stats* stats);

void rfnet_reset(struct rfnet* net);

/*****************************************************************************/

#endif // KAONIC_MODULES_RFNET_H__

