/*
 * Copyright (c) 2025 Beechat Network Systems Ltd.
 *
 * SPDX-License-Identifier: MIT
 */

/*****************************************************************************/

#include "rfnet/rfnet.h"

#include <string.h>

#ifdef RFNET_PORT_INCLUDE
#include "rfnet_port.h"
#else

// Default implementation
#define rfnet_log(...)

#endif

/*****************************************************************************/

#define RFNET_PEER_FLG_ALLOC (0x01)

/*****************************************************************************/

enum rfnet_packet_type {
    RFNET_PACKET_TYPE_ADV = 0x00AA,
    RFNET_PACKET_TYPE_PAYLOAD = 0x000AB,
};

/*****************************************************************************/

static rfnet_time_t get_real_time(struct rfnet* net) {
    return net->config.iface.time(net->config.iface.ctx);
}

static rfnet_time_t time_interval(struct rfnet* net, rfnet_time_t last_time) {
    return (net->real_time - last_time);
}

static bool interval_triggered(struct rfnet* net, rfnet_time_t* last_time, rfnet_time_t interval) {
    const bool triggered = time_interval(net, *last_time) >= interval;
    if (triggered) {
        *last_time = net->real_time;
    }
    return triggered;
}

static uint32_t calculate_crc(uint32_t init, const uint8_t* data, size_t len) {

    static const uint32_t table[16] = {
        0x00000000u, 0x1DB71064u, 0x3B6E20C8u, 0x26D930ACu, 0x76DC4190u, 0x6B6B51F4u,
        0x4DB26158u, 0x5005713Cu, 0xEDB88320u, 0xF00F9344u, 0xD6D6A3E8u, 0xCB61B38Cu,
        0x9B64C2B0u, 0x86D3D2D4u, 0xA00AE278u, 0xBDBDF21Cu,
    };

    uint32_t crc = init;

    crc = ~crc;

    for (size_t i = 0u; i < len; ++i) {
        const uint8_t byte = data[i];

        crc = (crc >> 4u) ^ table[(crc ^ byte) & 0x0Fu];
        crc = (crc >> 4u) ^ table[(crc ^ ((uint32_t)byte >> 4u)) & 0x0Fu];
    }

    return (~crc);
}

static uint32_t calculate_packet_crc(const struct rfnet_packet* packet) {

    const uint8_t* const packet_raw = (const uint8_t*)packet;

    const size_t header_len = sizeof(packet->header);

    uint32_t crc = 0;
    crc = calculate_crc(crc, &packet_raw[0], header_len - sizeof(packet->header.crc));
    crc = calculate_crc(crc, &packet_raw[header_len], packet->header.data_len);

    return crc;
}

static void generate_node_id(struct rfnet* net) {
    net->config.iface.gen_id(net->config.iface.ctx, &net->node.id);
}

static int receive_packet(struct rfnet* net, struct rfnet_packet* packet) {

    int rc;

    rc = net->config.iface.rx(net->config.iface.ctx, packet, sizeof(*packet));

    if (rc >= (int)sizeof(packet->header)) {
        rc = -1;
        const uint32_t actual_crc = calculate_packet_crc(packet);
        if (actual_crc == packet->header.crc) {
            rc = 0;
        } else {
            rfnet_log(">> corrupted frame (%08X != %08X) <<", actual_crc, packet->header.crc);
        }
    } else {
        rc = -1;
    }

    return rc;
}

static int transmit_packet(struct rfnet* net, struct rfnet_packet* packet) {

    packet->header.sequence = net->stats.tx_sequence;
    packet->header.pattern = net->config.packet_pattern;
    packet->header.crc = calculate_packet_crc(packet);

    ++net->stats.tx_sequence;
    ++net->stats.tx_counter;

    net->stats.tx_bytes_count += packet->header.data_len;

    return net->config.iface.tx(
        net->config.iface.ctx, packet, sizeof(packet->header) + packet->header.data_len);
}

static struct rfnet_peer* add_peer(struct rfnet* net, rfnet_node_id_t id) {

    struct rfnet_peer_storage* const peer_storage = &net->config.peer_storage;

    struct rfnet_peer* result_peer = NULL;
    struct rfnet_peer* free_peer = NULL;

    for (size_t i = 0; i < peer_storage->count; ++i) {

        struct rfnet_peer* const peer = &peer_storage->peers[i];

        if ((peer->flags & RFNET_PEER_FLG_ALLOC) != 0) {
            if (peer->id == id) {
                result_peer = peer;
                break;
            }
        } else {
            if (free_peer == NULL) {
                free_peer = peer;
            }
        }
    }

    if (free_peer != NULL && result_peer == NULL) {

        rfnet_log("add new peer 0x%08llX\n\r", id);

        free_peer->id = id;
        free_peer->flags |= RFNET_PEER_FLG_ALLOC;

        ++net->node.tdd.peer_count;

        result_peer = free_peer;
    }

    if (result_peer != NULL) {
        result_peer->last_packet_time = net->system_time;
    }

    return result_peer;
}

static void sync_time(struct rfnet* net, const struct rfnet_node* adv_node) {
    struct rfnet_peer_storage* const peer_storage = &net->config.peer_storage;

    size_t slot_index = 0;

    rfnet_node_id_t max_id = net->node.id;

    for (size_t i = 0; i < peer_storage->count; ++i) {

        const struct rfnet_peer* const peer = &peer_storage->peers[i];

        if ((peer->flags & RFNET_PEER_FLG_ALLOC) != 0) {
            if (peer->id > net->node.id) {
                ++slot_index;
            }

            if (max_id < peer->id) {
                max_id = peer->id;
            }
        }
    }

    rfnet_node_id_t clock_id = net->node.id;
    rfnet_time_t rtime_diff = 0;
    if (adv_node != NULL && adv_node->id >= max_id) {
        clock_id = adv_node->id;
        rtime_diff = adv_node->tdd.current_time - net->system_time;
        net->node.tdd = adv_node->tdd;
        net->system_time_diff = adv_node->tdd.current_time - get_real_time(net);
    }

    if (max_id == net->node.id) {
        net->node.tdd.current_time = get_real_time(net);
        net->system_time_diff = 0;
    }

    rfnet_log("CLK (%08llX) t:%lld dT:%lld rT:%lld\n\r",
              clock_id,
              net->node.tdd.current_time,
              net->system_time_diff,
              rtime_diff);

    net->node.slot_index = slot_index;
}

static void handle_packet(struct rfnet* net, const struct rfnet_packet* packet) {

    if (packet->header.pattern == net->config.packet_pattern) {

        ++net->stats.rx_counter;

        switch ((enum rfnet_packet_type)packet->header.type) {

            case RFNET_PACKET_TYPE_ADV: {
                struct rfnet_node adv_node;

                if (sizeof(adv_node) <= packet->header.data_len) {
                    memcpy(&adv_node, packet->data, sizeof(adv_node));

                    add_peer(net, adv_node.id);

                    sync_time(net, &adv_node);
                }
            } break;

            case RFNET_PACKET_TYPE_PAYLOAD:
                if ((packet->header.data_len > 0) && net->config.iface.on_receive != NULL) {
                    net->config.iface.on_receive(
                        net->config.iface.ctx, packet->data, packet->header.data_len);
                }

                net->stats.rx_bytes_count += packet->header.data_len;

                break;
        }
    }
}

static int send_advertise(struct rfnet* net) {

    net->node.tdd.current_time = get_real_time(net);

    net->net_packet.header.type = RFNET_PACKET_TYPE_ADV;
    net->net_packet.header.data_len = sizeof(net->node);
    memcpy(net->net_packet.data, &net->node, sizeof(net->node));

    return transmit_packet(net, &net->net_packet);
}

static int send_payload(struct rfnet* net) {
    if (net->tx_packet.header.data_len == 0) {
        return 0;
    }

    net->tx_packet.header.type = RFNET_PACKET_TYPE_PAYLOAD;

    const int rc = transmit_packet(net, &net->tx_packet);

    // Reset tx packet
    net->tx_packet.header.data_len = 0;

    return rc;
}

static bool is_current_slot(struct rfnet* net) {

    size_t peer_count = net->node.tdd.peer_count + 1u;
    if (peer_count == 1) {
        peer_count = 2;
    }

    const rfnet_time_t frame_duration =
        ((rfnet_time_t)net->node.tdd.slot_duration * (rfnet_time_t)(peer_count));

    const rfnet_time_t slot_time = (net->system_time % frame_duration);
    const rfnet_time_t slot_start_time = net->node.tdd.slot_duration * net->node.slot_index;
    const rfnet_time_t slot_end_time =
        slot_start_time + net->node.tdd.slot_duration - net->node.tdd.gap_duration;

    return (slot_time >= slot_start_time && slot_time <= slot_end_time);
}

static void update_time(struct rfnet* net) {
    net->real_time = get_real_time(net);

    if (interval_triggered(net, &net->stats.last_speed_time, 1000)) {

        net->stats.rx_speed = net->stats.rx_bytes_count;
        net->stats.tx_speed = net->stats.tx_bytes_count;

        net->stats.tx_bytes_count = 0;
        net->stats.rx_bytes_count = 0;
    }

    net->system_time = net->real_time + net->system_time_diff;
}

/*****************************************************************************/

void rfnet_init(struct rfnet* net, const struct rfnet_config* config) {

    if ((net != NULL) && (config != NULL)) {

        // Reset to zero
        *net = (struct rfnet) { 0 };

        net->config = *config;

        // Generate new node id
        generate_node_id(net);

        // Default TDD config
        net->node.tdd.slot_duration = 50;
        net->node.tdd.gap_duration = 5;

        rfnet_log("create new node %08llX", net->node.id);
    }
}

void rfnet_update(struct rfnet* net) {

    update_time(net);

    if (is_current_slot(net)) {
        if (interval_triggered(net, &net->last_beacon, net->config.beacon_interval)) {
            send_advertise(net);
        } else {
            send_payload(net);
        }
    } else {
        if (receive_packet(net, &net->rx_packet) == 0) {
            handle_packet(net, &net->rx_packet);
        }
    }
}

int rfnet_send(struct rfnet* net, const void* data, size_t len) {
    int rc = -1;

    if (rfnet_is_tx_free(net) == 0) {
        if ((data != NULL) && (len > 0) && (len <= RFNET_PACKET_DATA_SIZE)) {
            memcpy(net->tx_packet.data, data, len);
            net->tx_packet.header.data_len = len;
            rc = 0;
        }
    }

    return rc;
}

int rfnet_is_tx_free(const struct rfnet* net) {
    return (net->tx_packet.header.data_len == 0) ? 0 : -1;
}

void rfnet_get_stats(const struct rfnet* net, struct rfnet_stats* stats) {
    *stats = net->stats;
}

void rfnet_reset(struct rfnet* net) {

    rfnet_log("reset network");

    memset(net->config.peer_storage.peers,
           0x00,
           sizeof(struct rfnet_peer) * net->config.peer_storage.count);

    net->node.slot_index = 0;
    net->node.tdd.peer_count = 0;
    net->system_time_diff = 0;

    memset(&net->stats, 0x00, sizeof(net->stats));
}

/*****************************************************************************/
