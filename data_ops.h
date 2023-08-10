#ifndef DATA_OPS_H
#define DATA_OPS_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include "HiCut-zhu849.h"

/**
 * Serialized data format = data_header + custom_data_rule[] + custom_data_node[]
 * custom_data_rule = custom_data_header (type = HICUT_RULE) + hicut_rule
 * custom_data_node = custom_data_header (type = HICUT_NODE) + hicut_node_header + hicut_node_rules + hicut_node_children
 */

#pragma pack(push, 1)

struct data_header {
	uint32_t data_num;
};

enum custom_data_type {
	HICUT_RULE,
	HICUT_NODE,
};

struct custom_data_header {
	uint32_t custom_size;
	enum custom_data_type type;
};

struct hicut_rule {
	uint32_t src_ip;
	uint8_t src_len;
	uint32_t des_ip;
	uint8_t des_len;
	uint16_t src_port_start;
	uint16_t src_port_end;
	uint16_t des_port_start;
	uint16_t des_port_end;
	uint8_t protocol;
};

enum hicut_dimension {
	HICUT_NONE,
	HICUT_SRCIP,
	HICUT_DESIP,
	HICUT_SRCPORT,
	HICUT_DESPORT,
	HICUT_PROTOCOL,
};

struct hicut_node_header {
	enum hicut_dimension cut_dim;
	uint8_t bit_length;
	uint8_t src_addr_had_check;
	uint8_t des_addr_had_check;
	uint8_t src_port_had_check;
	uint8_t des_port_had_check;
	uint8_t ptc_had_check;
};

struct hicut_node_rules {
	uint32_t count;
	uint32_t indexes[];
};

struct hicut_node_children {
	uint32_t count;
	uint32_t indexes[];
};

#pragma pack(pop)

void hicut_serialize(FILE *fp, ctrie root, struct ENTRY *table, int num_entry);

void hicut_deserialize(FILE *fp, ctrie *root, struct ENTRY **table,
		       int *num_entry);

#endif
