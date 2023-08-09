#ifndef DATA_OPS_H
#define DATA_OPS_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include "HiCut-zhu849.h"

/**
 * Serialized data format = data_header + custom_data[]
 * custom_data = custom_data_header + hicut_node_header + hicut_rules + hicut_children
 */

struct data_header {
	uint32_t data_num;
};

struct custom_data_header {
	uint32_t custom_size;
};

enum hicut_dimension {
	HICUT_NONE,
	HICUT_SRCIP,
	HICUT_DESIP,
	HICUT_SRCPORT,
	HICUT_DESPORT,
	HICUT_PROTOCOL
};

struct hicut_node_header {
	enum hicut_dimension cut_dim;
	uint8_t bit_length;
	uint8_t src_addr_has_check : 1, des_addr_has_check : 1,
		src_port_has_check : 1, des_port_has_check : 1,
		ptc_has_check : 1;
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

struct hicut_rules {
	uint32_t count;
	struct hicut_rule data[];
};

struct hicut_children {
	uint32_t count;
	uint32_t indexes[];
};

void hicut_serialize(FILE *fp, ctrie root, struct ENTRY *table);

void hicut_deserialize(FILE *fp, ctrie *root, struct ENTRY **table,
		       int *num_entry);

#endif
