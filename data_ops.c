#include "data_ops.h"

#include <malloc.h>
#include <stdio.h>
#include <string.h>

#define HICUT_DEBUG 1

#if HICUT_DEBUG == 1
struct sizes_and_counts {
	uint32_t custom_size;
	uint32_t rule_count;
	size_t rules_size;
	uint32_t child_count;
	size_t children_size;
};

static uint32_t total_rule_count;
static struct sizes_and_counts max_size;
#endif

void hicut_serialize_node(FILE *fp, ctrie node, uint32_t *node_index,
			  struct ENTRY *table)
{
	struct custom_data_header header = {
		.custom_size = 0,
	};

	struct hicut_node_header node_header = {
		.cut_dim = node->cut_dim,
		.bit_length = node->bit_length,
		.src_addr_has_check = node->src_addr_had_check,
		.des_addr_has_check = node->des_addr_had_check,
		.src_port_has_check = node->src_port_had_check,
		.des_port_has_check = node->des_addr_had_check,
		.ptc_has_check = node->ptc_had_check,
	};
	header.custom_size += sizeof(node_header);

	uint32_t rule_count = node->arraySize;
	size_t rules_size = sizeof(struct hicut_rules) +
			    sizeof(struct hicut_rule) * rule_count;
	struct hicut_rules *rules = malloc(rules_size);
	rules->count = rule_count;
	for (uint32_t i = 0; i < rule_count; ++i) {
		struct hicut_rule *rule = rules->data + i;
		struct ENTRY *entry = table + node->index_array[i];

		rule->src_ip = entry->src_ip;
		rule->src_len = entry->src_len;
		rule->des_ip = entry->des_ip;
		rule->des_len = entry->des_len;
		rule->src_port_start = entry->src_port_start;
		rule->src_port_end = entry->src_port_end;
		rule->des_port_start = entry->des_port_start;
		rule->des_port_end = entry->des_port_end;
		rule->protocol = entry->protocol;
	}
	header.custom_size += rules_size;

	uint32_t child_count;
	if (node->child != NULL) {
		// child_count = malloc_usable_size(node->child);
		child_count = 1 << node->bit_length;
	} else {
		child_count = 0;
	}
	size_t children_size =
		sizeof(struct hicut_children) + sizeof(uint32_t) * child_count;
	struct hicut_children *children = malloc(children_size);
	children->count = child_count;
	for (uint32_t i = 0; i < child_count; ++i) {
		children->indexes[i] = *node_index;
		hicut_serialize_node(fp, &node->child[i], node_index, table);
	}
	header.custom_size += children_size;

#if HICUT_DEBUG == 1
	total_rule_count += rule_count;
	if (max_size.custom_size < header.custom_size) {
		max_size.custom_size = header.custom_size;
		max_size.rule_count = rule_count;
		max_size.rules_size = rules_size;
		max_size.child_count = child_count;
		max_size.children_size = children_size;
	}
#endif

	fwrite(&header, sizeof(header), 1, fp);
	fwrite(&node_header, sizeof(node_header), 1, fp);
	fwrite(rules, rules_size, 1, fp);
	fwrite(children, children_size, 1, fp);

	free(rules);
	free(children);

	++*node_index;
}

void hicut_serialize(FILE *fp, ctrie root, struct ENTRY *table)
{
	struct data_header header = {
		.data_num = 0,
	};

#if HICUT_DEBUG == 1
	total_rule_count = 0;
	memset(&max_size, 0, sizeof(max_size));
#endif

	fseek(fp, sizeof(header), SEEK_CUR);
	hicut_serialize_node(fp, root, &header.data_num, table);

#if HICUT_DEBUG == 1
	printf("Serialized rule count: %u\n", total_rule_count);
	printf("Max custom size: %uB = ... + %u rules (%luB) + %u children (%luB)\n",
	       max_size.custom_size, max_size.rule_count, max_size.rules_size,
	       max_size.child_count, max_size.children_size);
#endif

	fseek(fp, 0, SEEK_SET);
	fwrite(&header, sizeof(header), 1, fp);
}

void hicut_deserialize(FILE *fp, ctrie *root, struct ENTRY **table,
		       int *num_entry)
{
	return;
}
