#include "data_ops.h"

#include <malloc.h>
#include <stdio.h>
#include <string.h>

#define HICUT_DEBUG 1

#if HICUT_DEBUG == 1
struct sizes_and_counts {
	uint32_t node_custom_size;
	uint32_t rule_count;
	size_t rules_size;
	uint32_t child_count;
	size_t children_size;
};

static struct sizes_and_counts max_size;
#endif

void hicut_serialize_tree(FILE *fp, ctrie node, uint32_t *node_index)
{
	struct custom_data_header header = {
		.custom_size = 0,
		.type = HICUT_NODE,
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
	size_t rules_size =
		sizeof(struct hicut_node_rules) + sizeof(uint32_t) * rule_count;
	struct hicut_node_rules *rules = malloc(rules_size);
	rules->count = rule_count;
	for (uint32_t i = 0; i < rule_count; ++i) {
		rules->indexes[i] = node->index_array[i];
	}
	header.custom_size += rules_size;

	uint32_t child_count;
	if (node->child != NULL) {
		child_count = 1 << node->bit_length;
	} else {
		child_count = 0;
	}
	size_t children_size = sizeof(struct hicut_node_children) +
			       sizeof(uint32_t) * child_count;
	struct hicut_node_children *children = malloc(children_size);
	children->count = child_count;
	for (uint32_t i = 0; i < child_count; ++i) {
		children->indexes[i] = *node_index;
		hicut_serialize_tree(fp, &node->child[i], node_index);
	}
	header.custom_size += children_size;

#if HICUT_DEBUG == 1
	if (max_size.node_custom_size < header.custom_size) {
		max_size.node_custom_size = header.custom_size;
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

void hicut_serialize_rules(FILE *fp, struct ENTRY *table, int num_entry)
{
	struct custom_data_header header = {
		.custom_size = sizeof(struct hicut_rule),
		.type = HICUT_RULE,
	};
	struct hicut_rule rule = { 0 };

	for (struct ENTRY *p = table; p < table + num_entry; ++p) {
		rule.src_ip = p->src_ip;
		rule.src_len = p->src_len;
		rule.des_ip = p->des_ip;
		rule.des_len = p->des_len;
		rule.src_port_start = p->src_port_start;
		rule.src_port_end = p->src_port_end;
		rule.des_port_start = p->des_port_start;
		rule.des_port_end = p->des_port_end;
		rule.protocol = p->protocol;

		fwrite(&header, sizeof(header), 1, fp);
		fwrite(&rule, sizeof(rule), 1, fp);
	}
}

void hicut_serialize(FILE *fp, ctrie root, struct ENTRY *table, int num_entry)
{
	struct data_header header = {
		.data_num = 0,
	};
	uint32_t node_count = 0;

#if HICUT_DEBUG == 1
	memset(&max_size, 0, sizeof(max_size));
#endif

	fseek(fp, sizeof(header), SEEK_CUR);
	hicut_serialize_rules(fp, table, num_entry);
	header.data_num += num_entry;
	hicut_serialize_tree(fp, root, &node_count);
	header.data_num += node_count;

#if HICUT_DEBUG == 1
	printf("Total serialized custom data blocks: %u\n", header.data_num);
	printf("Max node custom size: %uB = ... + %u rules (%luB) + %u children (%luB)\n",
	       max_size.node_custom_size, max_size.rule_count,
	       max_size.rules_size, max_size.child_count,
	       max_size.children_size);
#endif

	fseek(fp, 0, SEEK_SET);
	fwrite(&header, sizeof(header), 1, fp);
}

void hicut_deserialize(FILE *fp, ctrie *root, struct ENTRY **table,
		       int *num_entry)
{
	return;
}
