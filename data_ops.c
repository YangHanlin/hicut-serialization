#include "data_ops.h"

#include <malloc.h>
#include <stdio.h>
#include <string.h>

#define HICUT_DEBUG 1

struct hicut_rule_list_node {
	struct hicut_rule data;
	struct hicut_rule_list_node *next;
};

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

void hicut_deserialize_rules(FILE *fp, struct ENTRY **table, int *num_entry)
{
	struct custom_data_header header = { 0 };
	uint32_t count = 0;
	struct hicut_rule_list_node *head = malloc(sizeof(
					    struct hicut_rule_list_node)),
				    *tail = head;
	head->next = NULL;

	while (1) {
		fread(&header, sizeof(header), 1, fp);
		if (header.type != HICUT_RULE) {
			break;
		}

		if (header.custom_size != sizeof(struct hicut_rule)) {
			// Unexpected error
		}

		tail->next = malloc(sizeof(struct hicut_rule_list_node));
		tail = tail->next;
		tail->next = NULL;
		fread(&tail->data, sizeof(tail->data), 1, fp);
		++count;
	}
	fseek(fp, -sizeof(header), SEEK_CUR);

#ifdef HICUT_DEBUG
	printf("Found %u rules in total\n", count);
#endif

	*num_entry = count;
	*table = malloc(sizeof(struct ENTRY) * count);
	for (uint32_t i = 0; i < count; ++i) {
		struct hicut_rule *rule = &head->next->data;
		struct ENTRY *entry = *table + i;
		entry->src_ip = rule->src_ip;
		entry->src_len = rule->src_len;
		entry->des_ip = rule->des_ip;
		entry->des_len = rule->des_len;
		entry->src_port_start = rule->src_port_start;
		entry->src_port_end = rule->src_port_end;
		entry->des_port_start = rule->des_port_start;
		entry->des_port_end = rule->des_port_end;

		struct hicut_rule_list_node *t = head->next;
		free(head);
		head = t;
	}
}

void hicut_deserialize_tree(FILE *fp, ctrie *root, uint32_t count)
{
	// TODO:
}

void hicut_deserialize(FILE *fp, ctrie *root, struct ENTRY **table,
		       int *num_entry)
{
	struct data_header header = {
		.data_num = 0,
	};
	fread(&header, sizeof(header), 1, fp);

	hicut_deserialize_rules(fp, table, num_entry);
	hicut_deserialize_tree(fp, root, header.data_num - *num_entry);
}
