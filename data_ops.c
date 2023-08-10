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

void _hicut_serialize_tree(FILE *fp, ctrie node, uint32_t *current_node_count)
{
	struct custom_data_header header = {
		.custom_size = 0,
		.type = HICUT_NODE,
	};

	struct hicut_node_header node_header = {
		.cut_dim = node->cut_dim,
		.bit_length = node->bit_length,
		.src_addr_had_check = node->src_addr_had_check,
		.des_addr_had_check = node->des_addr_had_check,
		.src_port_had_check = node->src_port_had_check,
		.des_port_had_check = node->des_port_had_check,
		.ptc_had_check = node->ptc_had_check,
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
		_hicut_serialize_tree(fp, &node->child[i], current_node_count);
		children->indexes[i] = *current_node_count - 1;
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

	++*current_node_count;
}

uint32_t hicut_serialize_tree(FILE *fp, ctrie root)
{
	uint32_t node_count = 0;
	_hicut_serialize_tree(fp, root, &node_count);
	return node_count;
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

#if HICUT_DEBUG == 1
	memset(&max_size, 0, sizeof(max_size));
#endif

	fseek(fp, sizeof(header), SEEK_CUR);
	hicut_serialize_rules(fp, table, num_entry);
	header.data_num += num_entry;
	uint32_t node_count = hicut_serialize_tree(fp, root);
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
	struct custom_data_header header = { 0 };
	struct hicut_node_header node_header = { 0 };
	uint32_t rule_count = 0, *rule_indexes = NULL;
	bnode *children = NULL;

	size_t child_counts_size = sizeof(uint32_t) * count;
	uint32_t *child_counts = malloc(child_counts_size);
	memset(child_counts, 0, child_counts_size);

	size_t child_indexes_size = sizeof(uint32_t *) * count;
	uint32_t **child_indexes = malloc(child_indexes_size);
	memset(child_indexes, 0, child_indexes_size);

	size_t nodes_size = sizeof(bnode) * count;
	bnode *nodes = malloc(nodes_size);
	memset(nodes, 0, nodes_size);

	for (uint32_t i = 0; i < count; ++i) {
		fread(&header, sizeof(header), 1, fp);
		if (header.type != HICUT_NODE) {
			// Unexpected error
		}

		fread(&node_header, sizeof(node_header), 1, fp);
		bnode *node = nodes + i;
		node->cut_dim = node_header.cut_dim;
		node->bit_length = node_header.bit_length;
		node->src_addr_had_check = node_header.src_addr_had_check;
		node->des_addr_had_check = node_header.des_addr_had_check;
		node->src_port_had_check = node_header.src_port_had_check;
		node->des_port_had_check = node_header.des_port_had_check;
		node->ptc_had_check = node_header.ptc_had_check;

		fread(&rule_count, sizeof(rule_count), 1, fp);
		node->arraySize = rule_count;
		if (rule_count > 0) {
			rule_indexes = malloc(sizeof(uint32_t) * rule_count);
			fread(rule_indexes, sizeof(uint32_t), rule_count, fp);
			node->index_array =
				malloc(sizeof(unsigned int) * rule_count);
			for (uint32_t j = 0; j < rule_count; ++j) {
				node->index_array[j] = rule_indexes[j];
			}
			free(rule_indexes);
			rule_indexes = NULL;
		}

		fread(child_counts + i, sizeof(uint32_t), 1, fp);
		child_indexes[i] = malloc(sizeof(uint32_t) * child_counts[i]);
		fread(child_indexes[i], sizeof(uint32_t), child_counts[i], fp);
	}

	// It's assumed that every node appears before its parent
	for (uint32_t i = 0; i < count; ++i) {
		if (child_counts[i] == 0) {
			continue;
		}
		children = malloc(sizeof(bnode) * child_counts[i]);
		for (uint32_t j = 0; j < child_counts[i]; ++j) {
			memcpy(children + j, nodes + child_indexes[i][j],
			       sizeof(bnode));
		}
		nodes[i].child = children;
	}
	*root = nodes + count - 1;

#ifdef HICUT_DEBUG
	printf("Deserialized %u tree nodes in total\n", count);
#endif
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
