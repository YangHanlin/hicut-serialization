#ifndef HICUT_ZHU849_H
#define HICUT_ZHU849_H

enum fiveDim { NONE, SRCIP, DESIP, SRCPORT, DESPORT, PROTOCOL };
////////////////////////////////////////////////////////////////////////////////////
struct ENTRY {
	unsigned int src_ip;
	unsigned char src_len;
	unsigned int des_ip;
	unsigned char des_len;
	unsigned int src_port_start;
	unsigned int src_port_end;
	unsigned int des_port_start;
	unsigned int des_port_end;
	unsigned int protocol;
};
////////////////////////////////////////////////////////////////////////////////////
struct list {
	unsigned int port;
	struct list *left, *right;
};
typedef struct list node;
typedef node *btrie;
////////////////////////////////////////////////////////////////////////////////////
struct bucket {
	enum fiveDim cut_dim;
	unsigned char bit_length;
	unsigned int *index_array;
	unsigned int arraySize;
	struct bucket *child;
	//record how many bit had check
	unsigned char src_addr_had_check;
	unsigned char des_addr_had_check;
	unsigned char src_port_had_check;
	unsigned char des_port_had_check;
	unsigned char ptc_had_check;
};
typedef struct bucket bnode;
typedef bnode *ctrie;

#endif
