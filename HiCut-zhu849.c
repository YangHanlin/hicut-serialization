#define _CRT_SECURE_NO_WARNINGS

#include "HiCut-zhu849.h"

#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include<math.h>
#include<limits.h>

#include "data_ops.h"

#define SPFAC 64
#define BINTH 16
////////////////////////////////////////////////////////////////////////////////////

static __inline__ unsigned long long rdtsc(void)
{
	unsigned hi, lo;
	__asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
	return ((unsigned long long)lo) | (((unsigned long long)hi) << 32);
}

/*global variables*/
ctrie root;
struct ENTRY *table;
struct ENTRY *query;
int num_entry = 0;
int num_query = 0;
unsigned long long int begin, end, total = 0;
unsigned long long int *clock;
int counter;
int dim_count[5] = {0,0,0,0,0};
int num_bnode = 0;
////////////////////////////////////////////////////////////////////////////////////
btrie create_node(){
	btrie temp;
	temp=(btrie)malloc(sizeof(node));
	temp->right=NULL;
	temp->left=NULL;
	temp->port=65536;
	return temp;
}
////////////////////////////////////////////////////////////////////////////////////
ctrie create_bnode() {
	ctrie temp;
	temp = (ctrie)malloc(sizeof(bnode));
	temp->cut_dim = NONE;
	temp->bit_length = 0;
	temp->index_array = NULL;
	temp->arraySize = 0;
	temp->child = NULL;
	temp->src_addr_had_check = 0;
	temp->des_addr_had_check = 0;
	temp->src_port_had_check = 0;
	temp->des_port_had_check = 0;
	temp->ptc_had_check = 0;
	return temp;
}
////////////////////////////////////////////////////////////////////////////////////
void read_table(char *str, unsigned int *src_ip, unsigned char *src_len, unsigned int *des_ip, unsigned char *des_len, unsigned int *src_port_start, unsigned int *src_port_end, unsigned int *des_port_start, unsigned int *des_port_end, unsigned int *protocol){
	char tok_space[]="\t";
	char tok_ip[] = "@./ ";
	char tok_port[] = ":\t ";
	char tok_protocol[] = "\tx/ ";
	char buf[200];
	char *sa, *da, *sp, *dp, *pt;

	//source address
	sa = strtok(str, tok_space);
	//destination address
	da = strtok(NULL, tok_space);
	//source port
	sp = strtok(NULL, tok_space);
	//destination address
	dp = strtok(NULL, tok_space);
	//protocol
	pt = strtok(NULL, tok_space);
	//final field
	sprintf(buf, "%s\0", strtok(NULL, tok_space));
	
	//deal with source ip
	*src_ip = 0;
	sprintf(buf, "%s\0", strtok(sa, tok_ip));
	*src_ip += atoi(buf);
	*src_ip <<= 8;
	sprintf(buf, "%s\0", strtok(NULL, tok_ip));
	*src_ip += atoi(buf);
	*src_ip <<= 8;
	sprintf(buf, "%s\0", strtok(NULL, tok_ip));
	*src_ip += atoi(buf);
	*src_ip <<= 8;
	sprintf(buf, "%s\0", strtok(NULL, tok_ip));
	*src_ip += atoi(buf);
	sprintf(buf, "%s\0", strtok(NULL, tok_ip));
	*src_len = atoi(buf);
	//deal with destination ip
	*des_ip = 0;
	sprintf(buf, "%s\0", strtok(da, tok_ip));
	*des_ip += atoi(buf);
	*des_ip <<= 8;
	sprintf(buf, "%s\0", strtok(NULL, tok_ip));
	*des_ip += atoi(buf);
	*des_ip <<= 8;
	sprintf(buf, "%s\0", strtok(NULL, tok_ip));
	*des_ip += atoi(buf);
	*des_ip <<= 8;
	sprintf(buf, "%s\0", strtok(NULL, tok_ip));
	*des_ip += atoi(buf);
	sprintf(buf, "%s\0", strtok(NULL, tok_ip));
	*des_len = atoi(buf);
	//deal with source port
	sprintf(buf, "%s\0", strtok(sp, tok_port));
	*src_port_start = atoi(buf);
	sprintf(buf, "%s\0", strtok(NULL, tok_port));
	*src_port_end = atoi(buf);
	//deal with destination port
	sprintf(buf, "%s\0", strtok(dp, tok_port));
	*des_port_start = atoi(buf);
	sprintf(buf, "%s\0", strtok(NULL, tok_port));
	*des_port_end = atoi(buf);
	//deal with protocol
	sprintf(buf, "%s\0", strtok(pt, tok_protocol));
	sprintf(buf, "%s\0", strtok(NULL, tok_protocol));
	*protocol = buf[0] >= 'a' ? (buf[0] - 'a' + 10) * 16 : (buf[0] - '0') * 16;
	*protocol += buf[1] >= 'a' ? (buf[1] - 'a' + 10) : (buf[1] - '0');
}
////////////////////////////////////////////////////////////////////////////////////
void set_table(char *file_name){
	FILE *fp;
	char string[200];
	unsigned int src_ip;
	unsigned char src_len;
	unsigned int des_ip;
	unsigned char des_len;
	unsigned int src_port_start;
	unsigned int src_port_end;
	unsigned int des_port_start;
	unsigned int des_port_end;
	unsigned int protocol;

	fp=fopen(file_name,"r");
	while(fgets(string,200,fp)!=NULL){
		read_table(string, &src_ip, &src_len, &des_ip, &des_len, &src_port_start, &src_port_end, &des_port_start, &des_port_end, &protocol);
		num_entry++;
	}
	rewind(fp);
	table = (struct ENTRY *)malloc(num_entry * sizeof(struct ENTRY));
	num_entry = 0;
	while(fgets(string,200,fp)!=NULL){
		read_table(string, &src_ip, &src_len, &des_ip, &des_len, &src_port_start, &src_port_end, &des_port_start, &des_port_end, &protocol);
		table[num_entry].src_ip = src_ip;
		table[num_entry].src_len = src_len;
		table[num_entry].des_ip = des_ip;
		table[num_entry].des_len = des_len;
		table[num_entry].src_port_start = src_port_start;
		table[num_entry].src_port_end = src_port_end;
		table[num_entry].des_port_start = des_port_start;
		table[num_entry].des_port_end = des_port_end;
		table[num_entry++].protocol = protocol;
	}
}
////////////////////////////////////////////////////////////////////////////////////
void set_query(char *file_name) {
	FILE *fp;
	char string[200];
	unsigned int src_ip;
	unsigned char src_len;
	unsigned int des_ip;
	unsigned char des_len;
	unsigned int src_port_start;
	unsigned int src_port_end;
	unsigned int des_port_start;
	unsigned int des_port_end;
	unsigned int protocol;

	fp = fopen(file_name, "r");
	while (fgets(string, 200, fp) != NULL) {
		read_table(string, &src_ip, &src_len, &des_ip, &des_len, &src_port_start, &src_port_end, &des_port_start, &des_port_end, &protocol);
		num_query++;
	}
	rewind(fp);
	query = (struct ENTRY *)malloc(num_query * sizeof(struct ENTRY));
	clock = (unsigned long long int *)malloc(num_query * sizeof(unsigned long long int));
	num_query = 0;
	while (fgets(string, 200, fp) != NULL) {
		read_table(string, &src_ip, &src_len, &des_ip, &des_len, &src_port_start, &src_port_end, &des_port_start, &des_port_end, &protocol);
		query[num_query].src_ip = src_ip;
		query[num_query].src_len = src_len;
		query[num_query].des_ip = des_ip;
		query[num_query].des_len = des_len;
		query[num_query].src_port_start = src_port_start;
		query[num_query].src_port_end = src_port_end;
		query[num_query].des_port_start = des_port_start;
		query[num_query].des_port_end = des_port_end;
		query[num_query].protocol = protocol;
		clock[num_query++] = 10000000;
	}
}
////////////////////////////////////////////////////////////////////////////////////
int addr_tree_addnode(btrie r, unsigned int ip, unsigned char len, unsigned int hop) {
	btrie ptr = r;
	int i;
	for (i = 0; i < len; i++) {
		if (ip&(1 << (31 - i))) {
			if (ptr->right == NULL)
				ptr->right = create_node();
			ptr = ptr->right;
			if ((i == len - 1) && (ptr->port == 65536))
				ptr->port = hop;
		}
		else {
			if (ptr->left == NULL)
				ptr->left = create_node();
			ptr = ptr->left;
			if ((i == len - 1) && (ptr->port == 65536))
				ptr->port = hop;
		}
	}
}
////////////////////////////////////////////////////////////////////////////////////
void port_seg_addnode(btrie* port_seg, unsigned int port_start, unsigned int port_end) {
	btrie ptr = port_seg[port_start];
	int i;
	for (i = 0; i < 16; i++) {
		if (ptr->port == 65536) {
			ptr->port = port_end;
			return;
		}
		else if (port_end > ptr->port) {
			if (ptr->right == NULL)
				ptr->right = create_node();
			ptr = ptr->right;
		}
		else if (port_end < ptr->port) {
			if (ptr->left == NULL) 
				ptr->left = create_node();
			ptr = ptr->left;
		}
		else 
			return;
	}
	ptr->port = port_end;
}
////////////////////////////////////////////////////////////////////////////////////
void count_tree_distinct(btrie p) {
	if (p == NULL)return;
	count_tree_distinct(p->left);
	count_tree_distinct(p->right);
	if (p->port != 65536)counter++;
}
////////////////////////////////////////////////////////////////////////////////////
void free_tree(btrie p ) {
	if (p == NULL)return;
	free_tree(p->left);
	free_tree(p->right);
	free(p);
}
////////////////////////////////////////////////////////////////////////////////////
void create() {
	int i;
	//initialize root node
	num_bnode++;
	root = create_bnode();
	root->index_array = malloc(sizeof(unsigned int) * num_entry);
	root->arraySize = num_entry;
	for (i = 0; i < num_entry; i++)
		root->index_array[i] = i;
}
////////////////////////////////////////////////////////////////////////////////////
void find_cutOfDim(ctrie p) {
	int i;
	int index;
	int src_addr_DN, des_addr_DN, src_port_DN, des_port_DN, ptc_DN;
	btrie src_root, des_root, src_port_seg[65536], des_port_seg[65536];
	unsigned int ptc_seg[256];

	//initialize
	src_root = create_node();
	des_root = create_node();
	for (i = 0; i < 65536; i++) {
		src_port_seg[i] = create_node();
		des_port_seg[i] = create_node();
	}
	for (i = 0; i < 256; i++)
		ptc_seg[i] = 0;

	//add node with 5 dim
	for (i = 0; i < p->arraySize; i++) {
		index = p->index_array[i];
		addr_tree_addnode(src_root, table[index].src_ip, table[index].src_len, table[index].src_port_start);
		addr_tree_addnode(des_root, table[index].des_ip, table[index].des_len, table[index].des_port_start);
		port_seg_addnode(src_port_seg, table[index].src_port_start, table[index].src_port_end);
		port_seg_addnode(des_port_seg, table[index].des_port_start, table[index].des_port_end);
		ptc_seg[table[index].protocol]++;
	}

	//count src address distinct number
	counter = 0;
	count_tree_distinct(src_root);
	src_addr_DN = counter;
	//count des address distinct number
	counter = 0;
	count_tree_distinct(des_root);
	des_addr_DN = counter;
	//count src port distinct number
	counter = 0;
	for (i = 0; i < 65536; i++) {
		if (src_port_seg[i]->port != 65536)
			count_tree_distinct(src_port_seg[i]);
	}
	src_port_DN = counter;
	//count des port distinct number
	counter = 0;
	for (i = 0; i < 65536; i++) {
		if (des_port_seg[i]->port != 65536)
			count_tree_distinct(des_port_seg[i]);
	}
	des_port_DN = counter;
	//count ptc distinct number
	counter = 0;
	for (i = 0; i < 256; i++) {
		if (ptc_seg[i] != 0)
			counter++;
	}
	ptc_DN = counter;

	//select max distinct number dim
	enum fiveDim max_dim = NONE;
	int max_number = INT_MIN;
	if (src_addr_DN >= des_addr_DN) {
		max_dim = SRCIP;
		max_number = src_addr_DN;
		dim_count[0]++;
	}
	else {
		max_dim = DESIP;
		max_number = des_addr_DN;
		dim_count[1]++;
	}
	if (src_port_DN > max_number) {
		max_dim = SRCPORT;
		max_number = src_port_DN;
		dim_count[2]++;
	}
	if (des_port_DN > max_number) {
		max_dim = DESPORT;
		max_number = des_port_DN;
		dim_count[3]++;
	}
	if (ptc_DN > max_number) {
		max_dim = PROTOCOL;
		max_number = ptc_DN;
		dim_count[4]++;
	}
	//free memory space
	free_tree(src_root);
	free_tree(des_root);
	for (i = 0; i < 65536; i++){
		free_tree(src_port_seg[i]);
		free_tree(des_port_seg[i]);
	}
	p->cut_dim = max_dim;
}
////////////////////////////////////////////////////////////////////////////////////
void choose_numOfpart(ctrie ptr) {
	/********************************************************************************
	   We are doing a binary search on the number of cuts to be made at this node(v). 
	   When the number of cuts are such that the corresponding memory consumptionestimate becomes more than what is allowed by the space Measure function "spmf()", we end the search.
	   It is possible to do smarter variations of this search algorithm.
	 *******************************************************************************/
	int i, j;
	int cut_length;
	int done = 1;
	int nump;
	unsigned int s_index,e_index;
	int *count_array = NULL;
	int smC;
	int spmf = SPFAC * ptr->arraySize;
	
	for (cut_length = 2; cut_length < 32; cut_length++) {
		nump = pow(2, cut_length);
		if (nump >= sqrt(ptr->arraySize))
			break;
	}

	//brute force to find best cut of part
	while(done){
		smC = 0;
		count_array = malloc(sizeof(int)*nump);
		for (i = 0; i < nump; i++)
			count_array[i] = 0;
		//select cut dim
		if (ptr->cut_dim == SRCIP) {
			for (j = 0; j < ptr->arraySize; j++) {
				if (cut_length > table[ptr->index_array[j]].src_len + ptr->src_addr_had_check) {
					s_index = table[ptr->index_array[j]].src_ip << ptr->src_addr_had_check  >>  (32 - table[ptr->index_array[j]].src_len) << (cut_length - table[ptr->index_array[j]].src_len);
					e_index = ((table[ptr->index_array[j]].src_ip << ptr->src_addr_had_check) | (0xFFFFFFFF >> table[ptr->index_array[j]].src_len)) >> (32 - cut_length);
					for (i = s_index; i <= e_index; i++)
						count_array[i]++;
				}
				else {
					s_index = table[ptr->index_array[j]].src_ip << ptr->src_addr_had_check >> (32 - cut_length);
					count_array[s_index]++;
				}
			}
		}
		else if (ptr->cut_dim == DESIP) {
			for (j = 0; j < ptr->arraySize; j++) {
				if (cut_length > table[ptr->index_array[j]].des_len + ptr->des_addr_had_check) {
					s_index = table[ptr->index_array[j]].des_ip << ptr->des_addr_had_check >> (32 - table[ptr->index_array[j]].des_len) << (cut_length - table[ptr->index_array[j]].des_len);
					e_index = ((table[ptr->index_array[j]].des_ip << ptr->des_addr_had_check) | (0xFFFFFFFF >> table[ptr->index_array[j]].des_len)) >> (32 - cut_length);
					for (i = s_index; i <= e_index; i++)
						count_array[i]++;
				}
				else {
					s_index = table[ptr->index_array[j]].des_ip << ptr->des_addr_had_check >> (32 - cut_length);
					count_array[s_index]++;
				}
			}
		}
		else if (ptr->cut_dim == SRCPORT) {
			for (j = 0; j < ptr->arraySize; j++) {
				s_index = table[ptr->index_array[j]].src_port_start << ptr->src_port_had_check >> (32 - cut_length);
				e_index = table[ptr->index_array[j]].src_port_end << ptr->src_port_had_check >> (32 - cut_length);
				for (i = s_index; i <= e_index; i++)
					count_array[i]++;
			}
		}
		else if (ptr->cut_dim == DESPORT) {
			for (j = 0; j < ptr->arraySize; j++) {
				s_index = table[ptr->index_array[j]].des_port_start << ptr->des_port_had_check >> (32 - cut_length);
				e_index = table[ptr->index_array[j]].des_port_end << ptr->des_port_had_check >> (32 - cut_length);
				for (i = s_index; i <= e_index; i++)
					count_array[i]++;
			}
		}
		else if (ptr->cut_dim == PROTOCOL) {
			for (j = 0; j < ptr->arraySize; j++) {
				s_index = table[ptr->index_array[j]].protocol << ptr->ptc_had_check >> (32 - cut_length);
				count_array[s_index]++;
			}
		}
		else
			printf("******************ERROR*********************");

		//smC += number of partitions colliding with rule r;
		for (int i = 0; i < nump; i++)
			smC += count_array[i];
		smC += nump;
		//check if comply formula 
		if (smC < spmf) {
			nump *= 2;
			cut_length++;
			free(count_array);
		}
		// break
		else 
			done = 0;
	}

	//redo last time operation
	nump /= 2;
	cut_length--;
	free(count_array);
	count_array = malloc(sizeof(int)*nump);
	for (i = 0; i < nump; i++)
		count_array[i] = 0;
	//select cut dim
	if (ptr->cut_dim == SRCIP) {
		for (j = 0; j < ptr->arraySize; j++) {
			if (cut_length > table[ptr->index_array[j]].src_len + ptr->src_addr_had_check) {
				s_index = table[ptr->index_array[j]].src_ip << ptr->src_addr_had_check >> (32 - table[ptr->index_array[j]].src_len) << (cut_length - table[ptr->index_array[j]].src_len);
				e_index = ((table[ptr->index_array[j]].src_ip << ptr->src_addr_had_check) | (0xFFFFFFFF >> table[ptr->index_array[j]].src_len)) >> (32 - cut_length);
				for (i = s_index; i <= e_index; i++)
					count_array[i]++;
			}
			else {
				s_index = table[ptr->index_array[j]].src_ip << ptr->src_addr_had_check >> (32 - cut_length);
				count_array[s_index]++;
			}
		}
	}
	else if (ptr->cut_dim == DESIP) {
		for (j = 0; j < ptr->arraySize; j++) {
			if (cut_length > table[ptr->index_array[j]].des_len + ptr->des_addr_had_check) {
				s_index = table[ptr->index_array[j]].des_ip << ptr->des_addr_had_check >> (32 - table[ptr->index_array[j]].des_len) << (cut_length - table[ptr->index_array[j]].des_len);
				e_index = ((table[ptr->index_array[j]].des_ip << ptr->des_addr_had_check) | (0xFFFFFFFF >> table[ptr->index_array[j]].des_len)) >> (32 - cut_length);
				for (i = s_index; i <= e_index; i++)
					count_array[i]++;
			}
			else {
				s_index = table[ptr->index_array[j]].des_ip << ptr->des_addr_had_check >> (32 - cut_length);
				count_array[s_index]++;
			}
		}
	}
	else if (ptr->cut_dim == SRCPORT) {
		for (j = 0; j < ptr->arraySize; j++) {
			s_index = table[ptr->index_array[j]].src_port_start << ptr->src_port_had_check >> (32 - cut_length);
			e_index = table[ptr->index_array[j]].src_port_end << ptr->src_port_had_check >> (32 - cut_length);
			for (i = s_index; i <= e_index; i++)
				count_array[i]++;
		}
	}
	else if (ptr->cut_dim == DESPORT) {
		for (j = 0; j < ptr->arraySize; j++) {
			s_index = table[ptr->index_array[j]].des_port_start << ptr->des_port_had_check >> (32 - cut_length);
			e_index = table[ptr->index_array[j]].des_port_end << ptr->des_port_had_check >> (32 - cut_length);
			for (i = s_index; i <= e_index; i++)
				count_array[i]++;
		}
	}
	else if (ptr->cut_dim == PROTOCOL) {
		for (j = 0; j < ptr->arraySize; j++) {
			s_index = table[ptr->index_array[j]].protocol << ptr->ptc_had_check >> (32 - cut_length);
			count_array[s_index]++;
		}
	}
	else
		printf("******************ERROR*********************");

	//set this ctrie node info
	ptr->bit_length = cut_length;
	ptr->child = (ctrie)malloc(sizeof(bnode)*nump);
	for (i = 0; i < nump; i++) {
		num_bnode++;
		ptr->child[i].arraySize = 0;
		ptr->child[i].bit_length = 0;
		ptr->child[i].child = NULL;
		ptr->child[i].cut_dim = NONE;
		ptr->child[i].src_addr_had_check = ptr->src_addr_had_check;
		ptr->child[i].des_addr_had_check = ptr->des_addr_had_check;
		ptr->child[i].src_port_had_check = ptr->src_port_had_check;
		ptr->child[i].des_port_had_check = ptr->des_port_had_check;
		ptr->child[i].ptc_had_check = ptr->ptc_had_check;
		if (count_array[i] != 0)
			ptr->child[i].index_array = malloc(sizeof(unsigned int) * count_array[i]);
		else
			ptr->child[i].index_array = NULL;
	}
	free(count_array);

	//distribution to child's bucket
	if (ptr->cut_dim == SRCIP) {
		for (j = 0; j < ptr->arraySize; j++) {
			if (cut_length > table[ptr->index_array[j]].src_len + ptr->src_addr_had_check) {
				s_index = table[ptr->index_array[j]].src_ip << ptr->src_addr_had_check >> (32 - table[ptr->index_array[j]].src_len) << (cut_length - table[ptr->index_array[j]].src_len);
				e_index = ((table[ptr->index_array[j]].src_ip << ptr->src_addr_had_check) | (0xFFFFFFFF >> table[ptr->index_array[j]].src_len)) >> (32 - cut_length);
				for (i = s_index; i <= e_index; i++) {
					ptr->child[i].index_array[ptr->child[i].arraySize++] = ptr->index_array[j];
					ptr->child[i].src_addr_had_check = ptr->src_addr_had_check + ptr->bit_length;
				}
			}
			else {
				s_index = table[ptr->index_array[j]].src_ip << ptr->src_addr_had_check >> (32 - cut_length);
				ptr->child[s_index].index_array[ptr->child[s_index].arraySize++] = ptr->index_array[j];
				ptr->child[s_index].src_addr_had_check = ptr->src_addr_had_check + ptr->bit_length;
			}
		}
	}
	else if (ptr->cut_dim == DESIP) {
		for (j = 0; j < ptr->arraySize; j++) {
			if (cut_length > table[ptr->index_array[j]].des_len + ptr->des_addr_had_check) {
				s_index = table[ptr->index_array[j]].des_ip << ptr->des_addr_had_check >> (32 - table[ptr->index_array[j]].des_len) << (cut_length - table[ptr->index_array[j]].des_len);
				e_index = ((table[ptr->index_array[j]].des_ip << ptr->des_addr_had_check) | (0xFFFFFFFF >> table[ptr->index_array[j]].des_len)) >> (32 - cut_length);
				for (i = s_index; i <= e_index; i++) {
					ptr->child[i].index_array[ptr->child[i].arraySize++] = ptr->index_array[j];
					ptr->child[i].des_addr_had_check = ptr->des_addr_had_check + ptr->bit_length;
				}
			}
			else {
				s_index = table[ptr->index_array[j]].des_ip << ptr->des_addr_had_check >> (32 - cut_length);
				ptr->child[s_index].index_array[ptr->child[s_index].arraySize++] = ptr->index_array[j];
				ptr->child[s_index].des_addr_had_check = ptr->des_addr_had_check + ptr->bit_length;
			}
		}
	}
	else if (ptr->cut_dim == SRCPORT) {
		for (j = 0; j < ptr->arraySize; j++) {
			s_index = table[ptr->index_array[j]].src_port_start << ptr->src_port_had_check >> (32 - cut_length);
			e_index = table[ptr->index_array[j]].src_port_end << ptr->src_port_had_check >> (32 - cut_length);
			for (i = s_index; i <= e_index; i++) {
				ptr->child[i].index_array[ptr->child[i].arraySize++] = ptr->index_array[j];
				ptr->child[i].src_port_had_check = ptr->src_port_had_check + ptr->bit_length;
			}
		}
	}
	else if (ptr->cut_dim == DESPORT) {
		for (j = 0; j < ptr->arraySize; j++) {
			s_index = table[ptr->index_array[j]].des_port_start << ptr->des_port_had_check >> (32 - cut_length);
			e_index = table[ptr->index_array[j]].des_port_end << ptr->des_port_had_check >> (32 - cut_length);
			for (i = s_index; i <= e_index; i++) {
				ptr->child[i].index_array[ptr->child[i].arraySize++] = ptr->index_array[j];
				ptr->child[i].des_port_had_check = ptr->des_port_had_check + ptr->bit_length;
			}
		}
	}
	else if (ptr->cut_dim == PROTOCOL) {
		for (j = 0; j < ptr->arraySize; j++) {
			i = table[ptr->index_array[j]].protocol << ptr->ptc_had_check >> (32 - cut_length);
			ptr->child[i].index_array[ptr->child[i].arraySize++] = ptr->index_array[j];
			ptr->child[i].ptc_had_check = ptr->ptc_had_check + ptr->bit_length;
		}
	}
}
////////////////////////////////////////////////////////////////////////////////////
void cut(ctrie p) {
	if (p->arraySize <= BINTH)
		return;

	ctrie ptr = p;
	find_cutOfDim(ptr);
	if (ptr->cut_dim == SRCIP && ptr->src_addr_had_check >= 32)
		return;
	else if (ptr->cut_dim == DESIP && ptr->des_addr_had_check >= 32)
		return;
	else if (ptr->cut_dim == SRCPORT && ptr->src_port_had_check >= 16)
		return;
	else if (ptr->cut_dim == DESPORT && ptr->des_port_had_check >= 16)
		return;
	else if (ptr->cut_dim == PROTOCOL && ptr->ptc_had_check >= 8)
		return;
	choose_numOfpart(ptr);

	for (int i = 0; i < pow(2,ptr->bit_length); i++) {
		if (ptr->child[i].arraySize > 0)
			cut(&ptr->child[i]);
	}
}
////////////////////////////////////////////////////////////////////////////////////
void search(unsigned int src_ip, unsigned int des_ip, unsigned int src_port, unsigned int des_port, unsigned int protocol) {
	ctrie ptr = root;
	int find = 0;
	int target = -1;
	unsigned int index;
	
	while (find != 1) {
		if (ptr->cut_dim == SRCIP) {
			index = src_ip << ptr->src_addr_had_check >> (32 - ptr->bit_length);
			ptr = &(ptr->child[index]);
		}
		else if (ptr->cut_dim == DESIP) {
			index = des_ip << ptr->des_addr_had_check >> (32 - ptr->bit_length);
			ptr = &(ptr->child[index]);
		}
		else if (ptr->cut_dim == SRCPORT) {
			index = src_port << ptr->src_port_had_check >> (32 - ptr->bit_length);
			ptr = &(ptr->child[index]);
		}
		else if (ptr->cut_dim == DESPORT) {
			index = des_port << ptr->des_port_had_check >> (32 - ptr->bit_length);
			ptr = &(ptr->child[index]);
		}
		else if (ptr->cut_dim == PROTOCOL) {
			index = protocol << ptr->ptc_had_check >> (32 - ptr->bit_length);
			ptr = &(ptr->child[index]);
		}
		else if (ptr->cut_dim == NONE) {
			for (int i = 0; i < ptr->arraySize; i++) {
				if (table[ptr->index_array[i]].src_ip == src_ip && table[ptr->index_array[i]].des_ip == des_ip)
					if (table[ptr->index_array[i]].src_port_start <= src_port && table[ptr->index_array[i]].src_port_end >= src_port && table[ptr->index_array[i]].des_port_start <= des_port && table[ptr->index_array[i]].des_port_end >= des_port && table[ptr->index_array[i]].protocol == protocol) {
						target = table[ptr->index_array[i]].des_ip;
						break;
					}
			}
			find = 1;
			//break;
		}
		else
			break;
	}
	/*
	if (target == -1)
		printf("not find\n");
	else
		printf("%x\n", target);
	*/
}
////////////////////////////////////////////////////////////////////////////////////
void CountClock()
{
	unsigned int i;
	unsigned int* NumCntClock = (unsigned int*)malloc(50 * sizeof(unsigned int));
	for (i = 0; i < 50; i++) NumCntClock[i] = 0;
	unsigned long long MinClock = 10000000, MaxClock = 0;
	for (i = 0; i < num_query; i++)
	{
		if (clock[i] > MaxClock) MaxClock = clock[i];
		if (clock[i] < MinClock) MinClock = clock[i];
		if (clock[i] / 100 < 50) NumCntClock[clock[i] / 100]++;
		else NumCntClock[49]++;
	}
	printf("(MaxClock, MinClock) = (%5llu, %5llu)\n", MaxClock, MinClock);

	for (i = 0; i < 50; i++)
	{
		printf("%d\n", NumCntClock[i]);
	}
	return;
}
////////////////////////////////////////////////////////////////////////////////////
void shuffle(struct ENTRY *array, int n) {
	srand((unsigned)time(NULL));
	struct ENTRY *temp = (struct ENTRY *)malloc(sizeof(struct ENTRY));

	for (int i = 0; i < n - 1; i++) {
		size_t j = i + rand() / (RAND_MAX / (n - i) + 1);
		temp->src_ip = array[j].src_ip;
		temp->des_ip = array[j].des_ip;
		temp->src_port_start = array[j].src_port_start;
		temp->src_port_end = array[j].src_port_end;
		temp->des_port_start = array[j].des_port_start;
		temp->des_port_end = array[j].des_port_end;
		temp->src_len = array[j].src_len;
		temp->des_len = array[j].des_len;
		temp->protocol = array[j].protocol;
	}
}
////////////////////////////////////////////////////////////////////////////////////
int main(int argc,char *argv[]){
	int i,j;
	int cut_dim;
	char filename[50] = "8k.txt";
	set_table(argv[1]);
	set_query(argv[2]);
	printf("Building tree\n");
	begin = rdtsc();
	create();
	cut(root);
	end = rdtsc();
	printf("Avg. Build Time: %llu\n", (end - begin) / num_entry);
	printf("SPFAC:%d\n", SPFAC);
	printf("BINTH:%d\n", BINTH);
	printf("num of entry:%d\n", num_entry);
	printf("num of bnode : %d\n", num_bnode);
	printf("dim count:\n");
	for (i = 0; i < 5; i++)
		printf("	%d\n", dim_count[i]);

	printf("Serializing tree\n");
	FILE *fp = fopen("hicut-tree.tmp", "wb");
	if (fp == NULL) {
		printf("Error: cannot open serialization file\n");
	} else {
		hicut_serialize(fp, root, table);
		fclose(fp);
	}

	shuffle(query, num_query);
	
	for (j = 0; j < 100; j++) {
		//printf("loop: %d\n",j);
		for (i = 0; i < num_query; i++) {
			begin = rdtsc();
			search(query[i].src_ip, query[i].des_ip, query[i].src_port_start, query[i].des_port_start, query[i].protocol); //bug edited
			end = rdtsc();
			//printf("id: %d\n",i);
			//printf("%d\n",(end - begin));
			if (clock[i] > (end - begin))
				clock[i] = (end - begin);
		}
	}
	total = 0;
	for (j = 0; j < num_query; j++)
		total += clock[j];
	printf("Avg. Search: %lld\n", total / num_query);
	CountClock();
	
	return 0;
}
