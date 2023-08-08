CC_OPTS = -std=gnu11 -Wall -g

.PHONY: all test clean compile_commands.json

all: hicut test_rules

test: all
	./hicut test_rules trace

clean:
	rm -f *.o *.tmp hicut compile_commands.json test_rules

compile_commands.json:
	bear --output compile_commands.json.tmp -- make -B all
	mv -f compile_commands.json.tmp compile_commands.json
	compdb -p . list > compile_commands.json.tmp
	mv -f compile_commands.json.tmp compile_commands.json

hicut: HiCut-zhu849.o data_ops.o
	gcc $(CC_OPTS) -o hicut HiCut-zhu849.o data_ops.o -lm

HiCut-zhu849.o: HiCut-zhu849.c HiCut-zhu849.h data_ops.h
	gcc $(CC_OPTS) -c -o HiCut-zhu849.o HiCut-zhu849.c

data_ops.o: data_ops.c data_ops.h
	gcc $(CC_OPTS) -c -o data_ops.o data_ops.c

test_rules: ruleset/acl1_100k Makefile
	cat /dev/null > test_rules
	tail -n 1000 ruleset/acl1_100k >> test_rules
