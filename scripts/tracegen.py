#!/usr/bin/env python3

import random
import sys
import socket
from typing import Iterable

def generate(query_count: int, random_seed: int) -> Iterable[str]:
    r = random.Random(random_seed)
    for _ in range(query_count):
        src_ip, dest_ip = map(lambda b: socket.inet_ntop(socket.AF_INET, b), map(lambda _: r.randbytes(4), range(2)))
        src_port, dest_port = map(lambda _: r.randint(1, 65535), range(2))
        proto = r.randint(1, 255)
        yield f'@{src_ip}/32\t@{dest_ip}/32\t{src_port} : {src_port}\t{dest_port} : {dest_port}\t0x{proto:02x}/0x{proto:02x}\t0x0000/0x0000\t'

def main():
    if len(sys.argv) < 2:
        print(f'usage: {sys.argv[0]} QUERY_COUNT [RANDOM_SEED]', file=sys.stderr)
        exit(1)
    query_count = int(sys.argv[1])
    random_seed = int(sys.argv[2]) if len(sys.argv) >= 3 else 0
    for line in generate(query_count=query_count, random_seed=random_seed):
        print(line)

if __name__ == '__main__':
    main()
