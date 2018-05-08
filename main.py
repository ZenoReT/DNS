import sys
import socket
import argparse
from resolver import Resolver


def create_parser():
    parser = argparse.ArgumentParser(
        description='A caching DNS server.\n\
        \rThe list of keys:\n\
        \r-ss')
    parser.add_argument('-ss', '--start_server', type=str,
                    help='Will start search from this server',
                    default='212.193.163.6')
    return parser


def main():
    parser = create_parser()
    parsed_args = parser.parse_args(sys.argv[1:])
    dns_addr = parsed_args.start_server
    resolver = Resolver(dns_addr)
    try:
        resolver.start_listening()
    except socket.error:
        sys.exit()



if __name__ == '__main__':
    main()
