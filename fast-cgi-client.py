import argparse
import logging
import sys
from src.fcgi_client import FastCGIClient


if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description='A simple FastCGI client for Python3')
    parser.add_argument('-t', '--target', help='Target to call, host:port or unix://path', required=True)
    parser.add_argument('-p', '--param', help='Parameters in the format KEY=VALUE, multiple allowed', default=[], action='append')
    parser.add_argument('-s', '--stdin', help='STDIN content')
    parser.add_argument('-m', '--timeout', help='Socket timeout in ms', default=3000, type=int)
    parser.add_argument('-k', '--keepalive', help='Keepalive', action="store_true", default=False)
    parser.add_argument('-v', '--verbose', help='Verbose output', action="store_true", default=False)

    args, unknow = parser.parse_known_args()

    post = '' if args.stdin == None else args.stdin.encode('utf-8')

    if args.verbose:
        logging.basicConfig(format=f"%(levelname)s - %(message)s", level=logging.DEBUG)
    else:
        logging.basicConfig(format=f"%(levelname)s - %(message)s", level=logging.INFO)

    parameters = {}
    for param in args.param:
        if '=' not in param:
            logging.error(f"The following parameter is not in the format key=value: {param}")
            sys.exit(1)
        key = param.split('=')[0]
        value = param.split('=')[1]
        parameters[key] = value
    
    logging.info(f"Loaded {len(parameters)} parameters")

    client = FastCGIClient(args.target, args.timeout, args.keepalive)

    logging.info(f"Sending request to {args.target}")
    response = client.request(parameters, post)
    if not response:
        logging.error(f"Request error!")
        sys.exit(1)

    logging.info(f"Received response:")
    print(response)

    sys.exit(0)
    

    
