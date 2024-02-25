import argparse
import sys
import logging
from src.fcgi_client import PHPFPMClient

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='A simple PHP-FPM client for Python3')
    parser.add_argument('-t', '--target', help='Target to call, host:port or unix://path', required=True)
    parser.add_argument('-f', '--file', help='PHP-FPM Filepath to call with query string, example: /usr/app/index.php?name=value&name2=value2', required=True)
    parser.add_argument('-x', '--method', help='Method to call, example: GET, POST, PUT, DELETE', default='GET')
    parser.add_argument('-p', '--param', help='Parameters in the format KEY=VALUE, multiple allowed', default=[], action='append')
    parser.add_argument('-s', '--post', help='POST body content')
    parser.add_argument('-m', '--timeout', help='Socket timeout in ms', default=3000, type=int)
    parser.add_argument('-v', '--verbose', help='Verbose output', action="store_true", default=False)

    args, unknow = parser.parse_known_args()

    post = '' if args.post == None else args.post.encode('utf-8')

    if args.verbose:
        logging.basicConfig(format=f"%(levelname)s - %(message)s", level=logging.DEBUG)
    else:
        logging.basicConfig(format=f"%(levelname)s - %(message)s", level=logging.INFO)

    parameters = {}
    for param in args.param:
        if '=' not in param:
            logging.error("The following parameter is not in the format key=value: {param}")
            sys.exit(1)
        key = param.split('=')[0]
        value = param.split('=')[1]
        parameters[key] = value

    if '?' in args.file:
        file = args.file.split('?')[0]
        querystring = args.file.split('?')[1]
    else:
        file = args.file
        querystring = ''

    client = PHPFPMClient(args.target, args.timeout)

    logging.info(f"Sending {args.method} request to {args.target} @ {args.file}")
    response = client.request(file, args.method, querystring, post, parameters)
    if not response:
        logging.error("Request error!")
        sys.exit(1)

    logging.info(f"Received response:")
    print(response)

    sys.exit(0)