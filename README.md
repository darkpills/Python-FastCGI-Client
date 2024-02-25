# FastCGI and PHP-FPM Python3 Client

A simple FastCGI Python3 Client

* Compatible with IP:port and unix:// sockets
* Standalone script and Python library
* Python logging integration with debug level
* Response encoding guessing from HTTP headers

Original python2 core code from https://github.com/wuyunfeng/Python-FastCGI-Client/, ported to Python3, bug fixed and improved

## Installation

With pip:
```
pip3 install fcgi-client
```

Or from source code:
```
git clone https://github.com/darkpills/fcgi-client
```

## Quickstart: PHP-FPM Client

GET request:
```
# python3 php-fpm-client.py -t 127.0.0.1:9000 -f /var/www/html/index.php\?toto=1

INFO - Sending GET request to 127.0.0.1:9000 @ /var/www/html/index.php?toto=1
INFO - Received response:
X-Powered-By: PHP/8.3.2
Content-type: text/html; charset=UTF-8

Hello World
```

POST request with post content in post.txt
```
#  python3 php-fpm-client.py -t 127.0.0.1:9000 -f /var/www/html/index.php\?toto=1 -x POST -s "username=admin&password=admin" 

INFO - Sending POST request to 127.0.0.1:9000 @ /var/www/html/index.php?toto=1
INFO - Received response:
X-Powered-By: PHP/8.3.2
Content-type: text/html; charset=UTF-8
```

Usage:
```
#  python3 php-fpm-client.py -h
usage: php-fpm-client.py [-h] -t TARGET -f FILE [-x METHOD] [-p PARAM] [-s POST] [-m TIMEOUT] [-v]

A simple FastCGI client for Python3

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target to call, host:port or unix://path
  -f FILE, --file FILE  PHP-FPM Filepath to call with query string, example: /usr/app/index.php?name=value&name2=value2
  -x METHOD, --method METHOD
                        Method to call, example: GET, POST, PUT, DELETE
  -p PARAM, --param PARAM
                        Parameters in the format KEY=VALUE, multiple allowed
  -s POST, --post POST  POST body content
  -m TIMEOUT, --timeout TIMEOUT
                        Socket timeout in ms
  -v, --verbose         Verbose output

```

## Quickstart: FastCGI Client

A raw FastCGI request with 2 parameters:
```
# python3 fast-cgi-client.py -p SCRIPT_FILENAME=/var/www/html/index.php -p REQUEST_METHOD=GET -t 127.0.0.1:9000   

INFO - Loaded 2 parameters
INFO - Sending request to 127.0.0.1:9000
INFO - Received response:
bytearray(b'X-Powered-By: PHP/8.3.2\r\nContent-type: text/html; charset=UTF-8\r\n\r\nHello World')
```

Usage:
```
# python3 fast-cgi-client.py -h
usage: fast-cgi-client.py [-h] -t TARGET [-p PARAM] [-s STDIN] [-m TIMEOUT] [-k] [-v]

A simple FastCGI client for Python3

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target to call, host:port or unix://path
  -p PARAM, --param PARAM
                        Parameters in the format KEY=VALUE, multiple allowed
  -s STDIN, --stdin STDIN
                        STDIN content
  -m TIMEOUT, --timeout TIMEOUT
                        Socket timeout in ms
  -k, --keepalive       Keepalive
  -v, --verbose         Verbose output

```

## Use it as a library

PHP-FPM client:
```
from fcgi_client import PHPFPMClient

client = PHPFPMClient("unix:///my/socket")

# a get request
response = client.get('/var/www/html/index.php', 'test=1&toto=2')

# a post request
response = client.post('/var/www/html/index.php', 'test=1&toto=2')
```

FastCGI client:
```
from fcgiclient import FastCGIClient

client = FastCGIClient("unix:///my/socket")
response = client.request({'SCRIPT_FILENAME':'/var/www/html/index.php', 'REQUEST_METHOD': 'GET'}, 'postcontenthere')
```
