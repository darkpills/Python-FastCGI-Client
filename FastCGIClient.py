import random
import socket

class FastCGIClient:
    """A Fast-CGI Client for Python"""

    # private
    __FCGI_VERSION = 1

    __FCGI_ROLE_RESPONDER = 1
    __FCGI_ROLE_AUTHORIZER = 2
    __FCGI_ROLE_FILTER = 3

    __FCGI_TYPE_BEGIN = 1
    __FCGI_TYPE_ABORT = 2
    __FCGI_TYPE_END = 3
    __FCGI_TYPE_PARAMS = 4
    __FCGI_TYPE_STDIN = 5
    __FCGI_TYPE_STDOUT = 6
    __FCGI_TYPE_STDERR = 7
    __FCGI_TYPE_DATA = 8
    __FCGI_TYPE_GETVALUES = 9
    __FCGI_TYPE_GETVALUES_RESULT = 10
    __FCGI_TYPE_UNKOWNTYPE = 11

    __FCGI_HEADER_SIZE = 8

    # request state
    FCGI_STATE_SEND = 1
    FCGI_STATE_ERROR = 2
    FCGI_STATE_SUCCESS = 3

    # colors
    grey = "\x1b[90m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    reset = "\x1b[0m"
    green = "\x1b[1;32m"

    def __init__(self, host, port, timeout, keepalive, verbose=False):
        self.host = host
        self.port = port
        self.timeout = timeout
        if keepalive:
            self.keepalive = 1
        else:
            self.keepalive = 0
        self.verbose = verbose
        self.sock = None
        self.requests = dict()

    def info(self, message):
        print(self.green + "[+] " + self.reset + message)

    def error(self, message):
        print(self.red + message + self.reset)

    def debug(self, message):
        if self.verbose:
            print(self.grey + "[*] " + message + self.reset)

    def typeToString(self, type):
        if type == self.__FCGI_TYPE_BEGIN:
            return "BEGIN"
        elif type == self.__FCGI_TYPE_ABORT:
            return "ABORT"
        elif type == self.__FCGI_TYPE_END:
            return "END"
        elif type == self.__FCGI_TYPE_PARAMS:
            return "PARAMS"
        elif type == self.__FCGI_TYPE_STDIN:
            return "STDIN"
        elif type == self.__FCGI_TYPE_STDOUT:
            return "STDOUT"
        elif type == self.__FCGI_TYPE_STDERR:
            return "STDERR"
        elif type == self.__FCGI_TYPE_DATA:
            return "DATA"
        elif type == self.__FCGI_TYPE_GETVALUES:
            return "GETVALUES"
        elif type == self.__FCGI_TYPE_GETVALUES_RESULT:
            return "GETVALUES_RESULT"
        elif type == self.__FCGI_TYPE_UNKOWNTYPE:
            return "UNKNOWNTYPE"
        else:
            raise Exception(f"Unknown message type: {type}")

    def __connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # if self.keepalive:
        #     self.sock.setsockopt(socket.SOL_SOCKET, socket.SOL_KEEPALIVE, 1)
        # else:
        #     self.sock.setsockopt(socket.SOL_SOCKET, socket.SOL_KEEPALIVE, 0)
        try:
            self.sock.connect((self.host, int(self.port)))
        except socket.error as msg:
            self.sock.close()
            self.sock = None
            self.error(repr(msg))
            return False
        return True

    def __encodeFastCGIRecord(self, fcgi_type, content, requestid):
        length = len(content)
        response = bytearray()
        response.append(FastCGIClient.__FCGI_VERSION)
        response.append(fcgi_type)
        response.append((requestid >> 8) & 0xFF)
        response.append(requestid & 0xFF)
        response.append((length >> 8) & 0xFF)
        response.append(length & 0xFF)
        response.append(0)
        response.append(0)
        response = response + content

        return response 

    def __encodeNameValueParams(self, name, value):
        nLen = len(str(name))
        vLen = len(str(value))
        record = bytearray()
        if nLen < 128:
            record.append(nLen)
        else:
            record.append((nLen >> 24) | 0x80)
            record.append((nLen >> 16) & 0xFF)
            record.append((nLen >> 8) & 0xFF)
            record.append(nLen & 0xFF)
        if vLen < 128:
            record.append(vLen)
        else:
            record.append((vLen >> 24) | 0x80)
            record.append((vLen >> 16) & 0xFF)
            record.append((vLen >> 8) & 0xFF)
            record.append(vLen & 0xFF)
        return record + bytearray(str(name).encode('utf-8')) + bytearray(str(value).encode('utf-8'))

    def __decodeFastCGIHeader(self, stream):
        header = dict()
        header['version'] = stream[0]
        header['type'] = stream[1]
        header['requestId'] = int.from_bytes(stream[2:4], "big")
        header['contentLength'] = int.from_bytes(stream[4:6], "big")
        header['paddingLength'] = stream[6]
        header['reserved'] = stream[7]
        return header

    def __decodeFastCGIRecord(self):
        header = self.sock.recv(int(self.__FCGI_HEADER_SIZE))
        if not header:
            self.debug(f"Received empty response")
            return False
        
        record = self.__decodeFastCGIHeader(header)
        requestId = record['requestId'] 
        self.debug(f"[{requestId}] Received header message type {self.typeToString(record['type'])}")
        record['content'] = bytes()
        if 'contentLength' in record.keys():
            totalContentLength = int(record['contentLength'])
            contentLength = 0
            while contentLength < totalContentLength:
                buffer = self.sock.recv(totalContentLength - contentLength)
                contentLength += len(buffer)
                self.debug(f"[{requestId}] Received content {contentLength} / {totalContentLength} bytes")
                if buffer:
                    record['content'] += buffer
        if 'paddingLength' in record.keys():
            self.debug(f"[{requestId}] Skipping padding content {record['paddingLength']} bytes")
            skiped = self.sock.recv(int(record['paddingLength']))
        return record

    def request(self, nameValuePairs={}, post=''):
        if not self.__connect():
            self.error('Connect failure: please check fast cgi host and port')
            return

        requestId = random.randint(1, (1 << 16) - 1)
        while requestId in self.requests:
            requestId = random.randint(1, (1 << 16) - 1)
        self.requests[requestId] = dict()
        request = bytearray()
        beginFCGIRecordContent = bytearray()
        beginFCGIRecordContent.append(0)
        beginFCGIRecordContent.append(FastCGIClient.__FCGI_ROLE_RESPONDER)
        beginFCGIRecordContent.append(self.keepalive)
        beginFCGIRecordContent = beginFCGIRecordContent + bytes(5)
        request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_BEGIN,
                                              beginFCGIRecordContent, requestId)
        filename = ''
        paramsRecord = bytearray()
        if nameValuePairs:
            for (name, value) in nameValuePairs.items():
                # paramsRecord = self.__encodeNameValueParams(name, value)
                # request += self.__encodeFastCGIRecord(self.__FCGI_TYPE_PARAMS, paramsRecord, requestId)
                paramsRecord += self.__encodeNameValueParams(name, value)
                if name == 'SCRIPT_FILENAME':
                    filename = value

        if len(paramsRecord) > 0:
            request += self.__encodeFastCGIRecord(self.__FCGI_TYPE_PARAMS, paramsRecord, requestId)
        request += self.__encodeFastCGIRecord(self.__FCGI_TYPE_PARAMS, bytearray(), requestId)

        if post:
            request += self.__encodeFastCGIRecord(self.__FCGI_TYPE_STDIN, post, requestId)
        request += self.__encodeFastCGIRecord(self.__FCGI_TYPE_STDIN, bytearray(), requestId)
        self.debug(f"[{requestId}] {self.host}:{self.port}{filename}")
        self.sock.send(request)
        self.requests[requestId]['state'] = self.FCGI_STATE_SEND
        self.requests[requestId]['response'] = bytearray()
        return self.__waitForResponse(requestId)

    def __waitForResponse(self, requestId):
        waitRequestIds = ','.join([str(x) for x in self.requests.keys()])
        self.debug(f"[{waitRequestIds}] Waiting for response")
        while True:
            response = self.__decodeFastCGIRecord()
            if not response:
                break

            if requestId != int(response['requestId']):
                self.debug(f"[{response['requestId']}] Skipping content for this request id...")
                continue
            if response['type'] == self.__FCGI_TYPE_STDOUT:
                self.requests[requestId]['response'] += response['content']
            if response['type'] == self.__FCGI_TYPE_STDERR:
                self.requests[requestId]['state'] = self.FCGI_STATE_ERROR
                if requestId == int(response['requestId']):
                    self.requests[requestId]['response'] += response['content']
            if response['type'] == self.__FCGI_TYPE_END:
                if self.requests[requestId]['state'] != self.FCGI_STATE_ERROR:
                    self.requests[requestId]['state'] = self.FCGI_STATE_SUCCESS
        
        self.sock.close()
        reponse = self.requests[requestId]['response']
        del self.requests[requestId]
        return reponse

    def __repr__(self):
        return "fastcgi connect host:{} port:{}".format(self.host, self.port)
