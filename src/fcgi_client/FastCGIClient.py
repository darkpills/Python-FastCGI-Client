import random
import socket
import logging
import argparse
import sys
import os

# from https://raw.githubusercontent.com/wuyunfeng/Python-FastCGI-Client/master/FastCGIClient.py
# with code ported to Python3
class FastCGIClient:
    """A Fast-CGI Client for Python3"""

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

    def __init__(self, target='127.0.0.1:9000', timeout=3000, keepalive=False):

        if target.lower().startswith('unix://'):
            self.host = None
            self.port = None
            self.path = target[7:]
        elif ':' in target:
            hostSplit = target.split(':')
            self.host = hostSplit[0]
            self.port = hostSplit[1]
            self.path = None
        else:
            self.host = target
            self.port = '9000'
            self.path = None
        
        self.timeout = timeout
        if keepalive:
            self.keepalive = 1
        else:
            self.keepalive = 0
        self.sock = None
        self.requests = dict()


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

    def connect(self):
        if self.path != None:
            logging.debug(f"Creating socket to {self.path}")
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        else:
            logging.debug(f"Creating socket to {self.host}:{self.port}")
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            if self.path != None:
                self.sock.connect(self.path)
            else:
                self.sock.connect((self.host, int(self.port)))
        except socket.error as msg:
            self.close()
            self.sock = None
            logging.error(repr(msg))
            return False
        return True
    
    def close(self):
        if self.sock:
            logging.debug(f"Closing socket")
            self.sock.close()
            self.sock = None

    def recv(self, size):
        data = False
        try:
            data = self.sock.recv(size)
        except socket.error as msg:
            self.close()
            logging.error(f"Unexpected socket error while expecting to receive {size} bytes:")
            logging.error(repr(msg))
        return data

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

        if type(content) is bytearray or type(content) is bytes:
            encodedContent = content
        elif type(content) is str:
            encodedContent = content.encode('utf-8')
        else:
            raise Exception("Cannot encode the following content into fastcgi record: {content}")

        response = response + encodedContent

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
        return record + bytearray(str(name).encode('ascii')) + bytearray(str(value).encode('ascii'))

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
        header = self.recv(int(self.__FCGI_HEADER_SIZE))
        if not header:
            logging.debug(f"Received empty response")
            return False
        
        record = self.__decodeFastCGIHeader(header)
        requestId = record['requestId'] 
        logging.debug(f"[{requestId}] Received header message type {self.typeToString(record['type'])}")
        record['content'] = bytes()
        if 'contentLength' in record.keys():
            totalContentLength = int(record['contentLength'])
            contentLength = 0
            while contentLength < totalContentLength:
                buffer = self.recv(totalContentLength - contentLength)
                contentLength += len(buffer)
                logging.debug(f"[{requestId}] Received content {contentLength} / {totalContentLength} bytes")
                if buffer:
                    record['content'] += buffer
                if len(buffer) == 0:
                    break
        if 'paddingLength' in record.keys():
            logging.debug(f"[{requestId}] Skipping padding content {record['paddingLength']} bytes")
            skiped = self.recv(int(record['paddingLength']))
        return record

    def request(self, nameValuePairs={}, post=''):
        if self.sock == None and not self.connect():
            logging.error('Connect failure: please check fastcgi connexion parameters')
            return None

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
        
        paramsRecord = bytearray()
        if nameValuePairs:
            for (name, value) in nameValuePairs.items():
                logging.debug(f"Request param: {name}={value}")
                paramsRecord += self.__encodeNameValueParams(name, value)

        if len(paramsRecord) > 0:
            request += self.__encodeFastCGIRecord(self.__FCGI_TYPE_PARAMS, paramsRecord, requestId)
        request += self.__encodeFastCGIRecord(self.__FCGI_TYPE_PARAMS, bytearray(), requestId)

        if post:
            logging.debug(f"Request STDIN: {post}")
            request += self.__encodeFastCGIRecord(self.__FCGI_TYPE_STDIN, post, requestId)
        request += self.__encodeFastCGIRecord(self.__FCGI_TYPE_STDIN, bytearray(), requestId)
        logging.debug(f"[{requestId}] Sending request")
        self.sock.send(request)
        self.requests[requestId]['state'] = self.FCGI_STATE_SEND
        self.requests[requestId]['response'] = bytearray()
        return self.waitForResponse(requestId)

    def waitForResponse(self, requestId):
        waitRequestIds = ','.join([str(x) for x in self.requests.keys()])
        logging.debug(f"[{waitRequestIds}] Waiting for response")
        while True:
            response = self.__decodeFastCGIRecord()
            if not response:
                break

            if requestId != int(response['requestId']):
                logging.debug(f"[{response['requestId']}] Skipping content for this request id...")
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
        
        self.close()
        response = self.requests[requestId]['response']
        del self.requests[requestId]

        logging.debug(f"[{requestId}] Raw response:\n{response}")
        return response
