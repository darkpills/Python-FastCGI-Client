import socket
import logging
from . FastCGIClient import FastCGIClient

class PHPFPMClient(FastCGIClient):
            
    def __init__(self, target='127.0.0.1:9000', timeout=3000):
        super().__init__(target, timeout)

    def recv(self, size):
        data = False
        try:
            data = self.sock.recv(size)
        except socket.error as msg:
            self.close()
            # don't know why, but for non local IP (127.0.0.1), we receive TCP RESET 
            # maybe because pool worker is crashing?
            if msg.errno == 104:
                logging.debug(f"Expected receive error: {msg.strerror}")
            # else we output it as an expected error
            else:
                logging.error(f"Unexpected socket receive error while expecting {size} bytes:")
                logging.error(repr(msg))
        return data

    def request(self, file, method='GET', queryString='', post='', options={}, decode=True):
        if not self.connect():
            logging.error('Connect failure: please check fastcgi connexion parameters')
            return None
        
        (localIP, localPort) = self.sock.getsockname()
        params = {
            'GATEWAY_INTERFACE': 'FastCGI/1.0',
            'REQUEST_METHOD': method,
            'SCRIPT_FILENAME': file,
            'SCRIPT_NAME': file,
            'QUERY_STRING': queryString,
            'SERVER_SOFTWARE': 'python3/fcgi-client',
            'REMOTE_ADDR': localIP,
            'REMOTE_PORT': localPort,
            'SERVER_PROTOCOL': 'HTTP/1.1'
        }
        if self.host != None:
            params['SERVER_ADDR'] = self.host
        if self.port != None:
            params['SERVER_PORT'] = self.port

        params.update(options)

        response = super().request(params, post)
        if decode and response != None:
            response = self.__decodeResponse(response)
        return response
    
    def get(self, file, queryString='', options={}, decode=True):
        return self.request(file, 'GET', queryString, '', options, decode)

    def delete(self, file, queryString='', options={}, decode=True):
        return self.request(file, 'DELETE', queryString, '', options, decode)
    
    def post(self, file, post, options={}, decode=True):
        return self.request(file, 'POST', '', post, options, decode)
    
    def put(self, file, post, options={}, decode=True):
        return self.request(file, 'PUT', '', post, options, decode)

    def __getHTTPHeaders(self, response):
        headers = {}
        buffer = bytearray()

        if response == None:
            return headers
        for i in range(len(response)-1):
            if response[i:i+2] == b"\r\n":
                headerSplit = buffer.decode('ascii').split(':')
                name = headerSplit[0].strip()
                value = headerSplit[1].strip() if len(headerSplit) > 1 else ''
                headers[name] = value
                buffer = bytearray()
            if i + 4 < len(response) and response[i:i+4] == b"\r\n\r\n":
                break
            
            buffer.append(response[i])
        
        return headers
    
    def __guessCharset(self, response):
        charset = "utf-8"
        if response == None:
            return charset
        headers = self.__getHTTPHeaders(response)
        for name, value in headers.items():
            if "charset" in value.lower():
                pos = value.lower().find("charset")
                charset = value[pos:].split(' ')[0].split('=')[1].strip().lower()
                logging.debug(f"Found charset {charset} in the response headers to decode it")
                return charset
        
        logging.debug(f"Attempting to decode response with default charset {charset}")
        return charset
    
    def __decodeResponse(self, response):
        charset = self.__guessCharset(response)
        return response.decode(charset)
