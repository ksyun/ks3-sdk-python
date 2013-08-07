# coding:utf-8

import urllib
import httplib
import time
import hmac
import base64
import random
from hashlib import sha1

class CallingFormat:
    PATH = 1
    SUBDOMAIN = 2
    VANITY = 3

def query_args_hash_to_string(query_args):    
    pairs = []
    for k, v in query_args.items():
        piece = k
        if v != None:
            piece += "=%s" % urllib.quote_plus(str(v).encode('utf-8'))
        pairs.append(piece)

    return '&'.join(pairs)

def merge_meta(headers, metadata):
    final_headers = headers.copy()
    for k in metadata.keys():
        final_headers["x-kss-" + "meta-" + k] = metadata[k]

    return final_headers

def canonical_string(method, bucket="", key="", query_args=None, headers=None, expires=None):
    if not headers:
        headers = {}
    if not query_args:
        query_args = {}
        
    interesting_headers = {}
    for header_key in headers:
        lk = header_key.lower()
        if lk in ['content-md5', 'content-type', 'date'] or lk.startswith("x-kss-"):
            interesting_headers[lk] = headers[header_key].strip()
    if not interesting_headers.has_key('content-type'):
        interesting_headers['content-type'] = ''
    if not interesting_headers.has_key('content-md5'):
        interesting_headers['content-md5'] = ''
    if interesting_headers.has_key('x-kss-date'):
        interesting_headers['date'] = ''
    if expires:
        interesting_headers['date'] = str(expires)

    sorted_header_keys = interesting_headers.keys()
    sorted_header_keys.sort()
    buf = "%s\n" % method
    for header_key in sorted_header_keys:
        if header_key.startswith("x-kss-"):
            buf += "%s:%s\n" % (header_key, interesting_headers[header_key])
        else:
            buf += "%s\n" % interesting_headers[header_key]

    if bucket:
        buf += "/%s" % bucket
    buf += "/%s" % urllib.quote_plus(key.encode('utf-8'))
    if query_args.has_key("acl"):
        buf += "?acl"

    return buf

def encode(secret_access_key, str_to_encode, urlencode=False):
    b64_hmac = base64.encodestring(hmac.new(secret_access_key, str_to_encode, sha1).digest()).strip()
    if urlencode:
        return urllib.quote_plus(b64_hmac)
    else:
        return b64_hmac

def add_auth_header(access_key_id, secret_access_key, headers, method, bucket, key, query_args):
    if not access_key_id:
        return
    if not headers.has_key('Date'):
        headers['Date'] = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())

    c_string = canonical_string(method, bucket, key, query_args, headers)
    headers['Authorization'] = \
        "%s %s:%s" % ("KSS", access_key_id, encode(secret_access_key, c_string))
    
def make_request(server, port, access_key_id, access_key_secret, method, bucket="",
                 key="", query_args=None, headers=None, data="", metadata=None,
                 call_fmt=CallingFormat.PATH, is_secure=False):
    if not headers:
        headers = {}
    if not query_args:
        query_args = {}
    if not metadata:
        metadata = {}

    path = ""
    if bucket:
        if call_fmt == CallingFormat.SUBDOMAIN:
            server = "%s.%s" % (bucket, server)
        elif call_fmt == CallingFormat.VANITY:
            server = bucket
        elif call_fmt == CallingFormat.PATH:
            path += "/%s" % bucket

    path += "/%s" % urllib.quote_plus(key.encode("utf-8"))

    if query_args:
        path += "?" + query_args_hash_to_string(query_args)

    host = "%s:%d" % (server, port)
    
    if (is_secure):
        connection = httplib.HTTPSConnection(host)
    else:
        connection = httplib.HTTPConnection(host)

    final_headers = merge_meta(headers, metadata)
    if method == "PUT" and "Content-Length" not in final_headers and not data:
        final_headers["Content-Length"] = "0"
        
    add_auth_header(access_key_id, access_key_secret, final_headers, method,
                    bucket, key, query_args)
    connection.request(method, path, data, final_headers)
    resp = connection.getresponse()
    return resp


def get_object_url(age, bucket="", key="", secret_access_key="", access_key_id="", query_args={}):
    expire = str(int(time.time()) + age)
    headers = {"Date": expire}
    c_string = canonical_string("GET", bucket, key, query_args, headers)    
    path = c_string.split("\n")[-1]
    
    signature = urllib.quote_plus(encode(secret_access_key, c_string))
    if "?" in path:
        url = "http://kss.ksyun.com%s&Expires=%s&AccessKeyId=%s&Signature=%s" % \
            (path, expire, access_key_id, signature)
    else:
        url = "http://kss.ksyun.com%s?Expires=%s&AccessKeyId=%s&Signature=%s" % \
            (path, expire, access_key_id, signature)        
    return url

class Connection:
    
    def __init__(self, access_key_id, access_key_secret, server="kss.ksyun.com",
            port=80, is_secure=False, calling_format=CallingFormat.PATH):
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.is_secure = is_secure
        self.server = server
        self.port = port
        self.calling_format = calling_format
        
    def make_request(self, method, bucket="", key="", data="",
            headers=None, query_args=None, metadata=None):        
        if not headers:
            headers = {}
        if not query_args:
            query_args = {}
        if not metadata:
            metadata = {}
        
        resp = make_request(self.server, self.port, self.access_key_id, self.access_key_secret,
            method, bucket, key, query_args, headers, data, metadata)
        
        return resp    
    
