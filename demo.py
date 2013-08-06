# coding:utf-8

# A Simple Demo

import os
import sys
import base64
import urllib2
from helper import Connection

ACCESS_KEY_ID = "<INSERT YOUR AWS ACCESS KEY ID HERE>"
SECRET_ACCESS_KEY = "<INSERT YOUR AWS SECRET ACCESS KEY HERE>"

# remove the next line when you've updated your ACCESS_KEY_ID and SECRET_ACCESS_KEY.
sys.exit();

def kss_demo():
    kss_conn = Connection(ACCESS_KEY_ID, SECRET_ACCESS_KEY)
    
    # Create A Bucket
    bucket_name = "mybucket-%s" % (base64.b16encode(os.urandom(16)).lower())    
    response = kss_conn.make_request("PUT", bucket_name)
    assert response.status == 200
 
    # List Buckets
    response = kss_conn.make_request("GET")
    assert response.status == 200
    print "Buckets:"
    print response.read()
    
    # Create An Object
    object_key = "object_key"
    object_data = "hello kss!"
    response = kss_conn.make_request("PUT", bucket_name, object_key, object_data)    
    assert response.status == 200

    # List Objects
    response = kss_conn.make_request("GET", bucket_name)
    assert response.status == 200
    print "Objects:"
    print response.read()

    # Download The Object
    response = kss_conn.make_request("GET", bucket_name, object_key)
    assert response.status == 200
    print "Downloaded:"
    print response.read()
    
    # Delete The Object
    response = kss_conn.make_request("DELETE", bucket_name, object_key)
    assert response.status == 204
    
    # Delete The Bucket
    response = kss_conn.make_request("DELETE", bucket_name)
    assert response.status == 204

if __name__ == '__main__':
    kss_demo()
