import argparse
import copy
from os.path import dirname
import sys, inspect, os
sys.path.append(os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))) # script directory
from mitmtest.testmanager import TestManager
from mitmtest.test import Test

domains_undertest = []
supress_pass = False
mgr = None

"""
    MITM Tester 
    by Glen Tregoning
"""
def start(context, argv):
    """
        Called once on script startup, before any other events.
    """
    parser = argparse.ArgumentParser(prog='mitmtest.sh', description='Test for Man In The Middle Vulnerabilities, including acceptance of self-signed/insecure certificates ("--test insecure"), and verification the certificate domain name matches the host connecting to ("--test domain").')
    parser.add_argument('intercept_domains', metavar='example.com, an.example.com', nargs='*', help='domains under test')
    parser.add_argument('--test', help="MITM test to run: 'insecure' (default): test with self-signed / insecure certificate, 'domain'= test the application verifies the domain of the certificate matches the host it's connecting to.", choices=['insecure', 'domain', 'none'], default="insecure")
    parser.add_argument('--suppress-pass', help="don't print hosts which pass the MITM test", action="store_true")
    args = parser.parse_args(args=argv[1:])
    global suppress_pass
    suppress_pass = args.suppress_pass
    
    global domains_undertest
    domains_undertest = args.intercept_domains
    test_mode = None
    if args.test == "domain":
      test_mode = Test.TYPE_DOMAIN_VERIFY
    elif args.test == "insecure":
      test_mode = Test.TYPE_SELF_SIGNED_INSECURE

    global mgr 
    mgr = TestManager(test_mode)
    print args
    context.log("start " + str(domains_undertest))

def request(context, flow):
    """
        Called when a client request has been received.
    """
    global failed
    global mgr
    
    client_addr = flow.client_conn.address
    test = mgr.getTest(client_addr)
    if test:
      if flow.server_conn.ssl_established == True:
        host=flow.server_conn.address.host
        user_agent = flow.request.headers.get_first("User-Agent")
        test.failTestForHost(host, user_agent)

def response(context, flow):
    """
       Called when a server response has been received.
    """
    if flow.server_conn.ssl_established == True:
      test = mgr.getTest(flow.client_conn.address)
      msg = "9000 Intercepted (no test being run)"
      if test:
        if test.type == Test.TYPE_SELF_SIGNED_INSECURE:
          msg = "9001 Intercepted via insecure certificate failure"
        elif test.type == Test.TYPE_DOMAIN_VERIFY:
          msg = "9002 Intercepted via domain verification failure"
      flow.response.headers["x-mitm-failed"] = [msg]
    
def clientconnect(context, conn_handler):
    global mgr
    global domains_undertest
    global suppress_pass
    address = conn_handler.client_conn.address
    if mgr.shouldTestClientAddress(address):
      test = Test(conn_handler.client_conn.address, conn_handler, mgr.test_mode, domains_undertest, suppress_pass)
      test.changeState(Test.STATE_ACTIVE)
      mgr.addTest(address, test)

def clientdisconnect(context, conn_handler):
    """
        Called when a client disconnects from the proxy.
    """
    global failed
    global domains_undertest
    global mgr

    client_addr = conn_handler.client_conn.address
    test = mgr.getTest(client_addr)
    if test:
      # Client Disconnected
      server_conn = conn_handler.server_conn
      if server_conn and server_conn.ssl_established == True:
        host=str(server_conn.address.host)
        test.potentialPassTestForHost(host)

