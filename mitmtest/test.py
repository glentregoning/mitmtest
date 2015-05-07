from libmproxy.proxy.config import ProxyConfig
from netlib.certutils import * 

class Test:
  TYPE_DOMAIN_VERIFY = "DOMAIN_VERIFY"
  TYPE_SELF_SIGNED_INSECURE = "SELF_SIGNED_INSECURE"
  TYPE_NONE = "NONE"

  STATE_IDLE = "IDLE"
  STATE_ACTIVE = "ACTIVE"
  STATE_FAILED = "FAILED"
  STATE_PASSED = "PASSED"

  def __init__(self, address, conn_handler, type, domains_under_test, suppress_pass):
    self.address = address
    self.conn_handler = conn_handler
    self.type = type
    self.domains_under_test = domains_under_test
    self.suppress_pass = suppress_pass
    self.state = Test.STATE_IDLE
    self.failed = {}
    self.passed = []

  def changeState(self, state):
    #print "<Test: %s State change '%s' -> '%s'>" % (str(self.address), str(self.state), str(state))
    self.state = state
    self.handle_state_change()

  def failTestForHost(self, host, user_agent):
    self.changeState(Test.STATE_FAILED)
    if self.failed.has_key(host) == False:
      self.failed[host] = []

    if not user_agent in self.failed[host]: 
      self.failed[host].append(user_agent)
      print "FAILED - MITM executed on request to https://%(host)s by user-agent:%(user_agent)s" % {'host': host, "user_agent" : user_agent }

  def potentialPassTestForHost(self, host):
    if self.failed.has_key(host) == False and self.is_host_under_test(host): 
      self.changeState(Test.STATE_PASSED)
      self.passed.append(host)
      if self.suppress_pass == False:
        print "PASSED - MITM failed on request to https://%(host)s" % {'host' : host }

  def is_host_under_test(self, host):
    under_test = len(self.domains_under_test) == 0
    if len(self.domains_under_test) > 0:
      for test_host in self.domains_under_test:
         if test_host in host:
            under_test = True
            break
    return under_test

  def copyConfig(self, override_ignore_patterns = None):
    c = self.conn_handler.config 
    ignored_hosts = c.check_ignore.patterns
    if override_ignore_patterns:
      ignored_hosts = override_ignore_patterns
    copy_config = ProxyConfig(
      host= c.host,
      port= c.port,
      server_version=c.server_version,
      cadir= c.cadir,
      clientcerts = c.clientcerts,
      no_upstream_cert= c.no_upstream_cert,
      body_size_limit= c.body_size_limit,
      mode= c.mode,
      # upstream_server= c.upstream_server, # Can't clone sadly...
      # http_form_in= c.http_form_in,
      # http_form_out= c.http_form_out,
      authenticator= c.authenticator,
      ignore_hosts= ignored_hosts,
      tcp_hosts= c.check_tcp.patterns,
      # ciphers_client = c.ciphers_client, # Not set?
      # ciphers_server= c.ciphers_server,
      # certs= c.certs, # This will be replaced below 
      certforward = c.certforward,
      # ssl_version_client= c.ssl_version_client,
      # ssl_version_server= c.ssl_version_server,
      ssl_ports= c.ssl_ports
    )
    return copy_config

  def ignored_hosts(self):
    if len(self.domains_under_test) == 0:
      return ['^(?!.*.).*']
    else:
      ignore = '^(?!'
      isFirst = True
      for domain in self.domains_under_test:
        if not isFirst:
          ignore += '|'
        ignore += ".*%s" % domain
        isFirst = False
      ignore += ').*'
      return [ignore]

  def config_self_signed_insecure_test(self):
    self.conn_handler.config = self.copyConfig(self.ignored_hosts())
    config = self.conn_handler.config
    config.certstore = CertStore.from_store(config.cadir, 'mitmtest-insecure')
    config.certstore.certs = dict()

  def config_domain_verify_test(self):
    self.conn_handler.config = self.copyConfig(self.ignored_hosts())
    config = self.conn_handler.config
    config.certstore.certs = dict()
    cert = config.certstore.get_cert("test.mitm.gtbox.info", [])
    config.certstore.add_cert(
            CertStoreEntry(cert[0], cert[1], cert[2]),
            "*"
    )

  def handle_state_change(self):
    if self.state == Test.STATE_ACTIVE and self.type == Test.TYPE_DOMAIN_VERIFY:
      self.config_domain_verify_test()   
    if self.state == Test.STATE_ACTIVE and self.type == Test.TYPE_SELF_SIGNED_INSECURE:
      self.config_self_signed_insecure_test()   

  def __str__(self):
    return "<Test(%s): %s State '%s'>" % (str(self.type), str(self.address), str(self.state))


