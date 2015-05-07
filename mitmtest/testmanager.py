from .test import Test

class TestManager:
  def __init__(self, test_mode):
    self.test_mode = test_mode
    self.tests_by_addr = {}  

  def shouldTestClientAddress(self, address):
    return not self.test_mode == Test.TYPE_NONE

  def addTest(self, address, test):
    self.tests_by_addr[address] = test

  def getTest(self, address):
    if not self.tests_by_addr.has_key(address):
      return None
    return self.tests_by_addr[address]

