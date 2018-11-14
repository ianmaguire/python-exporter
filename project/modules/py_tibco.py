#!/usr/bin/env python
import ConfigParser
import os.path
import pexpect
import time

class PyTibco(object):
  def __init__(self, config_file=None):
    if config_file is None: config_file="config.ini"
    Config = ConfigParser.ConfigParser()
    Config.read(config_file)
    self.name = 'Python Exporter Tibco Module'
    self.version = '0.0.1'
    self.author = Config.get('python_exporter', 'author')
    self.license = Config.get('python_exporter', 'license')
    self.headers = {"Content-Type":"application/json","Accept":"application/json"}
    self.basepath = os.path.dirname(__file__)

  def about(self):
    data = self.name + ': ' + self.version
    return data

  def tibco(self):
    starttime = time.time()
    tibco = pexpect.spawn('/usr/local/thirdparty/tibco/CURRENT/ems/8.2/bin/tibemsadmin ssl://localhost:7243')
    tibco.expect('Login .*: ')
    tibco.sendline('MyUserName')
    tibco.expect('Password: ')
    tibco.sendline('MyPassWord')
    tibco.expect('ssl://localhost:7243>')
    tibco.sendline('show queues')
    tibco.expect('ssl://localhost:7243>')
    data = 'Queues:::\n'
    data += str(tibco.before)
    tibco.sendline('show bridges')
    tibco.expect('ssl://localhost:7243>')
    data += '\n###Bridges:::\n'
    data += str(tibco.before)
    tibco.sendline('show consumers')
    tibco.expect('ssl://localhost:7243>')
    data += '\n###Consumers:::\n'
    data += str(tibco.before)
    tibco.sendline('show connections')
    tibco.expect('ssl://localhost:7243>')
    data += '\n###Connections:::\n'
    data += str(tibco.before)
    tibco.sendline('quit')
    response = lambda: None
    if data:
      response.success = str(1)
    else:
      response.success = str(0)
    response.response = data
    endtime = time.time()
    duration = endtime - starttime
    response.duration = duration
    return response

if __name__ == "__main__":
  py_tibco = PyTibco(config_file="config.ini")
  print py_tibco.about()