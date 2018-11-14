#!/usr/bin/env python
import ConfigParser
import os.path
import time

class PySockstat(object):
  def __init__(self, config_file=None):
    if config_file is None: config_file="config.ini"
    Config = ConfigParser.ConfigParser()
    Config.read(config_file)
    self.name = 'Python Exporter Sockstat Module'
    self.version = '0.0.1'
    self.author = Config.get('python_exporter', 'author')
    self.license = Config.get('python_exporter', 'license')
    self.headers = {"Content-Type":"application/json","Accept":"application/json"}
    self.basepath = os.path.dirname(__file__)

  def about(self):
    data = self.name + ': ' + self.version
    return data

  def sockstat(self):
    starttime = time.time()
    with open('/proc/net/sockstat', 'r') as f:
      data = f.readlines()
    f.close()
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
  py_sockstat = PySockstat(config_file="config.ini")
  print py_sockstat.about()