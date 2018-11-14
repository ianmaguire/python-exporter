#!/usr/bin/env python
import ConfigParser
import os.path
import time

class PyMemInfo(object):
  def __init__(self, config_file=None):
    if config_file is None: config_file="config.ini"
    Config = ConfigParser.ConfigParser()
    Config.read(config_file)
    self.name = 'Python Exporter Memory Info Module'
    self.version = '0.0.1'
    self.author = Config.get('python_exporter', 'author')
    self.license = Config.get('python_exporter', 'license')
    self.headers = {"Content-Type":"application/json","Accept":"application/json"}
    self.basepath = os.path.dirname(__file__)

  def about(self):
    data = self.name + ': ' + self.version
    return data

  def meminfo(self):
    starttime = time.time()
    with open('/proc/meminfo', 'r') as f:
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
  py_meminfo = PyMemInfo(config_file="config.ini")
  print py_meminfo.about()