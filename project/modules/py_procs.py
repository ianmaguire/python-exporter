#!/usr/bin/env python
import ConfigParser
import os.path
import time

class PyProcesses(object):
  def __init__(self, config_file=None):
    if config_file is None: config_file="config.ini"
    Config = ConfigParser.ConfigParser()
    Config.read(config_file)
    self.name = 'Python Exporter Processes Module'
    self.version = '0.0.1'
    self.author = Config.get('python_exporter', 'author')
    self.license = Config.get('python_exporter', 'license')
    self.headers = {"Content-Type":"application/json","Accept":"application/json"}
    self.basepath = os.path.dirname(__file__)

  def about(self):
    data = self.name + ': ' + self.version
    return data

  def blocked(self):
    starttime = time.time()
    with open('/proc/stat', 'r') as f:
      for line in f: 
        l = line.split()
        if l[0] == 'procs_blocked':
            data = l[1]
            f.close()
            response = lambda: None
            response.success = str(1)
            response.response = data
            endtime = time.time()
            duration = endtime - starttime
            response.duration = str(duration)
            return response
        else:
            response = lambda: None
            response.success = str(0)
            response.response = str(0)
            endtime = time.time()
            duration = endtime - starttime
            response.duration = str(duration)
    return response # returns the number voluntary and involuntary context switches performed

  def running(self):
    starttime = time.time()
    with open('/proc/stat', 'r') as f:
      for line in f: 
        l = line.split()
        if l[0] == 'procs_running':
            data = l[1]
            f.close()
            response = lambda: None
            response.success = str(1)
            response.response = data
            endtime = time.time()
            duration = endtime - starttime
            response.duration = str(duration)
            return response
        else:
            response = lambda: None
            response.success = str(0)
            response.response = str(0)
            endtime = time.time()
            duration = endtime - starttime
            response.duration = str(duration)
    return response # returns the number voluntary and involuntary context switches performed

if __name__ == "__main__":
  py_proc = PyProcesses(config_file="config.ini")
  print py_proc.about()