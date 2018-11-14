#!/usr/bin/env python
import psutil
import ConfigParser
import os.path
import time

class PyContextSwitches(object):
  def __init__(self, config_file=None):
    if config_file is None: config_file="config.ini"
    Config = ConfigParser.ConfigParser()
    Config.read(config_file)
    self.name = 'Python Exporter Context Switches Time Module'
    self.version = '0.0.1'
    self.author = Config.get('python_exporter', 'author')
    self.license = Config.get('python_exporter', 'license')
    self.headers = {"Content-Type":"application/json","Accept":"application/json"}
    self.basepath = os.path.dirname(__file__)

  def about(self):
    data = self.name + ': ' + self.version
    return data

  def context_switches(self):
    # data = psutil.cpu_stats()
    ## AttributeError: 'module' object has no attribute 'cpu_stats'
    ## no num_stx_switches() either
    with open('/proc/stat', 'r') as f:
      starttime = time.time()
      for line in f: 
        l = line.split()
        if l[0] == 'ctxt':
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
    # if no results, return zero
    return response # returns the number voluntary and involuntary context switches performed



if __name__ == "__main__":
  py_context_switches = PyContextSwitches(config_file="config.ini")
  print py_context_switches.about()

