#!/usr/bin/env python
import ConfigParser
import os.path
import subprocess
import time

class PySensors(object):
  def __init__(self, config_file=None):
    if config_file is None: config_file="config.ini"
    Config = ConfigParser.ConfigParser()
    Config.read(config_file)
    self.name = 'Python Exporter Sensors Module'
    self.version = '0.0.1'
    self.author = Config.get('python_exporter', 'author')
    self.license = Config.get('python_exporter', 'license')
    self.headers = {"Content-Type":"application/json","Accept":"application/json"}
    self.basepath = os.path.dirname(__file__)

  def about(self):
    data = self.name + ': ' + self.version
    return data

  def sensors(self):
    starttime = time.time()
    data = subprocess.Popen(['sensors','-A'], stdout=subprocess.PIPE).stdout.read()
    response = lambda: None
    if data:
      response.success = str(1)
    else:
      response.success = str(0)
    response.response = str(data)
    endtime = time.time()
    duration = endtime - starttime
    response.duration = duration
    return response

if __name__ == "__main__":
  py_sensors = PySensors(config_file="config.ini")
  print py_sensors.about()
  