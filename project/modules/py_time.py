#!/usr/bin/env python
import ConfigParser
import subprocess
import os.path
import time

class PyTime(object):
  def __init__(self, config_file=None):
    if config_file is None: config_file="config.ini"
    Config = ConfigParser.ConfigParser()
    Config.read(config_file)
    self.name = 'Python Exporter Time Module'
    self.version = '0.0.1'
    self.author = Config.get('python_exporter', 'author')
    self.license = Config.get('python_exporter', 'license')
    self.alertmanager_host = Config.get('alertmanager', 'alertmanager_host')
    self.headers = {"Content-Type":"application/json"}
    self.basepath = os.path.dirname(__file__)

  def about(self):
    data = self.name + ': ' + self.version
    return data

  def time(self):
    starttime = time.time()
    data = subprocess.Popen(['date','+%s'], stdout=subprocess.PIPE).stdout.read()
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
  time = PyTime(config_file="config.ini")
  print time.about()