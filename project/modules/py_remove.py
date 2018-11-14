#!/usr/bin/env python
import ConfigParser
import os

class Remove(object):

  def __init__(self, config_file=None):
	if config_file is None: config_file="config.ini"
    Config = ConfigParser.ConfigParser()
    Config.read(config_file)
    self.name = 'Remove File Module'
    self.version = '0.0.1'

  def about(self):
    message = self.name + ': ' + self.version
    return message

  def remove_file(self, username, password, group=None)
    starttime = time.time()
    response = lambda: None
    os.remove('/tmp/hugefile')
    response.response = 'Success'
    endtime = time.time()
    duration = endtime - starttime
    response.duration = str(duration)
    return response

if __name__ == "__main__":
  remove = Remove(config_file="../config.ini")
  print remove_file.about()