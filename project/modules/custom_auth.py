#!/usr/bin/env python
import ConfigParser
import json

class customAuth(object):

  def __init__(self, config_file=None):
	if config_file is None: config_file="config.ini"
    Config = ConfigParser.ConfigParser()
    Config.read(config_file)
    self.name = 'Custom Auth Module'
    self.version = '0.0.1'

  def about(self):
    message = self.name + ': ' + self.version
    return message

  # Return True for successful logins, False for failed login
  def auth_check(self, username, password, group=None)
    # To be continued...
    return False

if __name__ == "__main__":
  custom_auth = customAuth(config_file="../config.ini")
  print custom_auth.about()