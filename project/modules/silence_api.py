#!/usr/bin/env python
import ConfigParser
import os.path
import requests
import subprocess
import json
import urllib3

class SilenceAPI(object):
  def __init__(self, config_file=None):
    if config_file is None: config_file="config.ini"
    Config = ConfigParser.ConfigParser()
    Config.read(config_file)
    self.name = 'Silence Prometheus Alertmanager Module'
    self.version = '0.0.1'
    self.author = Config.get('python_exporter', 'author')
    self.license = Config.get('python_exporter', 'license')
    self.alertmanager_host = Config.get('alertmanager', 'alertmanager_host')
    self.headers = {"Content-Type":"application/json"}
    self.basepath = os.path.dirname(__file__)

  def about(self):
    data = self.name + ': ' + self.version
    return data

  def silence(self,instance,duration=None):
    if duration is None: duration='2 hours'
    url = self.alertmanager_host+'/api/v1/silences'
    date = subprocess.Popen(['date','--rfc-3339=ns'], stdout=subprocess.PIPE).stdout.read()
    start = date.replace(' ', 'T')
    starttime = str(start.replace('+00:00', 'Z')).rstrip()
    length = '+'+duration
    enddate = subprocess.Popen(['date','--rfc-3339=ns', '-d', length], stdout=subprocess.PIPE).stdout.read()
    end = enddate.replace(' ', 'T')
    endtime = str(end.replace('+00:00', 'Z')).rstrip()
    datastring = '{"matchers":[{"name":"instance","value":"'+instance+'","isRegex":false}],"startsAt":"'+starttime+'","endsAt":"'+endtime+'","updatedAt":"'+starttime+'","createdBy":"API","comment":"Silence!","status":{"state":"active"}}'
    print url
    data =  json.loads(json.dumps(datastring))
    print str(data)
    response = requests.post(url, data=datastring)
    print str(response.json())
    if response.status_code != 201: print('Status:', response.status_code, 'Headers:', response.headers, 'Error Response:',response.json())
    return response

  def get_silences(self,instance):
    url = self.alertmanager_host+'/api/v1/silences'
    response = requests.get(url)
    return response.json()

  def delete_silence(self,silence_id):
    url = self.alertmanager_host+'/api/v1/silence/'+str(silence_id)
    print url
    response = requests.delete(url)
    print('Status:', response.status_code, 'Headers:', response.headers)
    print('Text:', response.text)
    return response.json()



if __name__ == "__main__":
  silence = SilenceAPI(config_file="config.ini")
  print silence.about()
