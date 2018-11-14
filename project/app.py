#!/usr/bin/env python
import ConfigParser
import json
import socket
import os.path
# from prometheus_client import start_http_server, Summary, Counter, CollectorRegistry, Gauge, write_to_textfile, Histogram, push_to_gateway
# from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily, REGISTRY
# from prometheus_client.parser import text_string_to_metric_families
import random
import time
from itertools import izip
from collections import namedtuple, defaultdict
import re
import requests
import platform
import distro

# Py_Exporter custom modules
import modules.py_cpu
import modules.py_boot_time
import modules.py_context_switches
import modules.py_disk_bytes_read
import modules.py_disk_io
import modules.py_entropy_available_bits
import modules.py_fd
import modules.py_filesystem
import modules.py_disk_usage
import modules.py_df
import modules.py_forks
import modules.py_sensors
import modules.py_interrupts
import modules.py_load
import modules.py_meminfo
import modules.py_netstat
import modules.py_tibco
import modules.silence_api
import modules.py_netinfo
import modules.py_procs
import modules.py_sockstat
import modules.py_time
import modules.py_uname
import modules.py_vmstat
import modules.py_whoami
import modules.py_uwsgi
import modules.py_remove

# Required for Flask Basic Authentication
from functools import wraps

# Read Config
Config = ConfigParser.ConfigParser()
Config.read("config.ini")

__appname__ = Config.get('python_exporter', 'app_name')
__author__  = Config.get('python_exporter', 'author')
__version__ = Config.get('python_exporter', 'api_version')
__license__ = Config.get('python_exporter', 'license')

# Start Flask
from flask import Flask, jsonify, render_template, request, Response, json, redirect, url_for, send_from_directory
#from flask_prometheus import monitor 
app = Flask(__name__)
app.debug = True
app.logger.info("Starting Flask")

# Set hostname
hostname = socket.gethostname()
app.logger.info('Hostname '+hostname)

# Place holder for anything we want to do at launch
def startup():
  app.logger.info('Starting Python Exporter')

startup()

# Define error handling
def error(message):
  app.logger.error(message)

# Load modules
try: 
  py_cpu = modules.py_cpu.PyCPU()
  app.logger.info('Module Loaded: py_cpu')
  py_boot_time = modules.py_boot_time.PyBoot()
  app.logger.info('Module Loaded: py_boot_time')
  py_context_switches = modules.py_context_switches.PyContextSwitches()
  app.logger.info('Modules Loaded: py_context_switches')
  py_disk_bytes_read = modules.py_disk_bytes_read.PyDiskBytesRead()
  app.logger.info('Module Loaded: py_disk_bytes_read')
  py_disk_io = modules.py_disk_io.PyDiskIO()
  app.logger.info('Modeule Loaded: py_disk_io')
  py_entropy_available_bits = modules.py_entropy_available_bits.PyEntropy()
  app.logger.info('Module Loaded: py_entropy_available_bits')
  py_fd = modules.py_fd.PyFD()
  app.logger.info('Module Loaded: py_fd')
  py_fs = modules.py_filesystem.PyFS()
  app.logger.info('Module Loaded: py_filesystem')
  py_disk_usage = modules.py_disk_usage.PyDiskUsage()
  app.logger.info('Module Loaded: py_disk_usage')
  py_df = modules.py_df.PyDF()
  app.logger.info('Module Loaded: py_df')
  py_forks = modules.py_forks.PyForks()
  app.logger.info('Module Loaded: py_forks')
  py_sensors = modules.py_sensors.PySensors()
  app.logger.info('Module Loaded: py_sensors')
  py_interrupts = modules.py_interrupts.PyInterrupts()
  app.logger.info('Module Loaded: py_interrupts')
  py_load = modules.py_load.PyLoad()
  app.logger.info('Module Loaded: py_load')
  py_meminfo = modules.py_meminfo.PyMemInfo()
  app.logger.info('Module Loaded: py_meminfo')
  py_netstat = modules.py_netstat.PyNetstat()
  app.logger.info('Module Loaded: py_netstat')
  py_tibco = modules.py_tibco.PyTibco()
  app.logger.info('Module Loaded: py_tibco')
  silence_api = modules.silence_api.SilenceAPI()
  app.logger.info('Module Loaded: silence')
  py_netinfo = modules.py_netinfo.PyNetInfo()
  app.logger.info('Module Loaded: py_netinfo')
  py_procs = modules.py_procs.PyProcesses()
  app.logger.info('Module Loaded: py_procs')
  py_sockstat = modules.py_sockstat.PySockstat()
  app.logger.info('Module Loaded: py_sockstat')
  py_time = modules.py_time.PyTime()
  app.logger.info('Module Loaded: py_time')
  py_uname = modules.py_uname.PyUname()
  app.logger.info('Module Loaded: py_uname')
  py_vmstat = modules.py_vmstat.PyVmstat()
  app.logger.info('Module Loaded: py_vmstat')
  py_whoami = modules.py_whoami.PyWhoami()
  app.logger.info('Module Loaded: py_whoami')
  py_uwsgi = modules.py_uwsgi.PyUwsgi()
  app.logger.info('Module Loaded: py_uwsgi')
  py_remove = modules.py_remove.Remove()
  app.logger.info('Module Loaded: py_remove')

except Exception as e:
  error(e)
  exit(1)

# Check config, specifically to see if authorization is required
def check_config():
  app.logger.info('Parsing config options')
  try:
    auth_required = Config.get('options', 'auth_required')
  except:
    auth_required = False

try:
  auth_required
  app.logger.info('Authentication required')
  # Import modules
  import modules.custom_auth
  custom_auth = modules.custom_auth.customAuth()
  app.logger.info('Module loaded {}'.format(custom_auth))

  # Message for failed attempts
  def authentication_fail():
    """Sends a 401 response that enables basic auth"""
    return Response(
    'Could not verify your access level for that URL.\n'
    'You must login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

  def requires_auth(f):
    @wraps(f)
    def api_login(*args, **kwargs):
      auth = request.authorization
      app.logger.info("api_login username: ({})".format(auth.username))
      auth_check = custom_auth.auth_check(user=auth.username, passw=auth.password)
      app.logger.info("ldap_check:  ".format(ldap_check))
      if not auth or not auth_check:
        app.logger.info("Authentication failure for user {}".format(auth.username))
        return authentication_fail()
      else:
        return_data = f(*args, **kwargs)
        app.logger.info("Authentication successful for user {}".format(auth.username))
        return return_data
    return api_login
except:
  app.logger.info('Authentication not required')
  def requires_auth(f):
    @wraps(f)
    def no_auth(*args, **kwargs):
      return f(*args, **kwargs)
    return no_auth

# Do the stuff above
startup()
check_config()

## API Routes

# Verbose health check to ensure basic functionality
@app.route('/api/v1.0/health')
@requires_auth
def api_health_check():
  try:
    app.logger.info("api_health_check()")
    results = {
      'message': '{} is running!'.format(__appname__),
      'status': 'running',
      }
    return_data = json.dumps({'result': results})
    app.logger.info(return_data)
    return return_data, 200
  except Exception as e:
    error(e)

# Silence alerts from alertmanager
@app.route('/api/v1.0/silence', methods=['POST'])
@requires_auth
def silence():
  app.logger.info('api_silence()')
  app.logger.info('request.data: '+str(request.data))
  if request.headers['Content-Type'] == 'application/json':
    app.logger.info('JSON Request')
  else: 
    return json.dumps({"result": {"error": "415 Unsupported Media Type. Must be JSON."}}), 415
  try:
    content = request.get_json(silent=True)
    instance = content.get('instance', None)
    duration = content.get('duration', None)
    app.logger.info('instance: %s', instance)
    app.logger.info('duration: %s', duration)
    app.logger.info('Parsing data')
    data = silence_api.silence(instance=instance,duration=duration)
    app.logger.info('data returned: %s', data)
    response = '{"result": {"data": '+str(data.json())+'}}'
    return json.loads(json.dumps(response)), 200
  except Exception as e:
    error(e)
    response = '{"result": {"error": '+str(e)+'}}'
    return json.loads(json.dumps(response)), 415

# Silence alerts from alertmanager
@app.route('/api/v1.0/silencedelete', methods=['POST'])
@requires_auth
def silencedelete():
  app.logger.info('api_silence_delete()')
  app.logger.info('request.data: '+str(request.data))
  if request.headers['Content-Type'] == 'application/json':
    app.logger.info('JSON Request')
  else: 
    return json.dumps({"result": {"error": "415 Unsupported Media Type. Must be JSON."}}), 415
  try:
    content = request.get_json(silent=True)
    instance = content.get('instance', None)
    all_silences = silence_api.get_silences(instance=instance)
    app.logger.info('data returned: %s', all_silences)
    silence_id = None
    for i in all_silences['data']:
      if i['status']['state'] == 'active':
        for item in i['matchers']:
          if item['value'] == instance:
            silence_id = i['id']
            break
    if silence_id is None: 
      response = '{"result": {"data": "No active silences found"}}'
      return json.loads(json.dumps(response)), 200
    else:
      delete_silence = silence_api.delete_silence(silence_id=silence_id)
      response = '{"result": {"data": '+str(delete_silence)+'}}'
      return json.loads(json.dumps(response)), 200
  except Exception as e:
    error(e)
    response = '{"result": {"error": '+str(e)+'}}'
    return json.loads(json.dumps(response)), 415

# Webpages / templates

@app.route('/')
@requires_auth
def index():
  app.logger.info("index()")
  data = {'title': 'Home Page', 'name': 'user', 'greeting': 'Hello'}  # fake user
  return render_template('index.html', data=data)

@app.route('/health')
@requires_auth
def health():
  app.logger.info("health()")
  data = {'title': 'Health Check', 'status': 'running'}
  return render_template('health.html', data=data)

@app.route('/remove')
@requires_auth
def remove():
  app.logger.info("remove()")
  remove_file = py_remove.remove_file()
  data = {'title': 'Remove File', 'status': remove_file.response}
  return render_template('remove.html', data=data)

# Exporter metrics for Prometheus. Must be unicode. HTML must be hidden as a #comment.  
@app.route('/metrics')
@requires_auth
def metrics():
  app.logger.info("metrics()")
  data = '# Python Exporter <pre style="word-wrap: break-word; white-space: pre-wrap;"> \n'
  # Check OS version
  kernel = platform.release()
  os_version = distro.version(pretty=False)
  os_version_int = int(float(os_version))
  os_dist = distro.id()
  if os_dist == 'rhel': 
    os_dist = os_dist.upper()
  elif os_dist == 'centos': 
    os_dist = 'CentOS'
  else: 
    os_dist = os_dist.capitalize()
  # Useful OS info
  data += '# OS: ' + str(os_dist) + ' ' + str(os_version) + '\n'
  # User running as
  whoami = py_whoami.whoami()
  data += '# User: '+str(whoami.response)+'\n'
  # uwsgi version
  uwsgi = py_uwsgi.uwsgi()
  m = re.search(r'\d+\.\d+\.(?=\d)', uwsgi.response)
  uwsgi_version = m.group(0)
  data += '# HELP py_uwsgi_version Uwsgi two digit version\n'
  data += '# TYPE py_uwsgi_version untyped\n'
  data += 'py_uwsgi_version '+str(uwsgi_version).rstrip('.')+'\n'
  # OS Version
  data += '# HELP py_os_distro OS version.\n'
  data += '# TYPE py_os_distro gauge\n'
  data += 'py_os_distro{os="'+ str(os_dist) +'"} ' + str(os_version) + '\n'
  # Major OS release
  data += '# HELP py_os_distro_major_version OS major version.\n'
  data += '# TYPE py_os_distro_major_version gauge\n'
  data += 'py_os_distro_major_version{os="'+ str(os_dist) +'"} ' + str(os_version_int) + '\n'
  # py_boot_time
  boot_time = py_boot_time.boot_time()
  data += '# HELP py_boot_time Host boot time, in unixtime.\n'
  data += '# TYPE py_boot_time gauge\n'
  data += 'py_boot_time ' + str(boot_time.response) + '\n'
  # py_context_switches
  context_switches = py_context_switches.context_switches()
  data += '# HELP py_context_switches Total number of context switches.\n'
  data += '# TYPE py_context_switches counter\n'
  data += 'py_context_switches ' + str(context_switches.response) + '\n'
  # py_cpu
  cpu_times = py_cpu.cpu_times()
  cpu_num = 0
  data += '# HELP py_cpu Seconds the cpus spent in each mode.\n'
  data += '# TYPE py_cpu counter\n'
  for item in cpu_times.response:
    data += 'py_cpu{cpu="cpu' + str(cpu_num) + '", mode="user"} ' + str(item[0]) + '\n'
    data += 'py_cpu{cpu="cpu' + str(cpu_num) + '", mode="nice"} ' + str(item[1]) + '\n'
    data += 'py_cpu{cpu="cpu' + str(cpu_num) + '", mode="system"} ' + str(item[2]) + '\n'
    data += 'py_cpu{cpu="cpu' + str(cpu_num) + '", mode="idle"} ' + str(item[3]) + '\n'
    cpu_num += 1
  # py_disk_bytes_read
  disk_bytes_read = py_disk_bytes_read.disk_bytes_read()
  data += '# HELP py_disk_bytes_read The total number of bytes read successfully.\n'
  data += '# TYPE py_disk_bytes_read counter\n'
  for item in disk_bytes_read.response:
    data += 'py_disk_bytes_read{device="' + str(item) + '"} ' + str(disk_bytes_read.response[item][2]) + '\n'
  # py_disk_bytes_written
  data += '# HELP py_disk_bytes_written The total number of bytes written successfully.\n'
  data += '# TYPE py_disk_bytes_written counter\n'
  for item in disk_bytes_read.response:
    data += 'py_disk_bytes_written{device="' + str(item) + '"} ' + str(disk_bytes_read.response[item][3]) + '\n'
  # py_disk_io_now
  disk_io = py_disk_io.disk_io()
  data += '# HELP py_disk_io_now The number of I/Os currently in progress.\n'
  data += '# TYPE py_disk_io_now gauge\n'
  for item in disk_io.response:
    field = item.split()
    if not bool(re.search(r'\d', field[2])):
      pass
    else: 
      data += 'py_disk_io_now{device="' + str(field[2]) + '"} ' + str(field[11]) + '\n'
  # py_disk_io_time_ms
  data += '# HELP py_disk_io_time_ms Total Milliseconds spent doing I/Os.\n'
  data += '# TYPE py_disk_io_time_ms counter\n'
  for item in disk_io.response:
    field = item.split()
    if not bool(re.search(r'\d', field[2])):
      pass
    else: 
      data += 'py_disk_io_time_ms{device="' + str(field[2]) + '"} ' + str(field[12]) + '\n'
  # py_disk_io_time_weighted
  data += '# HELP py_disk_io_time_weighted The weighted # of milliseconds spent doing I/Os. See <a href="https://www.kernel.org/doc/Documentation/iostats.txt">https://www.kernel.org/doc/Documentation/iostats.txt</a>\n'
  data += '# TYPE py_disk_io_time_weighted counter\n'
  for item in disk_io.response:
    field = item.split()
    if not bool(re.search(r'\d', field[2])):
      pass
    else: 
      data += 'py_disk_io_time_weighted{device="' + str(field[2]) + '"} ' + str(field[13]) + '\n'
  # py_disk_read_time_ms
  data += '# HELP py_disk_read_time_ms The total number of milliseconds spent by all reads.\n'
  data += '# TYPE py_disk_read_time_ms counter\n'
  for item in disk_bytes_read.response:
    data += 'py_disk_bytes_read_time_ms{device="' + str(item) + '"} ' + str(disk_bytes_read.response[item][4]) + '\n'
  # py_disk_reads_completed
  data += '# HELP py_disk_reads_completed The total number of reads completed successfully.\n'
  data += '# TYPE py_disk_reads_completed counter\n'
  for item in disk_io.response:
    field = item.split()
    if not bool(re.search(r'\d', field[2])):
      pass
    else: 
      data += 'py_disk_reads_completed{device="' + str(field[2]) + '"} ' + str(field[3]) + '\n'
  # py_disk_reads_merged
  data += '# HELP py_disk_reads_merged The total number of reads merged. See <a href="https://www.kernel.org/doc/Documentation/iostats.txt">https://www.kernel.org/doc/Documentation/iostats.txt</a>\n'
  data += '# TYPE py_disk_reads_merged counter\n'
  for item in disk_io.response:
    field = item.split()
    if not bool(re.search(r'\d', field[2])):
      pass
    else: 
      data += 'py_disk_reads_merged{device="' + str(field[2]) + '"} ' + str(field[4]) + '\n'
  # py_disk_sectors_read
  data += '# HELP py_disk_sectors_read The total number of sectors read successfully.\n'
  data += '# TYPE py_disk_sectors_read counter\n'
  for item in disk_io.response:
    field = item.split()
    if not bool(re.search(r'\d', field[2])):
      pass
    else: 
      data += 'py_disk_sectors_read{device="' + str(field[2]) + '"} ' + str(field[5]) + '\n'
  # py_disk_sectors_written
  data += '# HELP py_disk_sectors_written The total number of sectors written successfully.\n'
  data += '# TYPE py_disk_sectors_written counter\n'
  for item in disk_io.response:
    field = item.split()
    if not bool(re.search(r'\d', field[2])):
      pass
    else: 
      data += 'py_disk_sectors_written{device="' + str(field[2]) + '"} ' + str(field[9]) + '\n'
  # py_disk_write_time_ms 
  data += '# HELP py_disk_write_time_ms The total number of milliseconds spent by all reads.\n'
  data += '# TYPE py_disk_write_time_ms counter\n'
  for item in disk_bytes_read.response:
    data += 'py_disk_bytes_read_time_ms{device="' + str(item) + '"} ' + str(disk_bytes_read.response[item][5]) + '\n'
  # py_disk_writes_completed
  data += '# HELP py_disk_write_completed The total number of writes completed successfully.\n'
  data += '# TYPE py_disk_writes_completed counter\n'
  for item in disk_io.response:
    field = item.split()
    if not bool(re.search(r'\d', field[2])):
      pass
    else: 
      data += 'py_disk_writes_completed{device="' + str(field[2]) + '"} ' + str(field[7]) + '\n'
  # py_disk_writes_merged
  data += '# HELP py_disk_writes_merged The total number of writes merged. See https://www.kernel.org/doc/Documentation/iostats.txt\n'
  data += '# TYPE py_disk_writes_merged counter\n'
  for item in disk_io.response:
    field = item.split()
    if not bool(re.search(r'\d', field[2])):
      pass
    else: 
      data += 'py_disk_writes_merged{device="' + str(field[2]) + '"} ' + str(field[8]) + '\n'
  # py_entropy_available_bits
  entropy_available_bits = py_entropy_available_bits.entropy_available_bits()
  data += '# HELP py_entropy_available_bits Bits of available entropy.\n'
  data += '# TYPE py_entropy_available_bits gauge\n'
  data += 'py_entropy_available_bits ' + str(entropy_available_bits.response) + '\n'
  # py_exporter_build_info
  data += '# HELP py_exporter_build_info A metric with a constant "1" value labeled by version, and another other relevant info from which py_exporter was built.\n'
  data += '# TYPE py_exporter_build_info gauge\n'
  data += 'py_exporter_build_info{version="' + __version__ + '"} 1\n'
  # py_filefd_allocated
  fd = py_fd.fd()
  data += '# HELP py_filefd_allocated File descriptor statistics: allocated.\n'
  data += '# TYPE py_filefd_allocated gauge\n'
  data += 'py_filefd_allocated ' + fd.response[0] + '\n'
  # py_filefd_maximum
  data += '# HELP py_filefd_maximum File descriptor statistics: maximum.\n'
  data += '# TYPE py_filefd_maximum gauge\n'
  data += 'py_filefd_maximum ' + fd.response[2] + '\n'
  # py_filesystem_avail
  df = py_df.df()
  data += '# HELP py_filesystem_avail Filesystem space available to non-root users in bytes.\n'
  data += '# TYPE py_filesystem_avail gauge\n'
  for line in df.response:
    field = str(line).split()
    if (not field[0].startswith('Filesystem')):
      data += 'py_filesystem_avail{device="' + str(field[0]) + '",mountpoint="' + str(field[5]) + '"} ' + str(field[3]) + '\n'
  # py_filesystem_files
  dfi = py_df.dfi()
  data += '# HELP py_filesystem_files Filesystem total file nodes.\n'
  data += '# TYPE py_filesystem_files gauge\n'
  for line in dfi.response:
    field = str(line).split()
    if (not field[0].startswith('Filesystem')):
      data += 'py_filesystem_files{device="' + str(field[0]) + '",mountpoint="' + str(field[5]) + '"} ' + str(field[1]) + '\n'
  dfi_duration = dfi.duration
  # py_filesystem_files_free
  dfi = py_df.dfi() # if this isn't called a second time it doesn't work for some reason
  data += '# HELP py_files_free Filesystem total free file nodes.\n'
  data += '# TYPE py_files_free gauge\n'
  for line in dfi.response:
    field = str(line).split()
    if (not field[0].startswith('Filesystem')):
      data += 'py_files_free{device="' + str(field[0]) + '",mountpoint="' + str(field[5]) + '"} ' + str(field[3]) + '\n'
  dfi_duration += dfi.duration
  # py_filesystem_free
  fs = py_fs.fs()
  data += '# HELP py_filesystem_free Filesystem space available in bytes.\n'
  data += '# TYPE py_filesystem_free gauge\n'
  disk_usage_duration = 0
  for item in fs.response:
    field = str(item).split("'")
    if (not field[3].startswith('/proc')) and (not field[3].startswith('/dev/')) and (not field[3].startswith('/sys')):
      d = py_disk_usage.disk(field[3])
      disk = d.response
      disk_usage_duration += d.duration
      data += 'py_filesystem_free{device="' + str(field[1]) + '",fstype="' + str(field[5]) +'"} ' + str(disk[2]) + '\n'
  # py_filesystem_readonly
  data += '# HELP py_filesystem_readonly Filesystem read-only status.\n'
  data += '# TYPE py_filesystem_readonly gauge\n'
  for item in fs.response:
    field = str(item).split("'")
    if (not field[3].startswith('/proc')) and (not field[3].startswith('/dev/')) and (not field[3].startswith('/sys')):
      if str(field[7]) == 'r':
        data += 'py_filesystem_readyonly{device="' + str(field[1]) + '",fstype="' + str(field[5]) +'"} 1\n'
      else:
        data += 'py_filesystem_readyonly{device="' + str(field[1]) + '",fstype="' + str(field[5]) +'"} 0\n'
  # py_filesystem_size
  data += '# HELP py_filesystem_size Filesystem size in bytes.\n'
  data += '# TYPE py_filesystem_size gauge\n'
  for item in fs.response:
    field = str(item).split("'")
    if (not field[3].startswith('/proc')) and (not field[3].startswith('/dev/')) and (not field[3].startswith('/sys')):
      d = py_disk_usage.disk(field[3])
      disk = d.response
      disk_usage_duration += d.duration
      data += 'py_filesystem_size{device="' + str(field[1]) + '",fstype="' + str(field[5]) +'"} ' + str(disk[0]) + '\n'
  # py_forks
  forks = py_forks.forks()
  data += '# HELP py_forks Total number of forks.\n'
  data += '# TYPE py_forks counter\n'
  field = str(forks.response).split()
  data += 'py_forks ' + str(field[0]) + '\n'
  # Sensors
  sensors = py_sensors.sensors()
  sensor_list = re.findall(r'coretemp-.*?\n\n', sensors.response, re.DOTALL)
  data += '# HELP py_sensors_high Sensors high value\n'
  data += '# TYPE py_sensors_high gauge\n'
  for i in sensor_list:
    # data += '## '+ i +'\n'
    adapter = re.search(r'coretemp-.*',i)
    cores = re.findall(r'Core.*', i)
    for item in cores:
      field = item.split()
      core = field[0] + ' ' + field[1].rstrip(':')
      high = re.search(r'(?<=\+)\d*',field[5])
      data += 'py_sensors_high{adapter="'+str(adapter.group(0)) +'",core="'+str(core) +'"} '+ str(high.group(0)) +'\n'
  data += '# HELP py_sensors_crit Sensors crit value\n'
  data += '# TYPE py_sensors_crit gauge\n'
  for i in sensor_list:
    # data += '## '+ i +'\n'
    adapter = re.search(r'coretemp-.*',i)
    cores = re.findall(r'Core.*', i)
    for item in cores:
      field = item.split()
      core = field[0] + ' ' + field[1].rstrip(':')
      crit = re.search(r'(?<=\+)\d*',field[8])
      data += 'py_sensors_crit{adapter="'+str(adapter.group(0)) +'",core="'+str(core) +'"} '+ str(crit.group(0)) +'\n'
  # py_intr
  interrupts = py_interrupts.interrupts()
  data += '# HELP py_intr Total number of interrupts serviced.\n'
  data += '# TYPE py_intr counter\n'
  data += 'py_intr ' + str(interrupts.response) + '\n'
  # py_load1
  load = py_load.load()
  data += '# HELP py_load1 1m load average.\n'
  data += '# TYPE py_load1 gauge\n'
  data += 'py_load1 ' + str(load.response[0]) + '\n'
  # py_load10
  data += '# HELP py_load10 10m load average.\n'
  data += '# TYPE py_load10 gauge\n'
  data += 'py_load10 ' + str(load.response[2]) + '\n'
  # py_load5
  data += '# HELP py_load5 5m load average.\n'
  data += '# TYPE py_load5 gauge\n'
  data += 'py_load5 ' + str(load.response[1]) + '\n'
  # py_memory_Active
  meminfo = py_meminfo.meminfo()
  data += '# HELP py_memory_Active Memory information field Active.\n'
  data += '# TYPE py_memory_Active gauge\n'
  for item in meminfo.response:
    if item.startswith('Active:'): 
     active_mem = item.split()
     data += 'py_memory_Active ' + str(active_mem[1].strip()) + '\n'
  # py_memory_Active_anon
  data += '# HELP py_memory_Active_anon Memory information field Active_anon.\n'
  data += '# TYPE py_memory_Active_anon gauge\n'
  for item in meminfo.response:
    if item.startswith('Active(anon):'): 
     active_mem = item.split()
     data += 'py_memory_Active_anon ' + str(active_mem[1].strip()) + '\n'
  # py_memory_Active_file
  data += '# HELP py_memory_Active_file Memory information field Active_file.\n'
  data += '# TYPE py_memory_Active_file gauge\n'
  for item in meminfo.response:
    if item.startswith('Active(file):'): 
     active_mem = item.split()
     data += 'py_memory_Active_file ' + str(active_mem[1].strip()) + '\n'
  # py_memory_AnonHugePages
  data += '# HELP py_memory_AnonHugePages Memory information field AnonHugePages.\n'
  data += '# TYPE py_memory_AnonHugePages gauge\n'
  for item in meminfo.response:
    if item.startswith('AnonHugePages:'): 
     active_mem = item.split()
     data += 'py_memory_AnonHugePages ' + str(active_mem[1].strip()) + '\n'
  # py_memory_AnonPages
  data += '# HELP py_memory_AnonPages Memory information field AnonPages.\n'
  data += '# TYPE py_memory_AnonPages gauge\n'
  for item in meminfo.response:
    if item.startswith('AnonPages:'): 
     active_mem = item.split()
     data += 'py_memory_AnonPages ' + str(active_mem[1].strip()) + '\n'
  # py_memory_Bounce
  data += '# HELP py_memory_Bounce Memory information field Bounce.\n'
  data += '# TYPE py_memory_Bounce gauge\n'
  for item in meminfo.response:
    if item.startswith('Bounce:'): 
     active_mem = item.split()
     data += 'py_memory_Bounce ' + str(active_mem[1].strip()) + '\n'
  # py_memory_Buffers
  data += '# HELP py_memory_Buffers Memory information field Buffers.\n'
  data += '# TYPE py_memory_Buffers gauge\n'
  for item in meminfo.response:
    if item.startswith('Buffers:'): 
     active_mem = item.split()
     data += 'py_memory_Buffers ' + str(active_mem[1].strip()) + '\n'
  # py_memory_Cached  
  data += '# HELP py_memory_Cached Memory information field Cached.\n'
  data += '# TYPE py_memory_Cached gauge\n'
  for item in meminfo.response:
    if item.startswith('Cached:'): 
     active_mem = item.split()
     data += 'py_memory_Cached ' + str(active_mem[1].strip()) + '\n'
  # py_memory_CommitLimit
  data += '# HELP py_memory_CommitLimit Memory information field CommitLimit.\n'
  data += '# TYPE py_memory_CommitLimit gauge\n'
  for item in meminfo.response:
    if item.startswith('CommitLimit:'): 
     active_mem = item.split()
     data += 'py_memory_CommitLimit ' + str(active_mem[1].strip()) + '\n'
  # py_memory_Committed_AS
  data += '# HELP py_memory_Committed_AS Memory information field Committed_AS.\n'
  data += '# TYPE py_memory_Committed_AS gauge\n'
  for item in meminfo.response:
    if item.startswith('Committed_AS:'): 
     active_mem = item.split()
     data += 'py_memory_Committed_AS ' + str(active_mem[1].strip()) + '\n'
  # py_memory_DirectMap2M
  data += '# HELP py_memory_DirectMap2M Memory information field DirectMap2M.\n'
  data += '# TYPE py_memory_DirectMap2M gauge\n'
  for item in meminfo.response:
    if item.startswith('DirectMap2M:'): 
     active_mem = item.split()
     data += 'py_memory_DirectMap2M ' + str(active_mem[1].strip()) + '\n'
  # py_memory_DirectMap4k
  data += '# HELP py_memory_DirectMap4k Memory information field DirectMap4k.\n'
  data += '# TYPE py_memory_DirectMap4k gauge\n'
  for item in meminfo.response:
    if item.startswith('DirectMap4k:'): 
     active_mem = item.split()
     data += 'py_memory_DirectMap4k ' + str(active_mem[1].strip()) + '\n'
  # py_memory_Dirty
  data += '# HELP py_memory_Dirty Memory information field Dirty.\n'
  data += '# TYPE py_memory_Dirty gauge\n'
  for item in meminfo.response:
    if item.startswith('Dirty:'): 
     active_mem = item.split()
     data += 'py_memory_Dirty ' + str(active_mem[1].strip()) + '\n'
  # py_memory_HardwareCorrupted
  data += '# HELP py_memory_HardwareCorrupted Memory information field HardwareCorrupted.\n'
  data += '# TYPE py_memory_HardwareCorrupted gauge\n'
  for item in meminfo.response:
    if item.startswith('HardwareCorrupted:'): 
     active_mem = item.split()
     data += 'py_memory_HardwareCorrupted ' + str(active_mem[1].strip()) + '\n'
  # py_memory_HugePages_Free
  data += '# HELP py_memory_HugePages_Free Memory information field HugePages_Free.\n'
  data += '# TYPE py_memory_HugePages_Free gauge\n'
  for item in meminfo.response:
    if item.startswith('HugePages_Free:'): 
     active_mem = item.split()
     data += 'py_memory_HugePages_Free ' + str(active_mem[1].strip()) + '\n'
  # py_memory_HugePages_Rsvd
  data += '# HELP py_memory_HugePages_Rsvd Memory information field HugePages_Rsvd.\n'
  data += '# TYPE py_memory_HugePages_Rsvd gauge\n'
  for item in meminfo.response:
    if item.startswith('HugePages_Rsvd:'): 
     active_mem = item.split()
     data += 'py_memory_HugePages_Rsvd ' + str(active_mem[1].strip()) + '\n'
  # py_memory_HugePages_Surp
  data += '# HELP py_memory_HugePages_Surp Memory information field HugePages_Surp.\n'
  data += '# TYPE py_memory_HugePages_Surp gauge\n'
  for item in meminfo.response:
    if item.startswith('HugePages_Surp:'): 
     active_mem = item.split()
     data += 'py_memory_HugePages_Surp ' + str(active_mem[1].strip()) + '\n'
  # py_memory_HugePages_Total
  data += '# HELP py_memory_HugePages_Total Memory information field HugePages_Total.\n'
  data += '# TYPE py_memory_HugePages_Total gauge\n'
  for item in meminfo.response:
    if item.startswith('HugePages_Total:'): 
     active_mem = item.split()
     data += 'py_memory_HugePages_Total ' + str(active_mem[1].strip()) + '\n'
  # py_memory_Hugepagesize
  data += '# HELP py_memory_Hugepagesize Memory information field Hugepagesize.\n'
  data += '# TYPE py_memory_Hugepagesize gauge\n'
  for item in meminfo.response:
    if item.startswith('Hugepagesize:'): 
     active_mem = item.split()
     data += 'py_memory_Hugepagesize ' + str(active_mem[1].strip()) + '\n'
  # py_memory_Inactive
  data += '# HELP py_memory_Inactive Memory information field Inactive.\n'
  data += '# TYPE py_memory_Inactive gauge\n'
  for item in meminfo.response:
    if item.startswith('Inactive:'): 
     active_mem = item.split()
     data += 'py_memory_Inactive ' + str(active_mem[1].strip()) + '\n'
  # py_memory_Inactive_anon
  data += '# HELP py_memory_Inactive_anon Memory information field Inactive_anon.\n'
  data += '# TYPE py_memory_Inactive_anon gauge\n'
  for item in meminfo.response:
    if item.startswith('Inactive(anon):'): 
     active_mem = item.split()
     data += 'py_memory_Inactive_anon ' + str(active_mem[1].strip()) + '\n'
  # py_memory_Inactive_file
  data += '# HELP py_memory_Inactive_file Memory information field Inactive_file.\n'
  data += '# TYPE py_memory_Inactive_file gauge\n'
  for item in meminfo.response:
    if item.startswith('Inactive(file):'): 
     active_mem = item.split()
     data += 'py_memory_Inactive_file ' + str(active_mem[1].strip()) + '\n'
  # py_memory_KernelStack
  data += '# HELP py_memory_KernelStack Memory information field KernelStack.\n'
  data += '# TYPE py_memory_KernelStack gauge\n'
  for item in meminfo.response:
    if item.startswith('KernelStack:'): 
     active_mem = item.split()
     data += 'py_memory_KernelStack ' + str(active_mem[1].strip()) + '\n'
  # py_memory_Mapped
  data += '# HELP py_memory_Mapped Memory information field Mapped.\n'
  data += '# TYPE py_memory_Mapped gauge\n'
  for item in meminfo.response:
    if item.startswith('Mapped:'): 
     active_mem = item.split()
     data += 'py_memory_Mapped ' + str(active_mem[1].strip()) + '\n'
  # py_memory_MemFree
  data += '# HELP py_memory_MemFree Memory information field MemFree.\n'
  data += '# TYPE py_memory_MemFree gauge\n'
  for item in meminfo.response:
    if item.startswith('MemFree:'): 
     active_mem = item.split()
     data += 'py_memory_MemFree ' + str(active_mem[1].strip()) + '\n'
  # py_memory_MemTotal
  data += '# HELP py_memory_MemTotal Memory information field MemTotal.\n'
  data += '# TYPE py_memory_MemTotal gauge\n'
  for item in meminfo.response:
    if item.startswith('MemTotal:'): 
     active_mem = item.split()
     data += 'py_memory_MemTotal ' + str(active_mem[1].strip()) + '\n'
  # py_memory_Mlocked
  data += '# HELP py_memory_Mlocked Memory information field Mlocked.\n'
  data += '# TYPE py_memory_Mlocked gauge\n'
  for item in meminfo.response:
    if item.startswith('Mlocked:'): 
     active_mem = item.split()
     data += 'py_memory_Mlocked ' + str(active_mem[1].strip()) + '\n'
  # py_memory_NFS_Unstable
  data += '# HELP py_memory_NFS_Unstable Memory information field NFS_Unstable.\n'
  data += '# TYPE py_memory_NFS_Unstable gauge\n'
  for item in meminfo.response:
    if item.startswith('NFS_Unstable:'): 
     active_mem = item.split()
     data += 'py_memory_NFS_Unstable ' + str(active_mem[1].strip()) + '\n'
  # py_memory_PageTables
  data += '# HELP py_memory_PageTables Memory information field PageTables.\n'
  data += '# TYPE py_memory_PageTables gauge\n'
  for item in meminfo.response:
    if item.startswith('PageTables:'): 
     active_mem = item.split()
     data += 'py_memory_PageTables ' + str(active_mem[1].strip()) + '\n'
  # py_memory_SReclaimable
  data += '# HELP py_memory_SReclaimable Memory information field SReclaimable.\n'
  data += '# TYPE py_memory_SReclaimable gauge\n'
  for item in meminfo.response:
    if item.startswith('SReclaimable:'): 
     active_mem = item.split()
     data += 'py_memory_SReclaimable ' + str(active_mem[1].strip()) + '\n'
  # py_memory_SUnreclaim
  data += '# HELP py_memory_SUnreclaim Memory information field SUnreclaim.\n'
  data += '# TYPE py_memory_SUnreclaim gauge\n'
  for item in meminfo.response:
    if item.startswith('SUnreclaim:'): 
     active_mem = item.split()
     data += 'py_memory_SUnreclaim ' + str(active_mem[1].strip()) + '\n'
  # py_memory_Shmem
  data += '# HELP py_memory_Shmem Memory information field Shmem.\n'
  data += '# TYPE py_memory_Shmem gauge\n'
  for item in meminfo.response:
    if item.startswith('Shmem:'): 
     active_mem = item.split()
     data += 'py_memory_Shmem ' + str(active_mem[1].strip()) + '\n'
  # py_memory_Slab
  data += '# HELP py_memory_Slab Memory information field Slab.\n'
  data += '# TYPE py_memory_Slab gauge\n'
  for item in meminfo.response:
    if item.startswith('Slab:'): 
     active_mem = item.split()
     data += 'py_memory_Slab ' + str(active_mem[1].strip()) + '\n'
  # py_memory_SwapCached
  data += '# HELP py_memory_SwapCached Memory information field SwapCached.\n'
  data += '# TYPE py_memory_SwapCached gauge\n'
  for item in meminfo.response:
    if item.startswith('SwapCached:'): 
     active_mem = item.split()
     data += 'py_memory_SwapCached ' + str(active_mem[1].strip()) + '\n'
  # py_memory_SwapFree
  data += '# HELP py_memory_SwapFreeMemory information field SwapFree\n'
  data += '# TYPE py_memory_SwapFree gauge\n'
  for item in meminfo.response:
    if item.startswith('SwapFree:'): 
     active_mem = item.split()
     data += 'py_memory_SwapFree ' + str(active_mem[1].strip()) + '\n'
  # py_memory_SwapTotal
  data += '# HELP py_memory_SwapTotal information field SwapTotal\n'
  data += '# TYPE py_memory_SwapTotal gauge\n'
  for item in meminfo.response:
    if item.startswith('SwapTotal:'): 
     active_mem = item.split()
     data += 'py_memory_SwapTotal ' + str(active_mem[1].strip()) + '\n'
  # py_memory_Unevictable
  data += '# HELP py_memory_Unevictable information field Unevictable\n'
  data += '# TYPE py_memory_Unevictable gauge\n'
  for item in meminfo.response:
    if item.startswith('Unevictable:'): 
     active_mem = item.split()
     data += 'py_memory_Unevictable ' + str(active_mem[1].strip()) + '\n'
  # py_memory_VmallocChunk
  data += '# HELP py_memory_VmallocChunk information field VmallocChunk\n'
  data += '# TYPE py_memory_VmallocChunk gauge\n'
  for item in meminfo.response:
    if item.startswith('VmallocChunk:'): 
     active_mem = item.split()
     data += 'py_memory_VmallocChunk ' + str(active_mem[1].strip()) + '\n'
  # py_memory_VmallocTotal
  data += '# HELP py_memory_VmallocTotal information field VmallocTotal\n'
  data += '# TYPE py_memory_VmallocTotal gauge\n'
  for item in meminfo.response:
    if item.startswith('VmallocTotal:'): 
     active_mem = item.split()
     data += 'py_memory_VmallocTotal ' + str(active_mem[1].strip()) + '\n'
  # py_memory_VmallocUsed
  data += '# HELP py_memory_VmallocUsed information field VmallocUsed\n'
  data += '# TYPE py_memory_VmallocUsed gauge\n'
  for item in meminfo.response:
    if item.startswith('VmallocUsed:'): 
     active_mem = item.split()
     data += 'py_memory_VmallocUsed ' + str(active_mem[1].strip()) + '\n'
  # py_memory_Writeback
  data += '# HELP py_memory_Writeback information field Writeback\n'
  data += '# TYPE py_memory_Writeback gauge\n'
  for item in meminfo.response:
    if item.startswith('Writeback:'): 
     active_mem = item.split()
     data += 'py_memory_Writeback ' + str(active_mem[1].strip()) + '\n'
  # py_memory_WritebackTmp
  data += '# HELP py_memory_WritebackTmp information field WritebackTmp\n'
  data += '# TYPE py_memory_WritebackTmp gauge\n'
  for item in meminfo.response:
    if item.startswith('WritebackTmp:'): 
     active_mem = item.split()
     data += 'py_memory_WritebackTmp ' + str(active_mem[1].strip()) + '\n'
  # Parse Tibco data
  if os.path.isfile('/usr/local/thirdparty/tibco/CURRENT/ems/8.2/bin/tibemsadmin'):
    tibco = py_tibco.tibco()
    tib = dict(item.split(":::") for item in tibco.response.split("###"))
    # py_tibco_queue_recievers
    data += '# HELP py_tibco_queue_recievers Tibco queue recievers\n'
    data += '# TYPE py_tibco_queue_recievers gauge\n'    
    for i in str(tib['Queues']).split('\n'):
      line = i.lstrip()
      if line.startswith('show'):
        pass
      elif line.startswith('Queue'):
        pass
      elif line.startswith('>'):
        field = line.split()
        data += 'py_tibco_queue_receivers{queue="' + str(field[0]) + '"} ' + str(field[3]) + '\n'
      elif line.startswith('$'):
        field = line.split()
        name = field[0].split('.')
        data += 'py_tibco_queue_receivers{queue="' + str(name[1]) + '"} ' + str(field[3]) + '\n'
      elif line.startswith('*'):
        field = line.split()
        name = field[1].split('.')
        data += 'py_tibco_queue_receivers{queue="' + str(name[1]) + '"} ' + str(field[4]) + '\n'
      elif line.startswith('/'):
        field = line.split()
        name = field[0].split('/')
        data += 'py_tibco_queue_receivers{queue="' + str(name[2]) + '"} ' + str(field[3]) + '\n'
      else:
        pass
    # py_tibco_queue_messages
    data += '# HELP py_tibco_queue_messages Tibco queue messages\n'
    data += '# TYPE py_tibco_queue_messages gauge\n'    
    for i in str(tib['Queues']).split('\n'):
      line = i.lstrip()
      if line.startswith('show'):
        pass
      elif line.startswith('Queue'):
        pass
      elif line.startswith('>'):
        field = line.split()
        data += 'py_tibco_queue_messages{queue="' + str(field[0]) + '"} ' + str(field[4]) + '\n'
      elif line.startswith('$'):
        field = line.split()
        name = field[0].split('.')
        data += 'py_tibco_queue_messages{queue="' + str(name[1]) + '"} ' + str(field[4]) + '\n'
      elif line.startswith('*'):
        field = line.split()
        name = field[1].split('.')
        data += 'py_tibco_queue_messages{queue="' + str(name[1]) + '"} ' + str(field[5]) + '\n'
      elif line.startswith('/'):
        field = line.split()
        name = field[0].split('/')
        data += 'py_tibco_queue_messages{queue="' + str(name[2]) + '"} ' + str(field[4]) + '\n'
      else:
        pass
    # py_tibco_queue_message_size
    data += '# HELP py_tibco_queue_message_size Tibco queue message size in Kilobytes\n'
    data += '# TYPE py_tibco_queue_message_size gauge\n'    
    for i in str(tib['Queues']).split('\n'):
      line = i.lstrip()
      if line.startswith('show'):
        pass
      elif line.startswith('Queue'):
        pass
      elif line.startswith('>'):
        field = line.split()
        if str(field[6]) == 'MB': 
          size = int(float(field[5]) * 1000)
        else:
          size = int(float(field[5]))
        data += 'py_tibco_queue_message_size{queue="' + str(field[0]) + '"} ' + str(size) + '\n'
      elif line.startswith('$'):
        field = line.split()
        if str(field[6]) == 'MB': 
          size = int(float(field[5]) * 1000)
        else:
          size = int(float(field[5]))
        name = field[0].split('.')
        data += 'py_tibco_queue_message_size{queue="' + str(name[1]) + '"} ' + str(size) + '\n'
      elif line.startswith('*'):
        field = line.split()
        if str(field[7]) == 'MB': 
          size = int(float(field[6]) * 1000)
        else:
          size = int(float(field[5]))
        name = field[1].split('.')
        data += 'py_tibco_queue_message_size{queue="' + str(name[1]) + '"} ' + str(size) + '\n'
      elif line.startswith('/'):
        field = line.split()
        if str(field[6]) == 'MB': 
          size = int(float(field[5]) * 1000)
        else:
          size = int(float(field[5]))
        name = field[0].split('/')
        data += 'py_tibco_queue_message_size{queue="' + str(name[2]) + '"} ' + str(size) + '\n'
      else:
        pass
    # py_tibco_bridge_queue_targets
    data += '# HELP py_tibco_bridge_queue_targets Tibco bridge queue targets\n'
    data += '# TYPE py_tibco_bridge_queue_targets gauge\n'       
    for i in str(tib['Bridges']).split('\n'):
      line = i.lstrip()
      if line.startswith('Q'):
        field = line.split()
        name = field[1].split('/')
        data += 'py_tibco_bridge_queue_targets{source="' +  str(name[2]) + '"} ' + str(field[2]) + '\n'
    # py_tibco_consumers_messages_sent
    data += '# HELP py_tibco_consumers_messages_sent Tibco consumers messages sent\n'
    data += '# TYPE py_tibco_consumers_messages_sent gauge\n' 
    for i in str(tib['Consumers']).split('\n'):
      line = i.lstrip()
      field = line.split()
      try:
        if field[0].isdigit():
          name = field[4].split('/')
          data += 'py_tibco_consumers_messages_sent{queue="' + str(name[2]) + '"} ' + str(field[6]) + '\n'
      except IndexError:
        pass
    # py_tibco_consumers_messages_size
    data += '# HELP py_tibco_consumers_messages_size Tibco consumers message size\n'
    data += '# TYPE py_tibco_consumers_messages_size gauge\n' 
    for i in str(tib['Consumers']).split('\n'):
      line = i.lstrip()
      field = line.split()
      try:
        if field[0].isdigit():
          name = field[4].split('/')
          data += 'py_tibco_consumers_messages_size{queue="' + str(name[2]) + '"} ' + str(field[7]) + '\n'
      except IndexError:
        pass
    # py_tibco_connections
    host = defaultdict(int)
    for i in str(tib['Connections']).split('\n'):
      line = i.lstrip()
      if line.startswith('J'):
        field = line.split()
        if '.' in field[4]:
          namefield = field[4].split('.')
          name = str(namefield[0])
        else: 
          name = str(field[4])
        #data += str(name)  + ' = ' + str(host[name]) + '\n'
        host[name] += int(field[6])
        #data += str(name) + ' -> ' + str(host[name]) + '\n'
      elif line.startswith('C'):
        field = line.split()
        if '.' in field[4]:
          namefield = field[4].split('.')
          name = str(namefield[0])
        else: 
          name = str(field[4])
        #data += str(name)  + ' -> ' + str(host[name]) + '\n'
        host[name] += int(field[6])
        #data += str(field[4]) + ': ' + str(name) + ' -> ' + str(host[name]) + ' -->' + str(field[6]) + '\n'
      else: 
        pass
    data += '# HELP py_tibco_connections Tibco connections per host\n'
    data += '# TYPE py_tibco_connections gauge\n'
    for key, value in host.iteritems():
      data += 'py_tibco_connections{host="' + str(key) + '"} ' + str(value) + '\n'
  # parse netstat data
  netstat = py_netstat.netstat()
  netstats = ''
  ns = {}
  for item in str(netstat.response).splitlines(True):
    if str(item).startswith('UdpLite'):
      pass
    elif (not str(item).startswith(' ')):
      if netstats != '':
        netstats += '...' + str(item).replace(':\n',':::')
      else:
        netstats += str(item).replace(':\n',':::')
      # pass
    else:
      word = str(item).lstrip()
      netstats += str(word).replace('\n',',')
  ns = dict(item.split(":::") for item in netstats.split("..."))
  
  # netstat ip data
  ip = {}
  ip_list = str(ns['Ip']).split(',')
  for i in ip_list:

    m = re.search(r'\d+(?=\Wtotal packets received)', i)
    if m:
      ip['total_packets_received'] = m.group(0)

    m = re.search(r'\d+(?=\Wforwarded)', i)
    if m:
      ip['forwarded'] = m.group(0)

    m = re.search(r'\d+(?=\Wincoming packets discarded)', i)
    if m:
      ip['packets_discarded'] = m.group(0)

    m = re.search(r'\d+(?=\Wincoming packets delivered)', i)
    if m:
      ip['packets_delivered'] = m.group(0)

    m = re.search(r'\d+(?=\Wrequests sent out)', i)
    if m:
      ip['requests_sent'] = m.group(0)

    m = re.search(r'\d+(?=\Wdropped because of missing route)', i)
    if m:
      ip['missing_route'] = m.group(0)  

    m = re.search(r'\d+(?=\Wfragments received ok)', i)
    if m:
      ip['fragments_received'] = m.group(0)

    m = re.search(r'\d+(?=\Wfragments created)', i)
    if m:
      ip['fragments_created'] = m.group(0)
    
    m = re.search(r'\d+(?=\Wwith invalid address)', i)
    if m:
      ip['invalid_addresses'] = m.group(0)
    
    m = re.search(r'\d+(?=\Wwith unknown protocol)', i)
    if m:
      ip['unknown_protocol'] = m.group(0)

  if ip.get('total_packets_received'):
    data += '# HELP py_netstat_ip_total_packets_received IP statistic total packets received\n'
    data += '# TYPE py_netstat_ip_total_packets_received untyped\n'
    data += 'py_netstat_ip_total_packets_received '+ str(ip['total_packets_received']) + '\n'

  if ip.get('forwarded'):
    data += '# HELP py_netstat_Ip_Forwarding Protocol Ip statistic Forwarding\n'
    data += '# TYPE py_netstat_Ip_Forwarding untyped\n'
    data += 'py_netstat_Ip_Forwarding '+ str(ip['forwarded']) + '\n'    

  if ip.get('packets_discarded'):
    data += '# HELP py_netstat_Ip_packets_discarded Protocol Ip statistic incoming packets discarded\n'
    data += '# TYPE py_netstat_Ip_packets_discarded untyped\n'
    data += 'py_netstat_Ip_packets_discarded '+ str(ip['packets_discarded']) + '\n'    

  if ip.get('packets_delivered'):
    data += '# HELP py_netstat_Ip_packets_delivered Protocol Ip statistic incoming packets delivered\n'
    data += '# TYPE py_netstat_Ip_packets_delivered untyped\n'
    data += 'py_netstat_Ip_packets_delivered '+ str(ip['packets_delivered']) + '\n'

  if ip.get('requests_sent'):
    data += '# HELP py_netstat_Ip_requests_sent Protocol Ip statistic requests sent out\n'
    data += '# TYPE py_netstat_Ip_requests_sent untyped\n'
    data += 'py_netstat_Ip_requests_sent '+ str(ip['requests_sent']) + '\n'

  if ip.get('missing_route'):
    data += '# HELP py_netstat_Ip_missing_route Protocol Ip statistic dropped because of missing route\n'
    data += '# TYPE py_netstat_Ip_missing_route untyped\n'
    data += 'py_netstat_Ip_missing_route '+ str(ip['missing_route']) + '\n'

  if ip.get('fragments_received'):
    data += '# HELP py_netstat_Ip_fragments_received Protocol Ip statistic fragments received ok\n'
    data += '# TYPE py_netstat_Ip_fragments_received untyped\n'
    data += 'py_netstat_Ip_fragments_received '+ str(ip['fragments_received']) + '\n'

  if ip.get('fragments_created'):
    data += '# HELP py_netstat_Ip_fragments_created Protocol Ip statistic fragments created\n'
    data += '# TYPE py_netstat_Ip_fragments_created untyped\n'
    data += 'py_netstat_Ip_fragments_created '+ str(ip['fragments_created']) + '\n'

  if ip.get('invalid_addresses'):
    data += '# HELP py_netstat_Ip_invalid_addresses Protocol Ip statistic invalid address\n'
    data += '# TYPE py_netstat_Ip_invalid_addresses untyped\n'
    data += 'py_netstat_Ip_invalid_addresses '+ str(ip['invalid_addresses']) + '\n'

  if ip.get('unknown_protocol'):
    data += '# HELP py_netstat_Ip_unknown_protocol Protocol Ip statistic unknown protocol\n'
    data += '# TYPE py_netstat_Ip_unknown_protocol untyped\n'
    data += 'py_netstat_Ip_unknown_protocol '+ str(ip['unknown_protocol']) + '\n'

  udp = {}
  udp_list = str(ns['Udp']).split(',')
  for i in udp_list:

    m = re.search(r'\d+(?=\Wpackets received)', i)
    if m:
      udp['packets_received'] = m.group(0)

    m = re.search(r'\d+(?=\Wpackets to unknown port received)', i)
    if m:
      udp['packets_unknown'] = m.group(0)

    m = re.search(r'\d+(?=\Wpacket receive errors)', i)
    if m:
      udp['packet_errors'] = m.group(0)

    m = re.search(r'\d+(?=\Wpackets sent)', i)
    if m:
      udp['packets_sent'] = m.group(0)

    m = re.search(r'\d+(?=\Wreceive buffer errors)', i)
    if m:
      udp['receive_buffer_errors'] = m.group(0)

    m = re.search(r'\d+(?=\Wsend buffer errors)', i)
    if m:
      udp['send_buffer_errors'] = m.group(0)

  if udp.get('packets_received'):
    data += '# HELP py_netstat_Udp_packets_received Protocol UDP statistic pakets received\n'
    data += '# TYPE py_netstat_Udp_packets_received untyped\n'
    data += 'py_netstat_Udp_packets_received '+ str(udp['packets_received']) + '\n'

  if udp.get('packets_unknown'):
    data += '# HELP py_netstat_Udp_packets_unknown Protocol UDP statistic pakets to unknown port received\n'
    data += '# TYPE py_netstat_Udp_packets_unknown untyped\n'
    data += 'py_netstat_Udp_packets_unknown '+ str(udp['packets_unknown']) + '\n'

  if udp.get('packet_errors'):
    data += '# HELP py_netstat_Udp_packet_errors Protocol UDP packet receive errors\n'
    data += '# TYPE py_netstat_Udp_packet_errors untyped\n'
    data += 'py_netstat_Udp_packet_errors '+ str(udp['packet_errors']) + '\n'

  if udp.get('packets_sent'):
    data += '# HELP py_netstat_Udp_packets_sent Protocol UDP packets sent\n'
    data += '# TYPE py_netstat_Udp_packets_sent untyped\n'
    data += 'py_netstat_Udp_packets_sent '+ str(udp['packets_sent']) + '\n'

  if udp.get('receive_buffer_errors'):
    data += '# HELP py_netstat_Udp_receive_buffer_errors Protocol UDP receive buffer errors\n'
    data += '# TYPE py_netstat_Udp_receive_buffer_errors untyped\n'
    data += 'py_netstat_Udp_receive_buffer_errors '+ str(udp['receive_buffer_errors']) + '\n'

  if udp.get('send_buffer_errors'):
    data += '# HELP py_netstat_Udp_send_buffer_errors Protocol UDP send buffer errors\n'
    data += '# TYPE py_netstat_Udp_send_buffer_errors untyped\n'
    data += 'py_netstat_Udp_send_buffer_errors '+ str(udp['send_buffer_errors']) + '\n'

  tcpext = {}
  tcpext_list = str(ns['TcpExt']).split(',')
  for i in tcpext_list:

    m = re.search(r'\d+(?=\Winvalid SYN cookies received)', i)
    if m:
      tcpext['invalid_syn_cookies'] = m.group(0)

    m = re.search(r'\d+(?=\Wresets received)', i)
    if m:
      tcpext['resets_received'] = m.group(0)

    m = re.search(r'\d+(?=\Wpackets pruned)', i)
    if m:
      tcpext['packets_pruned'] = m.group(0)

    m = re.search(r'\d+(?=\WICMP packets dropped)', i)
    if m:
      tcpext['icmp_dropped'] = m.group(0)

    m = re.search(r'\d+(?=\WTCP sockets finished time wait)', i)
    if m:
      tcpext['sockets_finished_time_wait'] = m.group(0)

    m = re.search(r'\d+(?=\Wdelayed acks sent)', i)
    if m:
      tcpext['delayed_acks'] = m.group(0)

    m = re.search(r'\d+(?=\Wdelayed acks further delayed because of locked socket)', i)
    if m:
      tcpext['delayed_acks_locked'] = m.group(0)

    m = re.search(r'(?<=Quick ack mode was activated\W)\d+', i)
    if m:
      tcpext['quick_acks'] = m.group(0)

    m = re.search(r'\d+(?=\Wpackets directly queued to recvmsg prequeue)', i)
    if m:
      tcpext['recvmsg_prequeue'] = m.group(0)

    m = re.search(r'\d+(?=\WSYNs to LISTEN sockets dropped)', i)
    if m:
      tcpext['syns_to_listen_dropped'] = m.group(0)

    m = re.search(r'\d+(?=\Wbytes directly in process context from backlog)', i)
    if m:
      tcpext['backlog_bytes'] = m.group(0)

    m = re.search(r'\d+(?=\Wpackets directly received from backlog)', i)
    if m:
      tcpext['backlog_packets'] = m.group(0)

    m = re.search(r'\d+(?=\Wpackets directly received from prequeue)', i)
    if m:
      tcpext['prequeue_packets'] = m.group(0)

    m = re.search(r'\d+(?=\Wbytes directly received in process context from prequeue)', i)
    if m:
      tcpext['prequeue_bytes'] = m.group(0)

    m = re.search(r'\d+(?=\Wpacket(s|) header(s|) predicted$)', i)
    if m:
      tcpext['header_predicted'] = m.group(0)

    m = re.search(r'\d+(?=\Wpackets header predicted and directly queued to user)', i)
    if m:
      tcpext['header_queued'] = m.group(0)

    m = re.search(r'\d+(?=\Wacknowledgments not containing data)', i)
    if m:
      tcpext['ack_no_data'] = m.group(0)

    m = re.search(r'\d+(?=\Wpredicted acknowledgments)', i)
    if m:
      tcpext['predicted_acks'] = m.group(0)

    m = re.search(r'\d+(?=\Wtimes recovered from packet loss)', i)
    if m:
      tcpext['packet_loss_recovered'] = m.group(0)

    m = re.search(r'(?<=Detected reordering\W)\d+(?=\Wtimes using FACK)', i)
    if m:
      tcpext['reorder_fack'] = m.group(0)

    m = re.search(r'(?<=Detected reordering\W)\d+(?=\Wtimes using SACK)', i)
    if m:
      tcpext['reorder_sack'] = m.group(0)

    m = re.search(r'(?<=Detected reordering\W)\d+(?=\Wtimes using time stamp)', i)
    if m:
      tcpext['reorder_timestamp'] = m.group(0)

    m = re.search(r'\d+(?=\Wcongestion windows fully recovered$)', i)
    if m:
      tcpext['congestion_recovery'] = m.group(0)

    m = re.search(r'\d+(?=\Wcongestion windows fully recovered without slow start$)', i)
    if m:
      tcpext['congestion_recovery_no_slow'] = m.group(0)

    m = re.search(r'\d+(?=\Wcongestion windows recovered without slow start by DSACK)', i)
    if m:
      tcpext['congestion_recovery_no_slow_dsack'] = m.group(0)

    m = re.search(r'\d+(?=\Wcongestion windows recovered without slow start after partial ack)', i)
    if m:
      tcpext['congestion_recovery_no_slow_partial_ack'] = m.group(0)

    m = re.search(r'\d+(?=\Wcongestion windows partially recovered using Hoe heuristic)', i)
    if m:
      tcpext['congestion_recovery_partial'] = m.group(0)

    m = re.search(r'\d+(?=\Wcongestion windows recovered after partial ack)', i)
    if m:
      tcpext['congestion_recovery_partial_ack'] = m.group(0)

    m = re.search(r'\d+(?=\WTCP data loss events)', i)
    if m:
      tcpext['tcp_data_loss'] = m.group(0)

    m = re.search(r'(?<=TCPDSACKUndo:\W)\d+', i)
    if m:
      tcpext['tcp_dsack_undo'] = m.group(0)

    m = re.search(r'(?<=TCPLostRetransmit:\W)\d+', i)
    if m:
      tcpext['tcp_lost_retransmit'] = m.group(0)

    m = re.search(r'\d+(?=\Wtimeouts after SACK recovery)', i)
    if m:
      tcpext['sack_recovery_timeouts'] = m.group(0)

    m = re.search(r'\d+(?=\Wtimeouts in loss state)', i)
    if m:
      tcpext['loss_state_timeouts'] = m.group(0)

    m = re.search(r'\d+(?=\Wfast retransmits)', i)
    if m:
      tcpext['fast_retransmits'] = m.group(0)

    m = re.search(r'\d+(?=\Wforward retransmits)', i)
    if m:
      tcpext['forward_retransmits'] = m.group(0)

    m = re.search(r'\d+(?=\Wretransmits in slow start)', i)
    if m:
      tcpext['transmits_slow_start'] = m.group(0)

    m = re.search(r'\d+(?=\Wother TCP timeouts)', i)
    if m:
      tcpext['other_timeouts'] = m.group(0)

    m = re.search(r'\d+(?=\W(sack|SACK) retransmits failed)', i)
    if m:
      tcpext['sack_retransmits_failed'] = m.group(0)

    m = re.search(r'(?<=TCPLossProbes:\W)\d+', i)
    if m:
      tcpext['tcp_loss_probes'] = m.group(0)

    m = re.search(r'(?<=TCPLossProbeRecovery:\W)\d+', i)
    if m:
      tcpext['tcp_loss_probe_recovery'] = m.group(0)

    m = re.search(r'\d+(?=\Wtimes receiver scheduled too late for direct processing)', i)
    if m:
      tcpext['receiver_scheduled_late'] = m.group(0)

    m = re.search(r'\d+(?=\WDSACKs sent for old packets)', i)
    if m:
      tcpext['dsacks_old_packets'] = m.group(0)

    m = re.search(r'\d+(?=\Wtimes receiver scheduled too late for direct processing)', i)
    if m:
      tcpext['receiver_scheduled_late'] = m.group(0)

    m = re.search(r'\d+(?=\WDSACKs sent for out of order packets)', i)
    if m:
      tcpext['dsacks_sent_out_of_order_packets'] = m.group(0)

    m = re.search(r'\d+(?=\WDSACKs for out of order packets received)', i)
    if m:
      tcpext['dsacks_received_out_of_order_packets'] = m.group(0)

    m = re.search(r'\d+(?=\WDSACKs received)', i)
    if m:
      tcpext['dsacks_received'] = m.group(0)

    m = re.search(r'\d+(?=\Wconnections reset due to unexpected data)', i)
    if m:
      tcpext['connections_reset_unexpected_data'] = m.group(0)

    m = re.search(r'\d+(?=\Wconnections reset due to early user close)', i)
    if m:
      tcpext['connections_reset_early_close'] = m.group(0)

    m = re.search(r'\d+(?=\Wconnections aborted due to timeout)', i)
    if m:
      tcpext['connections_aborted_timeout'] = m.group(0)

    m = re.search(r'(?<=TCPSACKDiscard:\W)\d+', i)
    if m:
      tcpext['tcp_dack_discard'] = m.group(0)

    m = re.search(r'(?<=TCPDSACKIgnoredOld:\W)\d+', i)
    if m:
      tcpext['tcp_dack_ignore_old'] = m.group(0)

    m = re.search(r'(?<=TCPDSACKIgnoredNoUndo:\W)\d+', i)
    if m:
      tcpext['tcp_dack_ignore_no_undo'] = m.group(0)

    m = re.search(r'(?<=TCPSpuriousRTOs:\W)\d+', i)
    if m:
      tcpext['tcp_spurious_rtos'] = m.group(0)

    m = re.search(r'(?<=TCPSackShifted:\W)\d+', i)
    if m:
      tcpext['tcp_sack_shifted'] = m.group(0)

    m = re.search(r'(?<=TCPSackMerged:\W)\d+', i)
    if m:
      tcpext['tcp_sack_merged'] = m.group(0)

    m = re.search(r'(?<=TCPSackShiftFallback:\W)\d+', i)
    if m:
      tcpext['tcp_sack_shift_fallback'] = m.group(0)

    m = re.search(r'(?<=TCPBacklogDrop:\W)\d+', i)
    if m:
      tcpext['tcp_backlog_drop'] = m.group(0)

    m = re.search(r'(?<=TCPDeferAcceptDrop:\W)\d+', i)
    if m:
      tcpext['tcp_defer_accept_drop'] = m.group(0)

    m = re.search(r'(?<=IPReversePathFilter:\W)\d+', i)
    if m:
      tcpext['ip_reverse_path_filter'] = m.group(0)

    m = re.search(r'(?<=TCPRetransFail:\W)\d+', i)
    if m:
      tcpext['tcp_retrans_fail'] = m.group(0)

    m = re.search(r'(?<=TCPRcvCoalesce:\W)\d+', i)
    if m:
      tcpext['tcp_rcv_coalesce'] = m.group(0)

    m = re.search(r'(?<=TCPOFOQueue:\W)\d+', i)
    if m:
      tcpext['tcp_ofo_queue'] = m.group(0)

    m = re.search(r'(?<=TCPOFOMerge:\W)\d+', i)
    if m:
      tcpext['tcp_ofo_merge'] = m.group(0)

    m = re.search(r'(?<=TCPChallengeACK:\W)\d+', i)
    if m:
      tcpext['tcp_challenge_ack'] = m.group(0)

    m = re.search(r'(?<=TCPSYNChallenge:\W)\d+', i)
    if m:
      tcpext['tcp_syn_challenge'] = m.group(0)

    m = re.search(r'(?<=TCPSpuriousRtxHostQueues:\W)\d+', i)
    if m:
      tcpext['tcp_spurious_rtx_host_queues'] = m.group(0)

    m = re.search(r'(?<=TCPAutoCorking:\W)\d+', i)
    if m:
      tcpext['tcp_auto_corking'] = m.group(0)

    m = re.search(r'(?<=TCPFromZeroWindowAdv:\W)\d+', i)
    if m:
      tcpext['tcp_from_zero_window'] = m.group(0)

    m = re.search(r'(?<=TCPToZeroWindowAdv:\W)\d+', i)
    if m:
      tcpext['tcp_to_zero_window'] = m.group(0)

    m = re.search(r'(?<=TCPWantZeroWindowAdv:\W)\d+', i)
    if m:
      tcpext['tcp_want_zero_window'] = m.group(0)

    m = re.search(r'(?<=TCPSynRetrans:\W)\d+', i)
    if m:
      tcpext['tcp_syn_retrans'] = m.group(0)

    m = re.search(r'(?<=TCPOrigDataSent:\W)\d+', i)
    if m:
      tcpext['tcp_orig_data_sent'] = m.group(0)

    m = re.search(r'(?<=TCPHystartTrainDetect:\W)\d+', i)
    if m:
      tcpext['tcp_Hystart_train_detect'] = m.group(0)

    m = re.search(r'(?<=TCPHystartTrainCwnd:\W)\d+', i)
    if m:
      tcpext['tcp_Hystart_train_cwnd'] = m.group(0)

    m = re.search(r'(?<=TCPHystartDelayDetect:\W)\d+', i)
    if m:
      tcpext['tcp_Hystart_delay_detect'] = m.group(0)

    m = re.search(r'(?<=TCPHystartDelayCwnd:\W)\d+', i)
    if m:
      tcpext['tcp_Hystart_delay_cwnd'] = m.group(0)

    m = re.search(r'(?<=TCPACKSkippedSynRecv:\W)\d+', i)
    if m:
      tcpext['tcp_ack_skipped_syn_recv'] = m.group(0)

    m = re.search(r'(?<=TCPACKSkippedSeq:\W)\d+', i)
    if m:
      tcpext['tcp_ack_skipped_seq'] = m.group(0)

    m = re.search(r'(?<=TCPACKSkippedChallenge:\W)\d+', i)
    if m:
      tcpext['tcp_ack_skipped_challenge'] = m.group(0)

  if tcpext.get('invalid_syn_cookies'):
    data += '# HELP py_netstat_TcpExt_invalid_syn_cookies Protocol TcpExt invalid SYN cookies received\n'
    data += '# TYPE py_netstat_TcpExt_invalid_syn_cookies untyped\n'
    data += 'py_netstat_TcpExt_invalid_syn_cookies '+ str(tcpext['invalid_syn_cookies']) + '\n'

  if tcpext.get('resets_received'):
    data += '# HELP py_netstat_TcpExt_resets_received Protocol TcpExt resets received\n'
    data += '# TYPE py_netstat_TcpExt_resets_received untyped\n'
    data += 'py_netstat_TcpExt_resets_received '+ str(tcpext['resets_received']) + '\n'

  if tcpext.get('packets_pruned'):
    data += '# HELP py_netstat_TcpExt_packets_pruned Protocol TcpExt packets pruned\n'
    data += '# TYPE py_netstat_TcpExt_packets_pruned untyped\n'
    data += 'py_netstat_TcpExt_packets_pruned '+ str(tcpext['packets_pruned']) + '\n'

  if tcpext.get('icmp_dropped'):
    data += '# HELP py_netstat_TcpExt_icmp_dropped Protocol TcpExt ICMP packets dropped\n'
    data += '# TYPE py_netstat_TcpExt_icmp_dropped untyped\n'
    data += 'py_netstat_TcpExt_icmp_dropped '+ str(tcpext['icmp_dropped']) + '\n'

  if tcpext.get('sockets_finished_time_wait'):
    data += '# HELP py_netstat_TcpExt_sockets_finished_time_wait Protocol TcpExt TCP sockets finished time wait\n'
    data += '# TYPE py_netstat_TcpExt_sockets_finished_time_wait untyped\n'
    data += 'py_netstat_TcpExt_sockets_finished_time_wait '+ str(tcpext['sockets_finished_time_wait']) + '\n'

  if tcpext.get('delayed_acks'):
    data += '# HELP py_netstat_TcpExt_delayed_acks Protocol TcpExt delayed acks sent\n'
    data += '# TYPE py_netstat_TcpExt_delayed_acks untyped\n'
    data += 'py_netstat_TcpExt_delayed_acks '+ str(tcpext['delayed_acks']) + '\n'

  if tcpext.get('delayed_acks_locked'):
    data += '# HELP py_netstat_TcpExt_delayed_acks_locked Protocol TcpExt delayed acks further delayed because of locked socket\n'
    data += '# TYPE py_netstat_TcpExt_delayed_acks_locked untyped\n'
    data += 'py_netstat_TcpExt_delayed_acks_locked '+ str(tcpext['delayed_acks_locked']) + '\n'

  if tcpext.get('quick_acks'):
    data += '# HELP py_netstat_TcpExt_quick_acks Protocol TcpExt Quick ack mode was activated\n'
    data += '# TYPE py_netstat_TcpExt_quick_acks untyped\n'
    data += 'py_netstat_TcpExt_quick_acks '+ str(tcpext['quick_acks']) + '\n'

  if tcpext.get('recvmsg_prequeue'):
    data += '# HELP py_netstat_TcpExt_recvmsg_prequeue Protocol TcpExt packets directly queued to recvmsg prequeue\n'
    data += '# TYPE py_netstat_TcpExt_recvmsg_prequeue untyped\n'
    data += 'py_netstat_TcpExt_recvmsg_prequeue '+ str(tcpext['recvmsg_prequeue']) + '\n'

  if tcpext.get('syns_to_listen_dropped'):
    data += '# HELP py_netstat_TcpExt_syns_to_listen_dropped Protocol TcpExt SYNs to LISTEN sockets dropped\n'
    data += '# TYPE py_netstat_TcpExt_syns_to_listen_dropped untyped\n'
    data += 'py_netstat_TcpExt_syns_to_listen_dropped '+ str(tcpext['syns_to_listen_dropped']) + '\n'

  if tcpext.get('backlog_bytes'):
    data += '# HELP py_netstat_TcpExt_backlog_bytes Protocol TcpExt bytes directly in process context from backlog\n'
    data += '# TYPE py_netstat_TcpExt_backlog_bytes untyped\n'
    data += 'py_netstat_TcpExt_backlog_bytes '+ str(tcpext['backlog_bytes']) + '\n'

  if tcpext.get('backlog_packets'):
    data += '# HELP py_netstat_TcpExt_backlog_packets Protocol TcpExt packets directly received from backlog\n'
    data += '# TYPE py_netstat_TcpExt_backlog_packets untyped\n'
    data += 'py_netstat_TcpExt_backlog_packets '+ str(tcpext['backlog_packets']) + '\n'

  if tcpext.get('prequeue_packets'):
    data += '# HELP py_netstat_TcpExt_prequeue_packets Protocol TcpExt packets directly received from prequeue\n'
    data += '# TYPE py_netstat_TcpExt_prequeue_packets untyped\n'
    data += 'py_netstat_TcpExt_prequeue_packets '+ str(tcpext['prequeue_packets']) + '\n'

  if tcpext.get('prequeue_bytes'):
    data += '# HELP py_netstat_TcpExt_prequeue_bytes Protocol TcpExt bytes directly received in process context from prequeue\n'
    data += '# TYPE py_netstat_TcpExt_prequeue_bytes untyped\n'
    data += 'py_netstat_TcpExt_prequeue_bytes '+ str(tcpext['prequeue_bytes']) + '\n'

  if tcpext.get('header_predicted'):
    data += '# HELP py_netstat_TcpExt_header_predicted Protocol TcpExt packet headers predicted\n'
    data += '# TYPE py_netstat_TcpExt_header_predicted untyped\n'
    data += 'py_netstat_TcpExt_header_predicted '+ str(tcpext['header_predicted']) + '\n'

  if tcpext.get('header_queued'):
    data += '# HELP py_netstat_TcpExt_header_queued Protocol TcpExt packets header predicted and directly queued to user\n'
    data += '# TYPE py_netstat_TcpExt_header_queued untyped\n'
    data += 'py_netstat_TcpExt_header_queued '+ str(tcpext['header_queued']) + '\n'

  if tcpext.get('ack_no_data'):
    data += '# HELP py_netstat_TcpExt_ack_no_data Protocol TcpExt acknowledgments not containing data\n'
    data += '# TYPE py_netstat_TcpExt_ack_no_data untyped\n'
    data += 'py_netstat_TcpExt_ack_no_data '+ str(tcpext['ack_no_data']) + '\n'

  if tcpext.get('predicted_acks'):
    data += '# HELP py_netstat_TcpExt_predicted_acks Protocol TcpExt predicted acknowledgments\n'
    data += '# TYPE py_netstat_TcpExt_predicted_acks untyped\n'
    data += 'py_netstat_TcpExt_predicted_acks '+ str(tcpext['predicted_acks']) + '\n'

  if tcpext.get('packet_loss_recovered'):
    data += '# HELP py_netstat_TcpExt_packet_loss_recovered Protocol TcpExt Wtimes recovered from packet loss\n'
    data += '# TYPE py_netstat_TcpExt_packet_loss_recovered untyped\n'
    data += 'py_netstat_TcpExt_packet_loss_recovered '+ str(tcpext['packet_loss_recovered']) + '\n'

  if tcpext.get('reorder_fack'):
    data += '# HELP py_netstat_TcpExt_reorder_fack Protocol TcpExt detected reordering using FACK\n'
    data += '# TYPE py_netstat_TcpExt_reorder_fack untyped\n'
    data += 'py_netstat_TcpExt_reorder_fack '+ str(tcpext['reorder_fack']) + '\n'

  if tcpext.get('reorder_sack'):
    data += '# HELP py_netstat_TcpExt_reorder_sack Protocol TcpExt detected reordering using SACK\n'
    data += '# TYPE py_netstat_TcpExt_reorder_sack untyped\n'
    data += 'py_netstat_TcpExt_reorder_sack '+ str(tcpext['reorder_sack']) + '\n'

  if tcpext.get('reorder_timestamp'):
    data += '# HELP py_netstat_TcpExt_reorder_timestamp Protocol TcpExt detected reordering using time stamp\n'
    data += '# TYPE py_netstat_TcpExt_reorder_timestamp untyped\n'
    data += 'py_netstat_TcpExt_reorder_timestamp '+ str(tcpext['reorder_timestamp']) + '\n'

  if tcpext.get('congestion_recovery'):
    data += '# HELP py_netstat_TcpExt_congestion_recovery Protocol TcpExt congestion windows fully recovered\n'
    data += '# TYPE py_netstat_TcpExt_congestion_recovery untyped\n'
    data += 'py_netstat_TcpExt_congestion_recovery '+ str(tcpext['congestion_recovery']) + '\n'

  if tcpext.get('congestion_recovery_no_slow'):
    data += '# HELP py_netstat_TcpExt_congestion_recovery_no_slow Protocol TcpExt congestion windows fully recovered without slow start\n'
    data += '# TYPE py_netstat_TcpExt_congestion_recovery_no_slow untyped\n'
    data += 'py_netstat_TcpExt_congestion_recovery_no_slow '+ str(tcpext['congestion_recovery_no_slow']) + '\n'

  if tcpext.get('congestion_recovery_no_slow_dsack'):
    data += '# HELP py_netstat_TcpExt_congestion_recovery_no_slow_dsack Protocol TcpExt congestion windows recovered without slow start by DSACK\n'
    data += '# TYPE py_netstat_TcpExt_congestion_recovery_no_slow_dsack untyped\n'
    data += 'py_netstat_TcpExt_congestion_recovery_no_slow_dsack '+ str(tcpext['congestion_recovery_no_slow_dsack']) + '\n'

  if tcpext.get('congestion_recovery_no_slow_partial_ack'):
    data += '# HELP py_netstat_TcpExt_congestion_recovery_no_slow_partial_ack Protocol TcpExt congestion windows recovered without slow start after partial ack\n'
    data += '# TYPE py_netstat_TcpExt_congestion_recovery_no_slow_partial_ack untyped\n'
    data += 'py_netstat_TcpExt_congestion_recovery_no_slow_partial_ack '+ str(tcpext['congestion_recovery_no_slow_partial_ack']) + '\n'

  if tcpext.get('congestion_recovery_partial'):
    data += '# HELP py_netstat_TcpExt_congestion_recovery_partial Protocol TcpExt congestion windows partially recovered using Hoe heuristic\n'
    data += '# TYPE py_netstat_TcpExt_congestion_recovery_partial untyped\n'
    data += 'py_netstat_TcpExt_congestion_recovery_partial '+ str(tcpext['congestion_recovery_partial']) + '\n'

  if tcpext.get('congestion_recovery_partial_ack'):
    data += '# HELP py_netstat_TcpExt_congestion_recovery_partial_ack Protocol TcpExt congestion windows recovered after partial ack\n'
    data += '# TYPE py_netstat_TcpExt_congestion_recovery_partial_ack untyped\n'
    data += 'py_netstat_TcpExt_congestion_recovery_partial_ack '+ str(tcpext['congestion_recovery_partial_ack']) + '\n'

  if tcpext.get('tcp_data_loss'):
    data += '# HELP py_netstat_TcpExt_tcp_data_loss Protocol TcpExt TCP data loss events\n'
    data += '# TYPE py_netstat_TcpExt_tcp_data_loss untyped\n'
    data += 'py_netstat_TcpExt_tcp_data_loss '+ str(tcpext['tcp_data_loss']) + '\n'

  if tcpext.get('tcp_dsack_undo'):
    data += '# HELP py_netstat_TcpExt_tcp_dsack_undo Protocol TcpExt TCPDSACKUndo\n'
    data += '# TYPE py_netstat_TcpExt_tcp_dsack_undo untyped\n'
    data += 'py_netstat_TcpExt_tcp_dsack_undo '+ str(tcpext['tcp_dsack_undo']) + '\n'

  if tcpext.get('tcp_lost_retransmit'):
    data += '# HELP py_netstat_TcpExt_tcp_lost_retransmit Protocol TcpExt TCPLostRetransmit\n'
    data += '# TYPE py_netstat_TcpExt_tcp_lost_retransmit untyped\n'
    data += 'py_netstat_TcpExt_tcp_lost_retransmit '+ str(tcpext['tcp_lost_retransmit']) + '\n'

  if tcpext.get('sack_recovery_timeouts'):
    data += '# HELP py_netstat_TcpExt_sack_recovery_timeouts Protocol TcpExt timeouts after SACK recovery\n'
    data += '# TYPE py_netstat_TcpExt_sack_recovery_timeouts untyped\n'
    data += 'py_netstat_TcpExt_sack_recovery_timeouts '+ str(tcpext['sack_recovery_timeouts']) + '\n'

  if tcpext.get('loss_state_timeouts'):
    data += '# HELP py_netstat_TcpExt_loss_state_timeouts Protocol TcpExt timeouts in loss state\n'
    data += '# TYPE py_netstat_TcpExt_loss_state_timeouts untyped\n'
    data += 'py_netstat_TcpExt_loss_state_timeouts '+ str(tcpext['loss_state_timeouts']) + '\n'

  if tcpext.get('fast_retransmits'):
    data += '# HELP py_netstat_TcpExt_fast_retransmits Protocol TcpExt fast retransmits\n'
    data += '# TYPE py_netstat_TcpExt_fast_retransmits untyped\n'
    data += 'py_netstat_TcpExt_fast_retransmits '+ str(tcpext['fast_retransmits']) + '\n'

  if tcpext.get('forward_retransmits'):
    data += '# HELP py_netstat_TcpExt_forward_retransmits Protocol TcpExt forward retransmits\n'
    data += '# TYPE py_netstat_TcpExt_forward_retransmits untyped\n'
    data += 'py_netstat_TcpExt_forward_retransmits '+ str(tcpext['forward_retransmits']) + '\n'

  if tcpext.get('transmits_slow_start'):
    data += '# HELP py_netstat_TcpExt_transmits_slow_start Protocol TcpExt retransmits in slow start\n'
    data += '# TYPE py_netstat_TcpExt_transmits_slow_start untyped\n'
    data += 'py_netstat_TcpExt_transmits_slow_start '+ str(tcpext['transmits_slow_start']) + '\n'

  if tcpext.get('other_timeouts'):
    data += '# HELP py_netstat_TcpExt_other_timeouts Protocol TcpExt other TCP timeouts\n'
    data += '# TYPE py_netstat_TcpExt_other_timeouts untyped\n'
    data += 'py_netstat_TcpExt_other_timeouts '+ str(tcpext['other_timeouts']) + '\n'

  if tcpext.get('sack_retransmits_failed'):
    data += '# HELP py_netstat_TcpExt_sack_retransmits_failed Protocol TcpExt SACK retransmits failed\n'
    data += '# TYPE py_netstat_TcpExt_sack_retransmits_failed untyped\n'
    data += 'py_netstat_TcpExt_sack_retransmits_failed '+ str(tcpext['sack_retransmits_failed']) + '\n'

  if tcpext.get('tcp_loss_probes'):
    data += '# HELP py_netstat_TcpExt_tcp_loss_probes Protocol TcpExt TCPLossProbes\n'
    data += '# TYPE py_netstat_TcpExt_tcp_loss_probes untyped\n'
    data += 'py_netstat_TcpExt_tcp_loss_probes '+ str(tcpext['tcp_loss_probes']) + '\n'

  if tcpext.get('receiver_scheduled_late'):
    data += '# HELP py_netstat_TcpExt_receiver_scheduled_late Protocol TcpExt times receiver scheduled too late for direct processing\n'
    data += '# TYPE py_netstat_TcpExt_receiver_scheduled_late untyped\n'
    data += 'py_netstat_TcpExt_receiver_scheduled_late '+ str(tcpext['receiver_scheduled_late']) + '\n'

  if tcpext.get('dsacks_sent_out_of_order_packets'):
    data += '# HELP py_netstat_TcpExt_dsacks_sent_out_of_order_packets Protocol TcpExt DSACKs for out of order packets received\n'
    data += '# TYPE py_netstat_TcpExt_dsacks_sent_out_of_order_packets untyped\n'
    data += 'py_netstat_TcpExt_dsacks_sent_out_of_order_packets '+ str(tcpext['dsacks_sent_out_of_order_packets']) + '\n'

  if tcpext.get('dsacks_received'):
    data += '# HELP py_netstat_TcpExt_dsacks_received Protocol TcpExt DSACKs received\n'
    data += '# TYPE py_netstat_TcpExt_dsacks_received untyped\n'
    data += 'py_netstat_TcpExt_dsacks_received '+ str(tcpext['dsacks_received']) + '\n'

  if tcpext.get('connections_reset_unexpected_data'):
    data += '# HELP py_netstat_TcpExt_connections_reset_unexpected_data Protocol TcpExt connections reset due to unexpected data\n'
    data += '# TYPE py_netstat_TcpExt_connections_reset_unexpected_data untyped\n'
    data += 'py_netstat_TcpExt_connections_reset_unexpected_data '+ str(tcpext['connections_reset_unexpected_data']) + '\n'

  if tcpext.get('connections_reset_early_close'):
    data += '# HELP py_netstat_TcpExt_connections_reset_early_close Protocol TcpExt connections reset due to early user close\n'
    data += '# TYPE py_netstat_TcpExt_connections_reset_early_close untyped\n'
    data += 'py_netstat_TcpExt_connections_reset_early_close '+ str(tcpext['connections_reset_early_close']) + '\n'

  if tcpext.get('connections_aborted_timeout'):
    data += '# HELP py_netstat_TcpExt_connections_aborted_timeout Protocol TcpExt connections aborted due to timeout\n'
    data += '# TYPE py_netstat_TcpExt_connections_aborted_timeout untyped\n'
    data += 'py_netstat_TcpExt_connections_aborted_timeout '+ str(tcpext['connections_aborted_timeout']) + '\n'

  if tcpext.get('tcp_dack_discard'):
    data += '# HELP py_netstat_TcpExt_tcp_dack_discard Protocol TcpExt TCPSACKDiscard\n'
    data += '# TYPE py_netstat_TcpExt_tcp_dack_discard untyped\n'
    data += 'py_netstat_TcpExt_tcp_dack_discard '+ str(tcpext['tcp_dack_discard']) + '\n'

  if tcpext.get('tcp_dack_ignore_old'):
    data += '# HELP py_netstat_TcpExt_tcp_dack_ignore_old Protocol TcpExt TCPDSACKIgnoredOld\n'
    data += '# TYPE py_netstat_TcpExt_tcp_dack_ignore_old untyped\n'
    data += 'py_netstat_TcpExt_tcp_dack_ignore_old '+ str(tcpext['tcp_dack_ignore_old']) + '\n'

  if tcpext.get('tcp_dack_ignore_no_undo'):
    data += '# HELP py_netstat_TcpExt_tcp_dack_ignore_no_undo Protocol TcpExt TCPDSACKIgnoredNoUndo\n'
    data += '# TYPE py_netstat_TcpExt_tcp_dack_ignore_no_undo untyped\n'
    data += 'py_netstat_TcpExt_tcp_dack_ignore_no_undo '+ str(tcpext['tcp_dack_ignore_no_undo']) + '\n'

  if tcpext.get('tcp_spurious_rtos'):
    data += '# HELP py_netstat_TcpExt_tcp_spurious_rtos Protocol TcpExt TCPSpuriousRTOs\n'
    data += '# TYPE py_netstat_TcpExt_tcp_spurious_rtos untyped\n'
    data += 'py_netstat_TcpExt_tcp_spurious_rtos '+ str(tcpext['tcp_spurious_rtos']) + '\n'

  if tcpext.get('tcp_sack_shifted'):
    data += '# HELP py_netstat_TcpExt_tcp_sack_shifted Protocol TcpExt TCPSackShifted\n'
    data += '# TYPE py_netstat_TcpExt_tcp_sack_shifted untyped\n'
    data += 'py_netstat_TcpExt_tcp_sack_shifted '+ str(tcpext['tcp_sack_shifted']) + '\n'

  if tcpext.get('tcp_sack_merged'):
    data += '# HELP py_netstat_TcpExt_tcp_sack_merged Protocol TcpExt TCPSackMerged\n'
    data += '# TYPE py_netstat_TcpExt_tcp_sack_merged untyped\n'
    data += 'py_netstat_TcpExt_tcp_sack_merged '+ str(tcpext['tcp_sack_merged']) + '\n'

  if tcpext.get('tcp_sack_shift_fallback'):
    data += '# HELP py_netstat_TcpExt_tcp_sack_shift_fallback Protocol TcpExt TCPSackShiftFallback\n'
    data += '# TYPE py_netstat_TcpExt_tcp_sack_shift_fallback untyped\n'
    data += 'py_netstat_TcpExt_tcp_sack_shift_fallback '+ str(tcpext['tcp_sack_shift_fallback']) + '\n'

  if tcpext.get('tcp_backlog_drop'):
    data += '# HELP py_netstat_TcpExt_tcp_backlog_drop Protocol TcpExt TCPBacklogDrop\n'
    data += '# TYPE py_netstat_TcpExt_tcp_backlog_drop untyped\n'
    data += 'py_netstat_TcpExt_tcp_backlog_drop '+ str(tcpext['tcp_backlog_drop']) + '\n'

  if tcpext.get('tcp_defer_accept_drop'):
    data += '# HELP py_netstat_TcpExt_tcp_defer_accept_drop Protocol TcpExt TCPDeferAcceptDrop\n'
    data += '# TYPE py_netstat_TcpExt_tcp_defer_accept_drop untyped\n'
    data += 'py_netstat_TcpExt_tcp_defer_accept_drop '+ str(tcpext['tcp_defer_accept_drop']) + '\n'

  if tcpext.get('ip_reverse_path_filter'):
    data += '# HELP py_netstat_TcpExt_ip_reverse_path_filter Protocol TcpExt IPReversePathFilter\n'
    data += '# TYPE py_netstat_TcpExt_ip_reverse_path_filter untyped\n'
    data += 'py_netstat_TcpExt_ip_reverse_path_filter '+ str(tcpext['ip_reverse_path_filter']) + '\n'

  if tcpext.get('tcp_retrans_fail'):
    data += '# HELP py_netstat_TcpExt_tcp_retrans_fail Protocol TcpExt TCPRetransFail\n'
    data += '# TYPE py_netstat_TcpExt_tcp_retrans_fail untyped\n'
    data += 'py_netstat_TcpExt_tcp_retrans_fail '+ str(tcpext['tcp_retrans_fail']) + '\n'

  if tcpext.get('tcp_rcv_coalesce'):
    data += '# HELP py_netstat_TcpExt_tcp_rcv_coalesce Protocol TcpExt TCPRcvCoalesce\n'
    data += '# TYPE py_netstat_TcpExt_tcp_rcv_coalesce untyped\n'
    data += 'py_netstat_TcpExt_tcp_rcv_coalesce '+ str(tcpext['tcp_rcv_coalesce']) + '\n'

  if tcpext.get('tcp_ofo_queue'):
    data += '# HELP py_netstat_TcpExt_tcp_ofo_queue Protocol TcpExt TCPOFOQueue\n'
    data += '# TYPE py_netstat_TcpExt_tcp_ofo_queue untyped\n'
    data += 'py_netstat_TcpExt_tcp_ofo_queue '+ str(tcpext['tcp_ofo_queue']) + '\n'

  if tcpext.get('tcp_ofo_merge'):
    data += '# HELP py_netstat_TcpExt_tcp_ofo_merge Protocol TcpExt TCPOFOMerge\n'
    data += '# TYPE py_netstat_TcpExt_tcp_ofo_merge untyped\n'
    data += 'py_netstat_TcpExt_tcp_ofo_merge '+ str(tcpext['tcp_ofo_merge']) + '\n'

  if tcpext.get('tcp_challenge_ack'):
    data += '# HELP py_netstat_TcpExt_tcp_challenge_ack Protocol TcpExt TCPChallengeACK\n'
    data += '# TYPE py_netstat_TcpExt_tcp_challenge_ack untyped\n'
    data += 'py_netstat_TcpExt_tcp_challenge_ack '+ str(tcpext['tcp_challenge_ack']) + '\n'

  if tcpext.get('tcp_syn_challenge'):
    data += '# HELP py_netstat_TcpExt_tcp_syn_challenge Protocol TcpExt TCPSYNChallenge\n'
    data += '# TYPE py_netstat_TcpExt_tcp_syn_challenge untyped\n'
    data += 'py_netstat_TcpExt_tcp_syn_challenge '+ str(tcpext['tcp_syn_challenge']) + '\n'

  if tcpext.get('tcp_spurious_rtx_host_queues'):
    data += '# HELP py_netstat_TcpExt_tcp_spurious_rtx_host_queues Protocol TcpExt TCPSpuriousRtxHostQueues\n'
    data += '# TYPE py_netstat_TcpExt_tcp_spurious_rtx_host_queues untyped\n'
    data += 'py_netstat_TcpExt_tcp_spurious_rtx_host_queues '+ str(tcpext['tcp_spurious_rtx_host_queues']) + '\n'

  if tcpext.get('tcp_auto_corking'):
    data += '# HELP py_netstat_TcpExt_tcp_auto_corking Protocol TcpExt TCPAutoCorking\n'
    data += '# TYPE py_netstat_TcpExt_tcp_auto_corking untyped\n'
    data += 'py_netstat_TcpExt_tcp_auto_corking '+ str(tcpext['tcp_auto_corking']) + '\n'

  if tcpext.get('tcp_from_zero_window'):
    data += '# HELP py_netstat_TcpExt_tcp_from_zero_window Protocol TcpExt TCPFromZeroWindowAdv\n'
    data += '# TYPE py_netstat_TcpExt_tcp_from_zero_window untyped\n'
    data += 'py_netstat_TcpExt_tcp_from_zero_window '+ str(tcpext['tcp_from_zero_window']) + '\n'

  if tcpext.get('tcp_to_zero_window'):
    data += '# HELP py_netstat_TcpExt_tcp_to_zero_window Protocol TcpExt TCPToZeroWindowAdv\n'
    data += '# TYPE py_netstat_TcpExt_tcp_to_zero_window untyped\n'
    data += 'py_netstat_TcpExt_tcp_to_zero_window '+ str(tcpext['tcp_to_zero_window']) + '\n'

  if tcpext.get('tcp_want_zero_window'):
    data += '# HELP py_netstat_TcpExt_tcp_want_zero_window Protocol TcpExt TCPWantZeroWindowAdv\n'
    data += '# TYPE py_netstat_TcpExt_tcp_want_zero_window untyped\n'
    data += 'py_netstat_TcpExt_tcp_want_zero_window '+ str(tcpext['tcp_want_zero_window']) + '\n'

  if tcpext.get('tcp_syn_retrans'):
    data += '# HELP py_netstat_TcpExt_tcp_syn_retrans Protocol TcpExt TCPSynRetrans\n'
    data += '# TYPE py_netstat_TcpExt_tcp_syn_retrans untyped\n'
    data += 'py_netstat_TcpExt_tcp_syn_retrans '+ str(tcpext['tcp_syn_retrans']) + '\n'

  if tcpext.get('tcp_orig_data_sent'):
    data += '# HELP py_netstat_TcpExt_tcp_orig_data_sent Protocol TcpExt TCPOrigDataSent\n'
    data += '# TYPE py_netstat_TcpExt_tcp_orig_data_sent untyped\n'
    data += 'py_netstat_TcpExt_tcp_orig_data_sent '+ str(tcpext['tcp_orig_data_sent']) + '\n'

  if tcpext.get('tcp_Hystart_train_detect'):
    data += '# HELP py_netstat_TcpExt_tcp_Hystart_train_detect Protocol TcpExt TCPHystartTrainDetect\n'
    data += '# TYPE py_netstat_TcpExt_tcp_Hystart_train_detect untyped\n'
    data += 'py_netstat_TcpExt_tcp_Hystart_train_detect '+ str(tcpext['tcp_Hystart_train_detect']) + '\n'

  if tcpext.get('tcp_Hystart_train_cwnd'):
    data += '# HELP py_netstat_TcpExt_tcp_Hystart_train_cwnd Protocol TcpExt TCPHystartTrainCwnd\n'
    data += '# TYPE py_netstat_TcpExt_tcp_Hystart_train_cwnd untyped\n'
    data += 'py_netstat_TcpExt_tcp_Hystart_train_cwnd '+ str(tcpext['tcp_Hystart_train_cwnd']) + '\n'

  if tcpext.get('tcp_Hystart_delay_detect'):
    data += '# HELP py_netstat_TcpExt_tcp_Hystart_delay_detect Protocol TcpExt TCPHystartDelayDetect\n'
    data += '# TYPE py_netstat_TcpExt_tcp_Hystart_delay_detect untyped\n'
    data += 'py_netstat_TcpExt_tcp_Hystart_delay_detect '+ str(tcpext['tcp_Hystart_delay_detect']) + '\n'

  if tcpext.get('tcp_Hystart_delay_cwnd'):
    data += '# HELP py_netstat_TcpExt_tcp_Hystart_delay_cwnd Protocol TcpExt TCPHystartDelayCwnd\n'
    data += '# TYPE py_netstat_TcpExt_tcp_Hystart_delay_cwnd untyped\n'
    data += 'py_netstat_TcpExt_tcp_Hystart_delay_cwnd '+ str(tcpext['tcp_Hystart_delay_cwnd']) + '\n'

  if tcpext.get('tcp_ack_skipped_syn_recv'):
    data += '# HELP py_netstat_TcpExt_tcp_ack_skipped_syn_recv Protocol TcpExt TCPACKSkippedSynRecv\n'
    data += '# TYPE py_netstat_TcpExt_tcp_ack_skipped_syn_recv untyped\n'
    data += 'py_netstat_TcpExt_tcp_ack_skipped_syn_recv '+ str(tcpext['tcp_ack_skipped_syn_recv']) + '\n'

  if tcpext.get('tcp_ack_skipped_seq'):
    data += '# HELP py_netstat_TcpExt_tcp_ack_skipped_seq Protocol TcpExt TCPACKSkippedSeq\n'
    data += '# TYPE py_netstat_TcpExt_tcp_ack_skipped_seq untyped\n'
    data += 'py_netstat_TcpExt_tcp_ack_skipped_seq '+ str(tcpext['tcp_ack_skipped_seq']) + '\n'

  if tcpext.get('tcp_ack_skipped_challenge'):
    data += '# HELP py_netstat_TcpExt_tcp_ack_skipped_challenge Protocol TcpExt TCPACKSkippedChallenge\n'
    data += '# TYPE py_netstat_TcpExt_tcp_ack_skipped_challenge untyped\n'
    data += 'py_netstat_TcpExt_tcp_ack_skipped_challenge '+ str(tcpext['tcp_ack_skipped_challenge']) + '\n'

  ipext = {}
  ipext_list = str(ns['IpExt']).split(',')
  for i in ipext_list:

    m = re.search(r'(?<=InMcastPkts:\W)\d+', i)
    if m:
      ipext['InMcastPkts'] = m.group(0)

    m = re.search(r'(?<=OutMcastPkts:\W)\d+', i)
    if m:
      ipext['OutMcastPkts'] = m.group(0)

    m = re.search(r'(?<=InBcastPkts:\W)\d+', i)
    if m:
      ipext['InBcastPkts'] = m.group(0)

    m = re.search(r'(?<=InOctets:\W)\d+', i)
    if m:
      ipext['InOctets'] = m.group(0)

    m = re.search(r'(?<=OutOctets:\W)\d+', i)
    if m:
      ipext['OutOctets'] = m.group(0)

    m = re.search(r'(?<=InMcastOctets:\W)\d+', i)
    if m:
      ipext['InMcastOctets'] = m.group(0)

    m = re.search(r'(?<=OutMcastOctets:\W)\d+', i)
    if m:
      ipext['OutMcastOctets'] = m.group(0)

    m = re.search(r'(?<=InBcastOctets:\W)\d+', i)
    if m:
      ipext['InBcastOctets'] = m.group(0)

    m = re.search(r'(?<=InNoRoutes:\W)\d+', i)
    if m:
      ipext['InNoRoutes'] = m.group(0)

    m = re.search(r'(?<=InNoECTPkts:\W)\d+', i)
    if m:
      ipext['InNoECTPkts'] = m.group(0)

    m = re.search(r'(?<=InECT1Pkts:\W)\d+', i)
    if m:
      ipext['InECT1Pkts'] = m.group(0)

    m = re.search(r'(?<=InECT0Pkts:\W)\d+', i)
    if m:
      ipext['InECT0Pkts'] = m.group(0)

    m = re.search(r'(?<=InCEPkts:\W)\d+', i)
    if m:
      ipext['InCEPkts'] = m.group(0)

  for k,v in ipext.iteritems():
    data += '# HELP py_netstat_IpExt_'+k+' Protocol IpExt '+k+'\n'
    data += '# TYPE py_netstat_IpExt_'+k+' untyped\n'
    data += 'py_netstat_IpExt_'+k+' '+ v + '\n'    

  tcp = {}
  tcp_list = str(ns['Tcp']).split(',')
  for i in tcp_list:

    m = re.search(r'\d+(?=\Wactive connections openings)', i)
    if m:
      tcp['active_connection_openings'] = m.group(0)

    m = re.search(r'\d+(?=\Wpassive connection openings)', i)
    if m:
      tcp['passive_connection_openings'] = m.group(0)

    m = re.search(r'\d+(?=\Wfailed connection attempts)', i)
    if m:
      tcp['failed_connection_attempts'] = m.group(0)

    m = re.search(r'\d+(?=\Wconnection resets received)', i)
    if m:
      tcp['connection_resets_received'] = m.group(0)

    m = re.search(r'\d+(?=\Wconnections established)', i)
    if m:
      tcp['connections_established'] = m.group(0)

    m = re.search(r'\d+(?=\Wsegments received)', i)
    if m:
      tcp['segments_received'] = m.group(0)

    m = re.search(r'\d+(?=\Wsegments send out)', i)
    if m:
      tcp['segments_sent_out'] = m.group(0)

    m = re.search(r'\d+(?=\Wsegments retransmited)', i)
    if m:
      tcp['segments_retransmited'] = m.group(0)

    m = re.search(r'\d+(?=\Wbad segments received)', i)
    if m:
      tcp['bad_segments_received'] = m.group(0)

    m = re.search(r'\d+(?=\Wresets sent)', i)
    if m:
      tcp['resets_sent'] = m.group(0)

  for k,v in tcp.iteritems():
    data += '# HELP py_netstat_Tcp_'+k+' Protocol Tcp '+k.replace("_"," ")+'\n'
    data += '# TYPE py_netstat_Tcp_'+k+' untyped\n'
    data += 'py_netstat_Tcp_'+k+' '+ v + '\n' 

  icmp_msg = {}
  icmp_msg_list = str(ns['IcmpMsg']).split(',')
  for i in icmp_msg_list:

    m = re.search(r'(?<=InType0:\W)\d+', i)
    if m:
      icmp_msg['InType0'] = m.group(0)

    m = re.search(r'(?<=InType3:\W)\d+', i)
    if m:
      icmp_msg['InType3'] = m.group(0)

    m = re.search(r'(?<=InType8:\W)\d+', i)
    if m:
      icmp_msg['InType8'] = m.group(0)

    m = re.search(r'(?<=InType11:\W)\d+', i)
    if m:
      icmp_msg['InType11'] = m.group(0)

    m = re.search(r'(?<=InType13:\W)\d+', i)
    if m:
      icmp_msg['InType13'] = m.group(0)

    m = re.search(r'(?<=InType17:\W)\d+', i)
    if m:
      icmp_msg['InType17'] = m.group(0)

    m = re.search(r'(?<=OutType0:\W)\d+', i)
    if m:
      icmp_msg['OutType0'] = m.group(0)

    m = re.search(r'(?<=OutType3:\W)\d+', i)
    if m:
      icmp_msg['OutType3'] = m.group(0)

    m = re.search(r'(?<=OutType8:\W)\d+', i)
    if m:
      icmp_msg['OutType8'] = m.group(0)

    m = re.search(r'(?<=OutType14:\W)\d+', i)
    if m:
      icmp_msg['OutType14'] = m.group(0)

  for k,v in icmp_msg.iteritems():
    data += '# HELP py_netstat_IcmpMsg_'+k+' Protocol IcmpMsg '+k+'\n'
    data += '# TYPE py_netstat_IcmpMsg_'+k+' untyped\n'
    data += 'py_netstat_IcmpMsg_'+k+' '+ v + '\n'    

  icmp = {}
  icmp_sort = str(ns['Icmp']).replace('histogram:', '\n')
  icmp_sorted = icmp_sort.split('\n')
  icmp_stats = icmp_sorted[0]
  icmp_input = icmp_sorted[1]
  icmp_output = icmp_sorted[2]
  icmp_list = str(ns['Icmp']).split(',')
  for i in icmp_stats.split(','):

    m = re.search(r'\d+(?=\WICMP messages received)', i)
    if m:
      icmp['icmp_messages_received'] = m.group(0)

    m = re.search(r'\d+(?=\Winput ICMP message failed)', i)
    if m:
      icmp['input_icmp_message_failed'] = m.group(0)

  for i in icmp_input.split(','):

    m = re.search(r'(?<=destination unreachable:\W)\d+', i)
    if m:
      icmp_msg['input_histogram_destination_unreachable'] = m.group(0)

    m = re.search(r'(?<=timeout in transit:\W)\d+', i)
    if m:
      icmp_msg['input_histogram_timeout_in_transit'] = m.group(0)

    m = re.search(r'(?<=echo requests:\W)\d+', i)
    if m:
      icmp_msg['input_histogram_echo_requests'] = m.group(0)

    m = re.search(r'(?<=echo replies:\W)\d+', i)
    if m:
      icmp_msg['input_histogram_echo_replies'] = m.group(0)

    m = re.search(r'(?<=timestamp request:\W)\d+', i)
    if m:
      icmp_msg['input_histogram_timestamp_request'] = m.group(0)

    m = re.search(r'\d+(?=\WICMP messages sent)', i)
    if m:
      icmp['input_histogram_icmp_messages_sent'] = m.group(0)

    m = re.search(r'\d+(?=\WICMP messages failed)', i)
    if m:
      icmp['input_histogram_icmp_messages_failed'] = m.group(0)

  for i in icmp_input.split(','):

    m = re.search(r'(?<=destination unreachable:\W)\d+', i)
    if m:
      icmp['output_histogram_destination_unreachable'] = m.group(0)

    m = re.search(r'(?<=echo requests:\W)\d+', i)
    if m:
      icmp['output_histogram_echo_requests'] = m.group(0)

    m = re.search(r'(?<=echo replies:\W)\d+', i)
    if m:
      icmp['output_histogram_echo_replies'] = m.group(0)

    m = re.search(r'(?<=timestamp request:\W)\d+', i)
    if m:
      icmp['output_histogram_timestamp_request'] = m.group(0)

  for k,v in icmp.iteritems():
    data += '# HELP py_netstat_Icmp_'+k+' Protocol Icmp '+k.replace("_"," ")+'\n'
    data += '# TYPE py_netstat_Icmp_'+k+' untyped\n'
    data += 'py_netstat_Icmp_'+k+' '+ v + '\n' 

## for debugging netstat info
  # data += '### IP: \n'
  # for i in str(ns['Ip']).split(','):
  #   data += '# '+ str(i) + '\n'
  # data += '### Udp: \n'
  # for i in str(ns['Udp']).split(','):
  #   data += '# '+str(i) + '\n'
  # data += '### TcpExt: \n'
  # for i in str(ns['TcpExt']).split(','):
  #   data += '# '+str(i) + '\n'
  # data += '### IpExt: \n'
  # for i in str(ns['IpExt']).split(','):
  #   data += '# '+str(i) + '\n'
  # data += '### Tcp: \n'
  # for i in str(ns['Tcp']).split(','):
  #   data += '# '+str(i) + '\n'
  # data += '### IcmpMsg: \n'
  # for i in str(ns['IcmpMsg']).split(','):
  #   data += '# '+str(i) + '\n'
  # data += '### ICMP unsorted: \n'
  # for i in str(ns['Icmp']).split(','):
  #   data += '# '+str(i)+'\n'
  # data += '### ICMP stats: \n'
  # for i in icmp_stats.split(','):
  #   data += '# '+str(i) + '\n'
  # data += '### ICMP input: \n'
  # for i in icmp_input.split(','):
  #   data += '# '+str(i) + '\n'
  # data += '### ICMP output: \n'
  # for i in icmp_output.split(','):
  #   data += '# '+str(i) + '\n'

  # netinfo
  netinfo = py_netinfo.netinfo()
  # py_network_receive_bytes
  data += '# HELP py_network_receive_bytes Network device statistic receive_bytes.\n'
  data += '# TYPE py_network_receive_bytes gauge\n'
  for i in netinfo.response:
    if i.startswith('Inter'):
      pass
    elif i.startswith(' face'):
      pass
    else:
      field = i.split()
      data += 'py_network_receive_bytes{device="'+ field[0].rstrip(':') +'"} '+ field[1] +'\n'

  # py_network_receive_compressed
  data += '# HELP py_network_receive_compressed Network device statistic receive_compressed.\n'
  data += '# TYPE py_network_receive_compressed gauge\n'
  for i in netinfo.response:
    if i.startswith('Inter'):
      pass
    elif i.startswith(' face'):
      pass
    else:
      field = i.split()
      data += 'py_network_receive_compressed{device="'+ field[0].rstrip(':') +'"} '+ field[7] +'\n'

  # py_network_receive_drop
  data += '# HELP py_network_receive_drop Network device statistic receive_drop.\n'
  data += '# TYPE py_network_receive_drop gauge\n'
  for i in netinfo.response:
    if i.startswith('Inter'):
      pass
    elif i.startswith(' face'):
      pass
    else:
      field = i.split()
      data += 'py_network_receive_drop{device="'+ field[0].rstrip(':') +'"} '+ field[4] +'\n'

  # py_network_receive_errs
  data += '# HELP py_network_receive_errs Network device statistic receive_errs.\n'
  data += '# TYPE py_network_receive_errs gauge\n'
  for i in netinfo.response:
    if i.startswith('Inter'):
      pass
    elif i.startswith(' face'):
      pass
    else:
      field = i.split()
      data += 'py_network_receive_errs{device="'+ field[0].rstrip(':') +'"} '+ field[3] +'\n'

  # py_network_receive_fifo
  data += '# HELP py_network_receive_fifo Network device statistic receive_fifo.\n'
  data += '# TYPE py_network_receive_fifo gauge\n'
  for i in netinfo.response:
    if i.startswith('Inter'):
      pass
    elif i.startswith(' face'):
      pass
    else:
      field = i.split()
      data += 'py_network_receive_fifo{device="'+ field[0].rstrip(':') +'"} '+ field[5] +'\n'

  # py_network_receive_frame
  data += '# HELP py_network_receive_frame Network device statistic receive_frame.\n'
  data += '# TYPE py_network_receive_frame gauge\n'
  for i in netinfo.response:
    if i.startswith('Inter'):
      pass
    elif i.startswith(' face'):
      pass
    else:
      field = i.split()
      data += 'py_network_receive_frame{device="'+ field[0].rstrip(':') +'"} '+ field[6] +'\n'

  # py_network_receive_multicast
  data += '# HELP py_network_receive_multicast Network device statistic receive_multicast.\n'
  data += '# TYPE py_network_receive_multicast gauge\n'
  for i in netinfo.response:
    if i.startswith('Inter'):
      pass
    elif i.startswith(' face'):
      pass
    else:
      field = i.split()
      data += 'py_network_receive_multicast{device="'+ field[0].rstrip(':') +'"} '+ field[8] +'\n'

  # py_network_receive_packets
  data += '# HELP py_network_receive_packets Network device statistic receive_packets.\n'
  data += '# TYPE py_network_receive_packets gauge\n'
  for i in netinfo.response:
    if i.startswith('Inter'):
      pass
    elif i.startswith(' face'):
      pass
    else:
      field = i.split()
      data += 'py_network_receive_packets{device="'+ field[0].rstrip(':') +'"} '+ field[2] +'\n'

  # py_network_transmit_bytes
  data += '# HELP py_network_transmit_bytes Network device statistic transmit_bytes.\n'
  data += '# TYPE py_network_transmit_bytes gauge\n'
  for i in netinfo.response:
    if i.startswith('Inter'):
      pass
    elif i.startswith(' face'):
      pass
    else:
      field = i.split()
      data += 'py_network_transmit_bytes{device="'+ field[0].rstrip(':') +'"} '+ field[9] +'\n'

  # py_network_transmit_packets
  data += '# HELP py_network_transmit_packets Network device statistic transmit_packets.\n'
  data += '# TYPE py_network_transmit_packets gauge\n'
  for i in netinfo.response:
    if i.startswith('Inter'):
      pass
    elif i.startswith(' face'):
      pass
    else:
      field = i.split()
      data += 'py_network_transmit_packets{device="'+ field[0].rstrip(':') +'"} '+ field[10] +'\n'

  # py_network_transmit_errs
  data += '# HELP py_network_transmit_errs Network device statistic transmit_errs.\n'
  data += '# TYPE py_network_transmit_errs gauge\n'
  for i in netinfo.response:
    if i.startswith('Inter'):
      pass
    elif i.startswith(' face'):
      pass
    else:
      field = i.split()
      data += 'py_network_transmit_errs{device="'+ field[0].rstrip(':') +'"} '+ field[11] +'\n'

  # py_network_transmit_drop
  data += '# HELP py_network_transmit_drop Network device statistic transmit_drop.\n'
  data += '# TYPE py_network_transmit_drop gauge\n'
  for i in netinfo.response:
    if i.startswith('Inter'):
      pass
    elif i.startswith(' face'):
      pass
    else:
      field = i.split()
      data += 'py_network_transmit_drop{device="'+ field[0].rstrip(':') +'"} '+ field[12] +'\n'

  # py_network_transmit_fifo
  data += '# HELP py_network_transmit_fifo Network device statistic transmit_fifo.\n'
  data += '# TYPE py_network_transmit_fifo gauge\n'
  for i in netinfo.response:
    if i.startswith('Inter'):
      pass
    elif i.startswith(' face'):
      pass
    else:
      field = i.split()
      data += 'py_network_transmit_fifo{device="'+ field[0].rstrip(':') +'"} '+ field[13] +'\n'

  # py_network_transmit_frame
  data += '# HELP py_network_transmit_frame Network device statistic transmit_frame.\n'
  data += '# TYPE py_network_transmit_frame gauge\n'
  for i in netinfo.response:
    if i.startswith('Inter'):
      pass
    elif i.startswith(' face'):
      pass
    else:
      field = i.split()
      data += 'py_network_transmit_frame{device="'+ field[0].rstrip(':') +'"} '+ field[14] +'\n'

  # py_network_transmit_compressed
  data += '# HELP py_network_transmit_compressed Network device statistic transmit_compressed.\n'
  data += '# TYPE py_network_transmit_compressed gauge\n'
  for i in netinfo.response:
    if i.startswith('Inter'):
      pass
    elif i.startswith(' face'):
      pass
    else:
      field = i.split()
      data += 'py_network_transmit_compressed{device="'+ field[0].rstrip(':') +'"} '+ field[15] +'\n'

  # py_network_transmit_multicast
  data += '# HELP py_network_transmit_multicast Network device statistic transmit_multicast.\n'
  data += '# TYPE py_network_transmit_multicast gauge\n'
  for i in netinfo.response:
    if i.startswith('Inter'):
      pass
    elif i.startswith(' face'):
      pass
    else:
      field = i.split()
      data += 'py_network_transmit_multicast{device="'+ field[0].rstrip(':') +'"} '+ field[16] +'\n'

  # py_procs_blocked
  procs_blocked = py_procs.blocked()
  data += '# HELP py_procs_blocked Number of processes blocked waiting for I/O to complete.\n'
  data += '# TYPE py_procs_blocked gauge\n'
  data += 'py_procs_blocked '+ procs_blocked.response +'\n'
  # py_procs_running
  procs_running = py_procs.running()
  data += '# HELP py_procs_running Number of processes in runnable state.\n'
  data += '# TYPE py_procs_running gauge\n'
  data += 'py_procs_running '+ procs_running.response +'\n'
  # sockstat data
  sockstat = py_sockstat.sockstat()
  sockstats = {}
  for i in sockstat.response:

    m = re.search(r'(?<=sockets: used\W)\d+', i)
    if m:
      sockstats['sockets_used'] = m.group(0)

    m = re.search(r'TCP:(.*inuse\W\d+)', i)
    if m:
      socklist = m.group(0).split()
      sockstats['TCP_inuse'] = socklist[-1]

    m = re.search(r'TCP:(.+alloc\W\d+)', i)
    if m:
      socklist = m.group(0).split()
      sockstats['TCP_alloc'] = socklist[-1]

    m = re.search(r'TCP:(.+orphan\W\d+)', i)
    if m:
      socklist = m.group(0).split()
      sockstats['TCP_orphan'] = socklist[-1]

    m = re.search(r'TCP:(.+tw\W\d+)', i)
    if m:
      socklist = m.group(0).split()
      sockstats['TCP_tw'] = socklist[-1]

    m = re.search(r'TCP:(.+mem\W\d+)', i)
    if m:
      socklist = m.group(0).split()
      sockstats['TCP_mem'] = socklist[-1]

    m = re.search(r'UDP:(.+inuse\W\d+)', i)
    if m:
      socklist = m.group(0).split()
      sockstats['UDP_inuse'] = socklist[-1]

    m = re.search(r'UDP:(.+mem\W\d+)', i)
    if m:
      socklist = m.group(0).split()
      sockstats['UDP_mem'] = socklist[-1]

    m = re.search(r'UDPLITE:(.+inuse\W\d+)', i)
    if m:
      socklist = m.group(0).split()
      sockstats['UDPLITE_inuse'] = socklist[-1]

    m = re.search(r'RAW:(.+inuse\W\d+)', i)
    if m:
      socklist = m.group(0).split()
      sockstats['RAW_inuse'] = socklist[-1]

    m = re.search(r'FRAG:(.+inuse\W\d+)', i)
    if m:
      socklist = m.group(0).split()
      sockstats['FRAG_inuse'] = socklist[-1]

    m = re.search(r'FRAG:(.+memory\W\d+)', i)
    if m:
      socklist = m.group(0).split()
      sockstats['FRAG_memory'] = socklist[-1]

    #data += '# '+ i #+'\n'

  for k,v in sockstats.iteritems():
    data += '# HELP py_sockstat_'+k+' Socket count: '+k.replace("_"," ")+'\n'
    data += '# TYPE py_sockstat_'+k+' gauge\n'
    data += 'py_sockstat_'+k+' '+ v + '\n' 

    #data += '# '+k+' '+ v + '\n'     

  # py_time
  time = py_time.time()
  data += '# HELP py_time System time in seconds since epoch (1970).\n'
  data += '# TYPE py_time gauge\n'
  data += 'py_time '+ time.response

  # py_uname_info
  uname = py_uname.uname()
  field = uname.response.split()
  domain = None
  machine = None
  m = re.search(r'(?<=\S\.).*', field[1])
  if m:
    domain = m.group(0)
  if domain == None:
    domain = '(none)'
  m = re.search(r'(?<=\S\.)\w+$', field[2])
  if m:
    machine = m.group(0)
  if machine == None:
    machine = 'error'

  data += '# HELP py_uname_info Labeled system information as provided by the uname system call.\n'
  data += '# TYPE py_uname_info gauge\n'
  data += 'py_uname_info{domain="'+domain+'",machine="'+machine+'",nodename="'+field[1]+'",release="'+field[2]+'",sysname="'+field[0]+'",version="'+field[3]+' '+field[4]+' '+field[5]+' '+field[6]+' '+field[7]+' '+field[8]+' '+field[9]+' '+field[10]+'"} 1\n'

  # vmstat metrics
  vmstat = py_vmstat.vmstat()
  vmstats = {}
  for i in vmstat.response:
    field = i.split()
    vmstats[field[0]] = field[1]

  for k,v in vmstats.iteritems():
    data += '# HELP py_vmstat_'+k+' /proc/vmstat information field '+k+'\n'
    data += '# TYPE py_vmstat_'+k+' untyped\n'
    data += 'py_vmstat_'+k+' '+v+'\n'
  # py_scrape_collector_duration_seconds
  data += '# HELP py_scrape_collector_duration_seconds Python exporter: Duration of a collector scrape.\n'
  data += '# TYPE py_scrape_collector_duration_seconds gauge\n'
  data += 'py_scrape_collector_duration_seconds{collector="boot_time"} '+str(boot_time.duration)+'\n'
  data += 'py_scrape_collector_duration_seconds{collector="context_switches"} '+str(context_switches.duration)+'\n'
  data += 'py_scrape_collector_duration_seconds{collector="cpu_times"} '+str(cpu_times.duration)+'\n'
  data += 'py_scrape_collector_duration_seconds{collector="df"} '+str(df.duration)+'\n'
  data += 'py_scrape_collector_duration_seconds{collector="df_inodes"} '+str(dfi_duration)+'\n'
  data += 'py_scrape_collector_duration_seconds{collector="disk_bytes_read"} '+str(disk_bytes_read.duration)+'\n'
  data += 'py_scrape_collector_duration_seconds{collector="disk_io"} '+str(disk_io.duration)+'\n'
  data += 'py_scrape_collector_duration_seconds{collector="disk_usage"} '+str(disk_usage_duration)+'\n'
  data += 'py_scrape_collector_duration_seconds{collector="entropy_available_bits"} '+str(entropy_available_bits.duration)+'\n'
  data += 'py_scrape_collector_duration_seconds{collector="file_descriptors"} '+str(fd.duration)+'\n'
  data += 'py_scrape_collector_duration_seconds{collector="filesystem"} '+str(fs.duration)+'\n'
  data += 'py_scrape_collector_duration_seconds{collector="forks"} '+str(forks.duration)+'\n'
  data += 'py_scrape_collector_duration_seconds{collector="interrupts"} '+str(interrupts.duration)+'\n'
  data += 'py_scrape_collector_duration_seconds{collector="meminfo"} '+str(meminfo.duration)+'\n'
  data += 'py_scrape_collector_duration_seconds{collector="netinfo"} '+str(netinfo.duration)+'\n'
  data += 'py_scrape_collector_duration_seconds{collector="procs_blocked"} '+str(procs_blocked.duration)+'\n'
  data += 'py_scrape_collector_duration_seconds{collector="procs_running"} '+str(procs_running.duration)+'\n'
  data += 'py_scrape_collector_duration_seconds{collector="sensors"} '+str(sensors.duration)+'\n'
  data += 'py_scrape_collector_duration_seconds{collector="sockstat"} '+str(sockstat.duration)+'\n'
  if os.path.isfile('/usr/local/thirdparty/tibco/CURRENT/ems/8.2/bin/tibemsadmin'):
    data += 'py_scrape_collector_duration_seconds{collector="tibco"} '+str(tibco.duration)+'\n'
  data += 'py_scrape_collector_duration_seconds{collector="time"} '+str(time.duration)+'\n'
  data += 'py_scrape_collector_duration_seconds{collector="uname"} '+str(uname.duration)+'\n'
  data += 'py_scrape_collector_duration_seconds{collector="vmstat"} '+str(vmstat.duration)+'\n'
  # py_scrape_collector_success  
  data += '# HELP py_scrape_collector_success Python exporter: Whether a collector succeeded\n'
  data += '# TYPE py_scrape_collector_success gauge\n'
  data += 'py_scrape_collector_success{collector="boot_time"} '+str(boot_time.success)+'\n'
  data += 'py_scrape_collector_success{collector="context_switches"} '+str(context_switches.success)+'\n'
  data += 'py_scrape_collector_success{collector="cpu_times"} '+str(cpu_times.success)+'\n'
  data += 'py_scrape_collector_success{collector="df"} '+str(df.success)+'\n'
  data += 'py_scrape_collector_success{collector="df_inodes"} '+str(dfi.success)+'\n'
  data += 'py_scrape_collector_success{collector="disk_bytes_read"} '+str(disk_bytes_read.success)+'\n'
  data += 'py_scrape_collector_success{collector="disk_io"} '+str(disk_io.success)+'\n'
  data += 'py_scrape_collector_success{collector="disk_usage"} '+str(d.success)+'\n'
  data += 'py_scrape_collector_success{collector="entropy_available_bits"} '+str(entropy_available_bits.success)+'\n'
  data += 'py_scrape_collector_success{collector="file_descriptors"} '+str(fd.success)+'\n'
  data += 'py_scrape_collector_success{collector="filesystem"} '+str(fs.success)+'\n'
  data += 'py_scrape_collector_success{collector="forks"} '+str(forks.success)+'\n'
  data += 'py_scrape_collector_success{collector="interrupts"} '+str(interrupts.success)+'\n'
  data += 'py_scrape_collector_success{collector="meminfo"} '+str(meminfo.success)+'\n'
  data += 'py_scrape_collector_success{collector="netinfo"} '+str(netinfo.success)+'\n'
  data += 'py_scrape_collector_success{collector="procs_blocked"} '+str(procs_blocked.success)+'\n'
  data += 'py_scrape_collector_success{collector="procs_running"} '+str(procs_running.success)+'\n'
  data += 'py_scrape_collector_success{collector="sensors"} '+str(sensors.success)+'\n'
  data += 'py_scrape_collector_success{collector="sockstat"} '+str(sockstat.success)+'\n'
  if os.path.isfile('/usr/local/thirdparty/tibco/CURRENT/ems/8.2/bin/tibemsadmin'):
    data += 'py_scrape_collector_success{collector="tibco"} '+str(tibco.success)+'\n'
  data += 'py_scrape_collector_success{collector="time"} '+str(time.success)+'\n'
  data += 'py_scrape_collector_success{collector="uname"} '+str(uname.success)+'\n'
  data += 'py_scrape_collector_success{collector="vmstat"} '+str(vmstat.success)+'\n'
  # And finally the big return of the longest string in history
  return data

if __name__ == '__main__':
  app.run(
      host="0.0.0.0",
      port=5000,
      debug=True
  )
