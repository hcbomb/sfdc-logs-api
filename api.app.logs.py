#!/usr/bin/python

import ConfigParser
import base64 as b
import json
import pprint
import re
import sys
import os
import pdb
import ast
import time
import logging
import argparse
import socket
import signal
from logging.handlers import TimedRotatingFileHandler
from logging.handlers import SysLogHandler 
from logging.handlers import SMTPHandler
from datetime import datetime

# File: 
# Author: Henry Canivel

pp = pprint.PrettyPrinter(indent=2)
verbose = False
testing = True
org_list = {}
app_list = {}
org_collect = None
args = None
dir_create_flag = False
start_time = None
r_file = None
rlist = None
errors = []

# init cfg operations
cfg = None
fp = None
log = None
syslog = None
sh = None
base_config = {}
base_section_list = ['base','email','syslog destination','monitor']

mfg = None
monitor_file = None
config_file = None

# init loggers
# separate logger to send app logs over syslog

def init_libs():
  try:
    global simple_salesforce
    global requests
    import simple_salesforce
    import requests
  except ImportError:
    log.exception('Missing module <%s>; please install using: "pip install %s"'
      % ('simple_salesforce', 'simple_salesforce'))
    sys.exit(1)

# save whatever we can gracefully
def signal_handler(signum, stack):
  # validate base config settings before writing to the files 
  if not ('base' in base_config and 'folder' in base_config['base'] and 'monitor' in base_config and 'file' in base_config['monitor']):
      sys.exit(1)

  log.debug('kill signal: %i' % int(signum))

  if mfg and monitor_file:
    log.debug('writing to monitor file one last time.')
    with open(config_file, 'wb') as mfgfile:
      mfg.write(mfgfile)

  sys.exit(0)

def init_handlers():
  global log, syslog, sh, config_file

  # for local file logging
  log_header = base_config['base']['log_header']
  log_folder = base_config['base']['folder']
  log_name = base_config['base']['log_name']

  # validate path exists
  if log_folder and os.path.exists(log_folder):
    config_file = os.path.join(log_folder, log_name)
  else:
    config_file = os.path.join(os.path.dirname(__file__), log_name)

  # for email
  email_dest = base_config['email']['email']
  email_subj = base_config['email']['subject']
  smtp_server = base_config['email']['smtp_server']

  # for syslog
  syslog_header = base_config['syslog destination']['syslog_header']
  syslog_server = base_config['syslog destination']['syslog_server']
  syslog_port = int(base_config['syslog destination']['syslog_port'])

  # set up primary handlers
  log = logging.getLogger(log_header)
  log.setLevel(logging.DEBUG)

  syslog = logging.getLogger(syslog_header)
  syslog.setLevel(logging.INFO)

  # log to file
  try:
    fh = TimedRotatingFileHandler(config_file, when='d', interval=4, backupCount=14)
    fh.setLevel(logging.DEBUG)
    fhformat = logging.Formatter('%(asctime)s %(name)s[%(process)d]: log_level=%(levelname)s function=%(funcName)s message="%(message)s"',
     datefmt='%m/%d/%YT%H:%M:%S%z')
    fh.setFormatter(fhformat)
    log.addHandler(fh)
  except Exception, e:
    raise Exception('file handler for file %s failed. reason: %r' % (config_file, repr(e)))

  # email
  # IT SMTP servers will mask email sender as 'noreply@salesforce.com'
  try:
    eh = SMTPHandler(mailhost=smtp_server,
                     fromaddr=email_dest,
                     toaddrs=email_dest,
                     subject=email_subj)
    eh.setLevel(logging.ERROR)
    log.addHandler(eh)
  except Exception, e:
    raise Exception('email handler for destination %s failed. reason: %r' % (email_dest, repr(e)))

  # syslog
  try:
    sh = logging.handlers.SysLogHandler(address=(syslog_server, syslog_port), 
                                        facility=logging.handlers.SysLogHandler.LOG_NOTICE)
    sh.setLevel(logging.INFO)
    sysformat = logging.Formatter('%(name)s[%(process)d]: %(message)s', datefmt='%m/%d/%YT%H:%M:%S%z')
    sh.setFormatter(sysformat)
    sh.createLock()
    syslog.addHandler(sh)
  except Exception, e:
    raise Exception('syslog handler for type %s failed. reason: %r' % (syslog_header, repr(e)))


# validate settings file
def init_settings(cfg_filename):
  global cfg, mfg
  try:
    cfg = ConfigParser.SafeConfigParser()
    cp = cfg.read(cfg_filename)

    mfg = ConfigParser.SafeConfigParser()

    # if cp empty, failed read
    if not cp:
      raise Exception('Cannot read config file %s' % cfg_filename)

    # validate the sections we need
    for i in base_section_list:
      if i not in cfg.sections():
        print 'section %s not found in settings?!' % i
        raise
      if not cfg.options(i):
        print 'section %s has no options?!' % i
        raise

      # add values
      base_config[i] = {}
      for j in cfg.options(i):
        base_config[i][j] = cfg.get(i,j)
    
    init_handlers()
  except Exception, e:
    print 'ERROR: read failed: %r' % repr(e)


'''quickly encode raw configs'''
def config_encode(raw):
    temp = None
    for s in raw.sections():
        for o in raw.options(s):
            temp = b.b64encode(str(raw.get(s,o)))
            raw.set(s,o,temp)

'''function for debugging'''
def config_dump(dump=None):
    if not dump:
        dump=cfg
    for s in dump.sections():
        print 'section: %s' % s
        for o in dump.options(s):
            print '\t%s => %s' % (o, dump.get(s,o))

''' validate file exists'''
def check_file(file_path, write_true=False):
    if os.path.exists(file_path):
        if write_true:
            log.warning('File: %s already exists. Overwriting' % file_path)
        else:
            log.debug('Attempting to read file %s' % file_path)
    # if file does not exist and attempting to read, error
    elif not write_true:
        raise Exception('File: %s does not exist; please validate' % file_path)

''' validates if we can write to recovery file. 
    there are 3 scenarios to consider:
    1. partial list of logs were successfully completed (collect what's left) from same org
    2. some orgs were successful, some weren't
        how to determine to collect from just what failed
    3. cache last successful timestamp per org to baseline
'''
def check_recovery_file(file_path):
    try:
        if os.path.exist(file_path):
            log.debug('recovery file %s is non-empty, validating')
            rlist = {}
            with open(file_path, 'r') as f:
                temp = {}
                rorg, rtime, rstate, rpayload = f.readline()
                temp['time'] = int(rtime)
                temp['state'] = str(rstate)
                temp['entries'] = ast.literal_eval(rpayload)
                rlist[org] = dict(temp)
    except:
        log.exception('Failure reading from file %s' % file_path)

''' don't want to read raw configs and process logs. this enforces file to at least fail 
    any practice of automating from plaintext credential files.
    validates proper creds for org is provided

    reading password configs
'''
def validate_config(creds_file, write_true=False):
    
    try:
        check_file(creds_file, write_true)
        fp = cfg.read(creds_file)
    except Exception, e:
        log.error('Failed file check. %s' % e,exc_info=1)
        raise RuntimeError('config file %s invalid; please validate' % creds_file)

    if not cfg.sections():
        log.error('No sections to defined in config file %s' % file_path,exc_info=1)
        raise RuntimeError('config file %s invalid; please validate' % creds_file)

    for s in cfg.sections():
        user_check = False
        pass_check = False
        id_check = False
        secret_check = False
        stype = None
  
        log.debug('processing config section %s' % s)      
        if not cfg.has_option(s, 'type'):
            continue
        else:
            log.debug('Section: %s has type option specified. Proceed to decode user/pass' % s)

        stype = b.b64decode(cfg.get(s,'type'))

        # validates option field and value specified
        for o in cfg.options(s):
            enc = cfg.get(s,o)
            if stype == 'org':
                user_check = True if o == 'user' and enc else user_check
                pass_check = True if o == 'pass' and enc else pass_check
            else:
                id_check = True if o == 'client_id' and enc else id_check
                secret_check = True if o == 'client_secret' and enc else secret_check

        log.debug('section: %s\ttype: %s' % (s, stype))
        if stype == 'org':
            org_list[s] = {}
            if (not user_check or not pass_check):
                log.warning('user credentials not set for org <%s>' % s)
        if stype == 'app':
            app_list[s] = {}
            if (not id_check or not secret_check):
                log.warning('connected app settings not configured for <%s>' % s)
    if not org_list:
        raise Exception('Error: Failed file check; no orgs were extracted. Please validate encoded file. \
            \n\tIf file is raw, execute with "-w <file name>" flag to generate encoded file to use.')
        sys.exit(1)
        

### Extract Config

def extract_connapp(app_name):
    app = {}
    try:
        app['client_id'] = b.b64decode(cfg.get(app_name, 'client_id'))
        app['client_secret'] = b.b64decode(cfg.get(app_name, 'client_secret'))
    except Exception, e:
        log.error(repr(e) +': cannot extract client credentials')
        raise
    return app

def extract_org(org_name, check_rest=False):
    org = {}
    status = ''
    try:
        org['user'] = b.b64decode(cfg.get(org_name, 'user'))
        org['pass'] = b.b64decode(cfg.get(org_name, 'pass'))
    except Exception, e:
        if repr(e) == 'Incorrect padding':
            log.error(repr(e) +': validate if file is properly encoded')
            return repr(e), org
        log.error(repr(e) +': cannot extract user credentials')

    try:
        org['env'] = b.b64decode(cfg.get(org_name, 'env'))
    except Exception, e:
        log.error(repr(e) +': environment not set for org %s' % org_name)

    try:
        # if not rest, check for orgId to make library call to simple salesforce
        if not check_rest:
            org['orgid'] = b.b64decode(cfg.get(org_name, 'orgid'))
    except Exception, e:
        log.error(repr(e) +': no org id found.')
        
    return status, org

''' validate proper options are provided for appropriate login type'''
def extract_configs(check_rest=False, org=None, app=None):
    try:
        if org:
            if cfg.has_section(org):
                # don't forget; these are encoded
                if (b.b64decode(cfg.get(org,'type')) == 'org'):
                    error_str, org_temp = extract_org(org, check_rest)
                    if error_str:
                        log.error('cannot complete config read <%s>; terminating program' % error_str)
                        sys.exit(1)
                    # append only if something was returned
                    if org_temp:
                        org_list[org] = org_temp      
            else:
                log.error('cannot locate org %s in config. please validate config' % org)
                sys.exit(1)     

        elif app:
            # REST is specified, so check for connected app settings
            if check_rest:
                if not app:
                    raise RuntimeError('missing app name: please specify app name to check in configs for REST login')
                elif 'all' == app:
                    for s in cfg.sections():
                        if (b.b64decode(cfg.get(s,'type')) == 'app'):
                            app_temp = extract_connapp(s)
                            if app_temp:
                                app_list[s] = app_temp
    except TypeError == 'Incorrect padding':
        raise
    except Exception:
        raise


### Acquire Session ID

def sessionid_login(org_name, username, password, orgid, sandbox=False):
    global monitor_file
    session_id, sf_instance = None, None

    retry = 0
    try:
        threshold = int(base_config['monitor']['retry_threshold'])
        timeout = int(base_config['monitor']['timeout'])
        monitor_file = str(base_config['monitor']['file'])
    except Exception, e:  
        log.error(repr(e) +': cannot extract monitor parameters to process org %s' % org_name, exc_info=1)
        raise

    while retry < threshold:
        try:
            session_id, sf_instance = simple_salesforce.SalesforceLogin(username=username,
                                                                        password=password,
                                                                        organizationId=orgid, 
                                                                        sandbox=sandbox, 
                                                                        sf_version='31.0')
            # if we get valid results, break out of loop
            if session_id and sf_instance:
                break
        except simple_salesforce.SalesforceAuthenticationFailed, e:

            error_str = str(e)

            # retry only if timeout error (404)

            if '404' not in error_str:
                log.error(error_str + ': failed SOAP login for org %s; terminating' % org_name, exc_info=1)
                session_id, sf_instance = None, None
                break

            # timeout error, org may be down; increment counter wait
            log.error('%s: failed SOAP login for org %s. timeout caught; retry attempt: %i/%i. sleep: %is' 
                % (error_str, org_name, retry, threshold, timeout))

            retry += 1

            sleep(timeout)
            # incr timeout
            timeout += timeout

        except Exception, e:
            log.error(error_str + ': failed SOAP login for org %s' % org_name, exc_info=1)
            break

    if session_id:
        issued = datetime.now().strftime('%s')  
        # update monitor cfg
        try:
          mfg.add_section(org_name)
        except Exception, e:
          log.error('cannot update mfg with new org: %s' % org_name)
    else:
        issued = None
        session_id = None
        sf_instance = None
        log.error('Reached max threshold (%s) for org: %s' % (str(threshold), org_name))
    return session_id, sf_instance, issued


### Acquire Access Token

def token_login(username, password, client_id, client_secret,
                url = None,
                token = None, 
                sandbox = None):

    params = {'client_id': client_id,
     'client_secret': client_secret,
     'grant_type': 'password',
     'format': 'json',
     'password': password,
     #'password': password + str(token),
     'username': username}
    base = 'login' if not sandbox else 'test'
    my_url = 'https://' +base +'.salesforce.com/services/oauth2/token'
    
    return requests.post(url=my_url, params=params)


def get_header(token):
    return {'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token
#            'X-PrettyPrint': '1'
            }


#### Execute 

def run_sessionid_setup(org_name, my_org):
    # curl https://login.salesforce.com/services/oauth2/token -d "grant_type=password" -d "client_id=myclientid" -d "client_secret=myclientsecret"-d "username=mylogin@salesforce.com" -d "password=mypassword123456"

    username = my_org['user']
    password = my_org['pass']
    orgid = my_org['orgid']
    env = my_org['env']

    sessionid, instance, issued = sessionid_login(org_name = org_name,
                                                  username = username,
                                                  password = password,
                                                  orgid = orgid,
                                                  sandbox = (env == 'sandbox'))

    return sessionid, instance, issued

def run_token_setup(org_name, my_app):
    # curl https://login.salesforce.com/services/oauth2/token -d "grant_type=password" -d "client_id=myclientid" -d "client_secret=myclientsecret"-d "username=mylogin@salesforce.com" -d "password=mypassword123456"

    username = b.b64decode(my_app['user'])
    password = b.b64decode(my_app['pass'])
    client_id = b.b64decode(my_app['client_id'])
    client_secret = b.b64decode(my_app['client_secret'])
    env = b.b64decode(my_app['env'])


    rsp = token_login(username = username, password = password,
                      client_id = client_id, client_secret = client_secret,
                      sandbox = env)

    if rsp.status_code > 300:
        raise RuntimeError('REST token generation pull down failed for %s: ' %org_name +rsp.text)

    packet = rsp.json()

    instance = packet['instance_url']
    issued = packet['issued_at']
    token = packet['access_token']

    log.debug('Success! Packet info:\n\tinstance:\t%s\n\tissued:\t\t%s\n\ttoken:\t\t%s' % (instance, issued, token) )

    if (verbose):
        pp.pprint(header)

    return token, instance, issued

# write/update file
def write_config(dest):

    if verbose:
        config_dump()
        pass

    try:
        wp = open(dest, 'w')
        config_encode(cfg)
        cfg.write(wp)
        wp.close()

        log.info('Success! Wrote encoded configs to file: %s; exiting' % dest)
    except Exception, e:
        log.error('Fail: Cannot write encoded config to file: %s. %s' % (dest, str(e)))

#### Build Log Query

"""key parameters:
    version={29.0, 30.0, 31.0}
    last_days={1..}
    dest_folder=<path>
"""

if (testing):
    version = '31.0'
    last_days = 100
    
# build SOQL query for use
def get_query(instance, days):
    #https://${instance}.salesforce.com/services/data/v31.0/query?q=Select+Id+,+EventType+,+LogDate+From+EventLogFile+Where+LogDate+=+${day}

    #query = 'Select+Id+,+EventType+,+LogDate+From+EventLogFile+Where+LogDate+=+Last_n_Days:{last_days}'
    query = 'Select Id , EventType , LogDate From EventLogFile Where LogDate = Last_n_Days:{last_days}'
    query = query.format(last_days = days)
    base_url = 'https://{instance}/services/data/v{version}/query'
    base_url = base_url.format(instance = instance, version = version, query = query)
    params = {'q': query}
    
    return base_url, params

# 
def clean_up_creds_cfg(section):
    if not cfg.has_section(section):
        log.error('section %s not found in config; cannot remove' % section)

    if cfg.has_option(section, 'token'):
        cfg.remove_option(section, 'token')

    if cfg.has_option(section, 'sessionid'):
        cfg.remove_option(section, 'sessionid')

    if cfg.has_option(section, 'issued'):
        cfg.remove_option(section, 'issued')

def configure_session_auth(org_name, login):
    check_time = int(datetime.now().strftime('%s'))
    
    org = org_list[org_name]
    # if the current session id is invalid or expired (> 24h), update
    if 'issued' not in org or (check_time - int(org['issued'])) >= 86400:
        if login == 'soap':

            # error handling for getting the sessionid is run at the libracy call
            session_id, sf_instance, issued = run_sessionid_setup(org_name, org)

            # wasn't able to pull new session id, expired anyways, so remove from config                
            if not session_id:
                clean_up_creds_cfg(section=org_name)
                #continue
            org_list[org_name]['sessionid'] = b.b64encode(str(session_id))
            cfg.set(org_name, 'sessionid', org_list[org_name]['sessionid'])

        elif login == 'rest':
            token, sf_instance, issued = run_token_setup(org_name, org)
            org_list[org_name]['token'] = b.b64encode(str(token))
            cfg.set(org_name, 'token', org_list[org_name]['token'])

        if not sf_instance or not issued:
            log.error('how did you get this far?? should\'ve been skipped')
            #continue

        org_list[org_name]['sf_instance'] = str(sf_instance)
        org_list[org_name]['issued'] = str(issued)

        cfg.set(org_name, 'sf_instance', org_list[org_name]['sf_instance'])
        cfg.set(org_name, 'issued', org_list[org_name]['issued'])


'''validates sessionid/token within 24
    caveat: timeout/ttl for sessionid/token depends on org. may need to update.
'''
def pass_org_check(org_name):
    org = org_list[org_name]

    if ('sessionid' in org and org['sessionid'] != 'None') or \
        ('token' in org and org['token'] != 'None'):        
        return True

    if 'sessionid' not in org and 'token' not in org:
        log.error('org %s does not have any valid keys to access API' % org_name, exc_info=1)
        return False

    if ('sf_instance' in org and org['sf_instance'] != 'None'):
        return False

    check_time = int(datetime.now().strftime('%s'))

    return 'issued' in org and (check_time - int(org['issued'])) < 86400


#### Extract the records

#### Build list properties

def check_dir(dir_path):
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)
        # flags for newly created. if there's an error, remove
        dir_create_flag = True

'''metadata to collect and save eventlogs'''
def build_record_info(org_name, record):
    
    if record['attributes']['type'] != 'EventLogFile':
        print 'Not a log type:\t%s' % record['attributes']['type']
        return {}
    r = {}
    r['org_name'] = org_name
    r['id'] = record['Id']
    r['date'] = record['LogDate'].split('T')[0]
    r['base_url'] = 'https://' +org_list[org_name]['sf_instance']
    r['url'] = record['attributes']['url'] +'/LogFile'
    r['type'] = record['EventType']

    r['dest_folder'] = 'logs.'+r['date']
    file_path = '{parent}/{dest_folder}/{log_type}.{date}.{id}.log'
    r['file_path'] = file_path.format(parent=org_name,
                                      dest_folder=r['dest_folder'],
                                      log_type=r['type'], 
                                      id=r['id'],
                                      date=r['date'])

    return r

''' dry run of configs to build the file '''
def print_results(result):
    records = result['records']

    log_list = []
    for r in records:
        x = build_record_info(r)
        log_list.append(x)
        print x

''' overwrite existing files; in case need to replace 
    error handling (for the get request):
        expired sessionid
        timeout (to service or query taking too long)

    else:
        mark/log for missed
        # future: process
'''
def process_record(org_name, record, header):
    global errors
    dest_filename = args.dest_folder +'/' +record['file_path']
    base_url = record['base_url'] +record['url']

    timer_start = datetime.now()

    try:
        threshold = int(base_config['monitor']['retry_threshold'])
        timeout = int(base_config['monitor']['timeout'])
    except Exception, e:
        log.error(repr(e) +': cannot extract monitor parameters to process org %s' % org_name, exc_info=1)

    retry = 0
    while retry < threshold:
        try:
            req= requests.get(base_url, headers=header, stream=True)

            if req.ok:
                break

            else:
                bad = qres.json()[0]
                #raise RuntimeError(': '.join("%s=%r" % (str(k), str(v)) for k,v in bad.items())) 

                errorCode = str(bad['errorCode'])
                message = str(bad['message'])

                # get new session id and retry
                if 'INVALID_SESSION_ID' in errorCode:
                    # session expired; init header/get sessionid
                    log.error('%s => %s: error retrieving log file. org: %s log_type: %s id: %s reason: sessionid expired; retry attempt: %i/%i. resetting retry.'
                        % (errorCode, message, org_name, record['type'], record['id'], retry, threshold))

                    configure_session_auth(org_name=org_name, login=login)

                    # build header info
                    url, header, params = build_header_info(org_name=org_name)

                    retry = 0

                elif 'QUERY_TIMEOUT' in errorCode:
                    # timeout error, org may be down; increment counter wait
                    log.error('%s => %s: error retrieving log file. org: %s log_type: %s id: %s reason: timeout caught; retry attempt: %i/%i. sleep: %is'
                        % (errorCode, message, org_name, record['type'], record['id'], retry, threshold, timeout))

                    retry += 1

                    sleep(timeout)
                    # incr timeout
                    timeout += timeout

                # other
                else:
                    error_str = '%s => %s: error retrieving log file. org: %s. something bad happened; retry attempt: %i/%i. stopping collection for this file.' \
                        % (errorCode, message, org_name, retry, threshold, timeout)
                    log.exception(error_str)
                    return [error_str]


        except (requests.ConnectionError, requests.HTTPError), e:
            log.error(repr(e) +': cannot extract Org API CSV log. org: %s\tlog_type: %s' 
                % (org_name, record['type']), exc_info=1)

            retry += 1
    
    # if unsuccessful, 
    if not req.ok:
        error_str = 'error retrieving log file. org: %s log_type: %s id: %s reason: %r' \
            % (org_name, record['type'], record['id'], repr(req.reason))
        #log.error(error_str)
        return [error_str]

    # make sure destination folder is legit
    check_dir(os.path.dirname(dest_filename))

    if os.path.isfile(dest_filename):
        log.warning('Warning: file %s already exists; overwriting' % dest_filename)
        
    with open(dest_filename, 'wb') as f:
        # for chunk in req.iter_content(chunk_size=2024):
        for line in req.iter_lines(chunk_size=2048):
            if line:
                try:    # for thread synchronization
                    sh.acquire()
                    line = line.replace("'", "")                    

                    try:
                        # send out to log collector
                        syslog.info('%r\n' % (line))
                    except Exception, e:
                        errors.append('error sending log via syslog. org: %s log_type: %s: id: %s reason: %r' 
                            % (org_name, record['type'], record['id'], repr(e)))
                    try:
                        f.write(line +'\n')
                    except Exception, e:
                        errors.append('error writing log locally. org: %s log_type: %s: id: %s reason: %r' 
                            % (org_name, record['type'], record['id'], repr(e)))
                    finally:
                        f.flush()
                finally:
                    sh.release()

    timer_finish = datetime.now()
    d = timer_finish - timer_start
    log.info("Saved to: %s. duration=%s.%s sec" % (dest_filename, d.seconds, d.microseconds))

    # return condensed list if any
    return set(errors)

''' send files over syslog 
    #unused
'''
def syslog_file(record):
    dest_filename = args.dest_folder +'/' +record['file_path']
    
    timer_start = datetime.now()
    try:
        with open(dest_filename, 'r') as f:
            for line in f.readline():
                try:
                    sh.acquire()
                    line = line.replace("'", "")                    
                    # write to local log file and send to syslog
                    syslog.info('%r' % line)
                finally:
                    sh.release()
    except Exception, e:
        log.error(str(e))
        raise
    finally:
        timer_finish = datetime.now()
        d = timer_finish - timer_start
        log.info("Saved to: %s. duration=%s.%s sec" % (dest_filename, d.seconds, d.microseconds))

# build header info to make API calls
def build_header_info(org_name, login, days):
    url, header, params = None, None, None

    if not pass_org_check(org_name):
        log.info("org: %s didn't pass check" % org_name)
        return url, header, params

    org = org_list[org_name]

    # get header
    header_key = org['sessionid'] if login == 'soap' else org['token']

    # remember to decode header key
    header_key = b.b64decode(header_key)
    header = get_header(header_key)

    # get config info
    url, params = get_query(org['sf_instance'], days)

    log.debug('org: %s\turl: %s\tparams: %r' % (org_name, url, params))

    mfg.set(org_name, 'status', 'building header info')

    return url, header, params

'''
# orgs => list of at least 1 org
# login => method of login: REST or SOAP
# days => # of days back to collect logs

error handling:
    expired sessionid
    timeout (to service or query taking too long)

else:
    return / skip log collection against org

changing format: 
old: all sessionids then all logs
new: sessionid then logs per org
'''
def run_log_collect(org_name, login, days):
    timer_start = datetime.now()

    # init header/get sessionid
    configure_session_auth(org_name=org_name, login=login)

    # build header info
    url, header, params = build_header_info(org_name=org_name, login=login, days=days)

    retry = 0
    result = None
    try:
        threshold = int(base_config['monitor']['retry_threshold'])
        timeout = int(base_config['monitor']['timeout'])        
    except Exception, e:
        log.exception(repr(e) +': cannot extract monitor parameters to process org %s' % org_name, exc_info=1)
        return

    ''' query for last X days of event logs '''

    ''' Error handling:
        INVALID_SESSION_ID
            action: get new sessionid
        QUERY_TIMEOUT
            action: wait and retry
        else
            action: stop log collection process for org
    '''
    while retry < threshold:
        qres = requests.get(url, headers=header, params=params)
        mfg.set(org_name, 'status', 'querying for logs')
            
        ''' sample error:
            RuntimeError: errorCode='INVALID_SESSION_ID': message='Session expired or invalid'
        '''

        try:
            if not qres.ok:
                bad = qres.json()[0]
                #raise RuntimeError(': '.join("%s=%r" % (str(k), str(v)) for k,v in bad.items())) 

                errorCode = str(bad['errorCode'])
                message = str(bad['message'])

                # get new session id and retry
                if 'INVALID_SESSION_ID' in errorCode:
                    # init header/get sessionid
                    log.error('%s => %s: exec SOQL query for org %s. sessionid expired; retry attempt: %i/%i. resetting retry.'
                        % (errorCode, message, org_name, retry, threshold))

                    configure_session_auth(org_name=org_name, login=login)

                    # build header info
                    url, header, params = build_header_info(org_name=org_name)

                    retry = 0

                elif 'QUERY_TIMEOUT' in errorCode:
                    # timeout error, org may be down; increment counter wait
                    log.error('%s => %s: exec SOQL query for org %s. timeout caught; retry attempt: %i/%i. sleep: %is'
                        % (errorCode, message, org_name, retry, threshold, timeout))

                    retry += 1

                    sleep(timeout)
                    # incr timeout
                    timeout += timeout

                # other
                else:
                    log.exception('%s => %s: exec SOQL query for org %s. something bad happened; retry attempt: %i/%i. sleep: %is'
                        % (errorCode, message, org_name, retry, threshold, timeout))
                    return

            # SOQL exec successful
            elif qres.ok:
                result = qres.json()
                log.debug('%s => exec SOQL query for org %s. status: %s, total records: %s. retry attempt: %i/%i. sleep: %is. #success!'
                    % (str(qres.status_code), org_name, str(result['done']), str(result['totalSize']), retry, threshold, timeout))
                break
        except Exception, e:
            log.exception('%s => %r: exec SOQL query for org %s. something bad happened; retry attempt: %i/%i.'
                        % (str(qres.status_code), repr(e), org_name, retry, threshold))
            return


    if result['totalSize'] < 1:
        log.warning('No entries to pull for org: %s' %org_name)
        
    records = result['records']
    log.debug('ALL RECORDS: (count: %i) %r' % (len(records), records))

    '''extract logs from org'''
    log_list = []
    for r in records:
        x = build_record_info(org_name, r)
        log.debug('Record: %r\trecord info: %r' % (r,x))
        log_list.append(x)

    # check monitor file
    errors = []
    for record in log_list:
        # update mfg
        mfg.set(org_name, 'record', '%s.%s' % (str(record['type']), str(record['date'])))

        # process the record and returns set of error strings
        errors += process_record(org_name, record, header)

    errors = set(errors)

    # shoot a summary email of errors for this org
    if errors:
        log.error('Summary:\n\tErrors found for org: %s\n' % org_name + '\n'.join(map(str, errors)))

        # update mfg
        mfg.set(org_name, 'errors', '%s' % ('|'.join(map(str, errors))))

    timer_finish = datetime.now()
    d = timer_finish - timer_start
    log.info("Org: %s record_count=%d duration=%s.%s sec" % (org_name, len(records), d.seconds, d.microseconds))

def main (argv):
    global args, start_time

    start_time = datetime.now()
    try:
        parser = argparse.ArgumentParser(description='Execute log extraction from Salesforce API',
          epilog = 'usage (with options): api.app.logs.py <settings file> -creds <file> -w <file> \
                    -recovery <file> \
                    [-login {rest|soap}] [-dest_folder <path>] \
                    [-org {all|<org name>}] [-app {all| <org name>}] \
                    [-days {2..86400}] \
                    [-console]')

        parser.add_argument('file', help='specify base config file')
        parser.add_argument('-creds', required=True, help='specify credentials file')
        parser.add_argument('-write', '-w', default=False, help='specify dest to write encoded config file')
        parser.add_argument('-recovery', '-r', help='specify dest to write file to save in case of failure')

        parser.add_argument('-login', '-l', nargs='?', default='soap', help='login method')

        # default is current location
        parser.add_argument('-dest_folder', nargs='?', default='.', help='name of parent destination folder')

        parser.add_argument('-org', '-o', nargs='?', default='all', help='org name')
        parser.add_argument('-app', '-a', nargs='?', default=None, help='app name')

        parser.add_argument('-days', nargs=1, default=None, help='days of logs')
        
        
        parser.add_argument('-console', action='store_true', default=False)
        parser.add_argument('-v', action='store_true', default=False)
        
        #pdb.set_trace()
        args = parser.parse_args()       

    except argparse.ArgumentError, e:
        log.error(repr(e),exc_info=1)
        raise
        sys.exit(2)

    # init logging settings
    init_settings(args.file)

    # init lib dependencies
    init_libs()

    # validate settings and creds files
    try:
      validate_config(args.creds, args.write)
    except Exception, e:
      log.error('errors: %r' % repr(e))

    log.debug('Initiating program at: %s' % start_time.strftime('%m/%d/%Y %H:%M:%S.%f'))

    signal.signal(signal.SIGHUP, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # signal cannot be caught
    #signal.signal(signal.SIGTERM, signal_term_handler)
    
    try:
        if args.console:
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)
            log.addHandler(ch)

        if args.v:
            verbose = True

        # if write, validate file
        if args.write:
            check_file(args.write, True)
            write_config(dest=args.write)
            sys.exit()
        # if write not specified, days is mandatory
        elif args.days == None:
            log.error('days field mandatory if not writing a new encoded file')
            sys.exit()

        if args.recovery:
            check_recovery_file(args.recovery)

        if args.login != 'rest' and args.login != 'soap':
            raise Exception('invalid login method. use rest or soap')

        # check/validate destination path
        if args.dest_folder:
            check_dir(args.dest_folder)

    except Exception, e:
        log.error(repr(e),exc_info=1)
    
    rest = (args.login == 'rest')

    days = int(args.days[0])
    login = args.login            
    org = 'all' if args.org is None and args.app is None else args.org
    
    try:
        # hard coding for org (not app) access for now
        log.info('attempting to collect %s days of logs from %s' % (days, org))
        # all orgs is specified, extract just orgs
        if 'all' == org:
            for s in cfg.sections():
                # don't forget; these are encoded
                if cfg.has_option(s, 'type') and b.b64decode(cfg.get(s,'type')) == 'org':
                    error_str, org_temp = extract_org(s, rest)
                    if error_str:
                        log.error('cannot complete config read <%s>; skipping section' % error_str)
                        break
                    # append only if something was returned
                    if org_temp:
                        org_list[s] = org_temp 
                        extract_configs(rest, s, args.app)

        # specify only one org to extract from
        else:
            try:
                if org not in cfg.sections():
                    log.error('org %s not configured' % org)
                    raise
            except:
                pass
            # don't forget; these are encoded
            if (b.b64decode(cfg.get(org,'type')) == 'org'):
                error_str, org_temp = extract_org(org, check_rest)
                if error_str:
                    log.error('cannot complete config read <%s>; skipping section' % error_str)
                    raise
                # append only if something was returned
                if org_temp:
                    org_list[org] = org_temp 
                    extract_configs(rest, org, args.app)

    except Exception, e:
        log.error('Failed to extract creds. %s' % repr(e))
        exit 

    if days < 2:
        log.error('invalid integer <%s>. specify 2-8 days due to data sync for logs.' % str(days),exc_info=1)
        exit
    
    try:
        org_collect = []
        if org == 'all' or org is None:
            org_collect = sorted(org_list.keys())
        else:
            org_collect.append(org)

        log.info('Getting logs for: ' 
                 +','.join(map(str,org_collect)) 
                 + '. method: %s' % login
                 +'. days collect: %i' % days)
        
        for o in org_collect:            
            run_log_collect(org_name=o, login=login, days=days)
            final_time = datetime.now()

            time_org = final_time.strftime('%m/%d/%Y %H:%M:%S.%f')
            mfg.set(s, 'last_run', time_org)
            log.debug('marking org %s run at: %s' % (o, time_org))

    except Exception, e:
        log.error(repr(e),exc_info=1)

        # only removes if empty anyways
        if dir_create_flag:
            os.rmdir(args.dest_folder)
        raise

    finally:
        final_time = datetime.now()
        delta = final_time - start_time
        log.debug('Finalizing program at: %s\tTotal duration: %s.%s sec' 
            % (final_time.strftime('%m/%d/%Y %H:%M:%S.%f'), delta.seconds, delta.microseconds))

 
if __name__ == "__main__":
  try:
    main(sys.argv)
  except KeyboardInterrupt:
    print "testing quit"
    log.debug( "testing quit: %r" % repr(cfg))
    # save monitor stuff first 
    sys.exit()


