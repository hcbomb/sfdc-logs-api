#!/usr/bin/python

import ConfigParser
import base64 as b
import json
import pprint
import re
import sys
import os
import pdb
import socket
import logging
from logging.handlers import TimedRotatingFileHandler as TimedRotatingFileHandler
from logging.handlers import SysLogHandler 
from datetime import datetime

# File: 
# Author: Henry Canivel

# init loggers
log = logging.getLogger('sfdc_log_internal')
log.setLevel(logging.DEBUG)
fh = TimedRotatingFileHandler('sfdc.api.getlogs.log', when='d', interval=4, backupCount=14)
fh.setLevel(logging.DEBUG)

ch = logging.handlers.SysLogHandler(address=('sfm-sec-splk-hf-lp2', 518), facility=logging.handlers.SysLogHandler.LOG_NOTICE)
ch.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s %(name)s[%(process)d]: log_level=%(levelname)s function=%(funcName)s line:%(lineno)d message="%(message)s"',
                              datefmt='%m/%d/%YT%H:%M:%S%z')
chformat = logging.Formatter('%(name)s[%(process)d]: log_level=%(levelname)s function=%(funcName)s line:%(lineno)d %(message)s')

fh.setFormatter(formatter)
ch.setFormatter(chformat)
log.addHandler(fh)
log.addHandler(ch)

# init syslog
syslog = logging.getLogger('sfdc_log')
syslog.setLevel(logging.INFO)
sh = logging.handlers.SysLogHandler(address=('sfm-sec-splk-hf-lp2', 518), facility=logging.handlers.SysLogHandler.LOG_NOTICE)
#sh = logging.handlers.SysLogHandler(address=('localhost', 514), facility=logging.handlers.SysLogHandler.LOG_NOTICE)
sysformat = logging.Formatter('%(name)s[%(process)d]: %(message)s')
sh.setFormatter(sysformat)
sh.createLock()
syslog.addHandler(sh)

# separate logger to send app logs over syslog

try:
    import argparse
    import simple_salesforce
    import requests
except ImportError:
    log.exception('Missing module <%s>; please install using: "pip install %s"'
                  % ('simple_salesforce', 'simple_salesforce'))
    exit

pp = pprint.PrettyPrinter(indent=2)
verbose = False
testing = True
org_list = {}
app_list = {}
org_collect = None
args = None
dir_create_flag = False
start_time = None

# init cfg operations
cfg = ConfigParser.SafeConfigParser()
fp = None

def config_dump():
    for s in cfg.sections():
        print 'section: %s' % s
        for o in cfg.options(s):
            print '\t%s => %s' % (o, cfg.get(s,o))

# default: read file
def check_file(file_path, write_true=False):
    if os.path.exists(file_path):
        if write_true:
            log.warning('File: %s already exists. Overwriting' % file_path)
        else:
            log.debug('Attempting to read file %s' % file_path)
    # if file does not exist and attempting to read, error
    elif not write_true:
        raise RuntimeError('File: %s does not exist; please validate' % file_path)

def validate_config(file_path, write_true=False):
    try:
        check_file(file_path, write_true)
        fp = cfg.read(file_path)
    except Exception, e:
        log.error(e,exc_info=1)
        raise RuntimeError('config file %s invalid; please validate' % file_path)
  
    if not cfg.sections():
        log.error('No sections to defined in config file %s' % file_path,exc_info=1)
    for s in cfg.sections():
        user_check = False
        pass_check = False
        id_check = False
        secret_check = False
        stype = None
        
        try:
            stype = b.b64decode(cfg.get(s,'type'))
        except:
            log.warning('no type specified for section %s' % s)
            continue

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


def extract_configs(check_rest, org=None, app=None):
    if org:
        # all orgs is specified, extract just orgs
        if 'all' == org:
            for s in cfg.sections():
                # don't forget; these are encoded
                if (b.b64decode(cfg.get(s,'type')) == 'org'):
                    error_str, org_temp = extract_org(s, check_rest)
                    if error_str:
                        log.error('cannot complete config read <%s>; terminating' % error_str)
                        break
                    # append only if something was returned
                    if org_temp:
                        org_list[s] = org_temp 
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


### Acquire Session ID

def sessionid_login(org_name, username, password, orgid, sandbox=False):
    session_id, sf_instance = None, None
    try:
        session_id, sf_instance = simple_salesforce.SalesforceLogin(username=username,
                                                                    password=password,
                                                                    organizationId=orgid, 
                                                                    sandbox=sandbox, 
                                                                    sf_version='31.0')
    except Exception, e:
        log.error(repr(e) + ': failed SOAP login for org %s' % org_name, exc_info=1)
    issued=datetime.now().strftime('%s') if session_id else None
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
def update_config(w=None):

    if verbose:
        config_dump()
        pass

    #pp.pprint(app_list)
    #pp.pprint(org_list)

    if w:
        wp = open(w, 'wb')
        cfg.write(wp)
        wp.close()

#### Build Log Query

"""key parameters:
    version={29.0, 30.0, 31.0}
    last_days={1..}
    dest_folder=<path>
"""

if (testing):
    version = '31.0'
    last_days = 100
    

def get_query(instance, days):
    #https://${instance}.salesforce.com/services/data/v31.0/query?q=Select+Id+,+EventType+,+LogDate+From+EventLogFile+Where+LogDate+=+${day}

    #query = 'Select+Id+,+EventType+,+LogDate+From+EventLogFile+Where+LogDate+=+Last_n_Days:{last_days}'
    query = 'Select Id , EventType , LogDate From EventLogFile Where LogDate = Last_n_Days:{last_days}'
    query = query.format(last_days = days)
    base_url = 'https://{instance}/services/data/v{version}/query'
    base_url = base_url.format(instance = instance, version = version, query = query)
    params = {'q': query}
    
    return base_url, params

def run_query():
    #https://${instance}.salesforce.com/services/data/v31.0/query?q=Select+Id+,+EventType+,+LogDate+From+EventLogFile+Where+LogDate+=+${day}

    #query = 'Select+Id+,+EventType+,+LogDate+From+EventLogFile+Where+LogDate+=+Last_n_Days:{last_days}'
    query = 'Select Id , EventType , LogDate From EventLogFile Where LogDate = Last_n_Days:{last_days}'
    query = query.format(last_days = last_days)
    base_url = '{instance}/services/data/v{version}/query'
    base_url = base_url.format(instance = instance, version = version, query = query)
    params = {'q': query}

    print 'base_url:\t%s\nparams:\t%s' % (base_url, params)

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

def run_log_init_check(orgs, login):
    check_time = int(datetime.now().strftime('%s'))
    
    for org_name in orgs:
        org = org_list[org_name]
        try:
            # if the current session id is invalid or expired (> 24h), update
            if 'issued' not in org or (check_time - int(org['issued'])) >= 86400:
                if login == 'soap':
                    session_id, sf_instance, issued = run_sessionid_setup(org_name, org)

                    # wasn't able to pull new session id, expired anyways, so remove from config                
                    if not session_id:
                        clean_up_creds_cfg(section=org_name)
                        continue
                    org_list[org_name]['sessionid'] = b.b64encode(str(session_id))
                    cfg.set(org_name, 'sessionid', org_list[org_name]['sessionid'])

                elif login == 'rest':
                    token, sf_instance, issued = run_token_setup(org_name, org)
                    org_list[org_name]['token'] = b.b64encode(str(token))
                    cfg.set(org_name, 'token', org_list[org_name]['token'])

                if not sf_instance or not issued:
                    log.error('how did you get this far?? should\'ve been skipped')
                    continue

                org_list[org_name]['sf_instance'] = str(sf_instance)
                org_list[org_name]['issued'] = str(issued)

                cfg.set(org_name, 'sf_instance', org_list[org_name]['sf_instance'])
                cfg.set(org_name, 'issued', org_list[org_name]['issued'])

        # don't crash program if only one org fails
        except Exception, e:
            log.error(repr(e) +': init failed for org %s' % org_name, exc_info=1)


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

# dry run of configs to build the file
def print_results(result):
    records = result['records']

    log_list = []
    for r in records:
        x = build_record_info(r)
        log_list.append(x)
        print x

# overwrite existing files; in case need to replace
def download_file(record, header):
    dest_filename = args.dest_folder +'/' +record['file_path']
    base_url = record['base_url'] +record['url']

    timer_start = datetime.now()
    req= requests.get(base_url, headers=header, stream=True)
    
    # make sure destination folder is legit
    check_dir(os.path.dirname(dest_filename))

    if os.path.isfile(dest_filename):
        log.warning('Warning: file %s already exists; overwriting' % dest_filename)
        
    if not req.ok:
        print 'Ouch. something went wrong with: %r' % record
        return False
    
    try:
        with open(dest_filename, 'wb') as f:
    #        for chunk in r.iter_content(chunk_size=1024):
            for line in req.iter_lines(chunk_size=2048):
                if line:
                    try:
                        sh.acquire()
                        # write to local log file and send to syslog
                        syslog.info('log=%s %r' % (record['type'], line))
                        f.write(line)
                        f.flush()
                    finally:
                        sh.release()
    except Exception, e:
        log.error(str(e))
        raise
    finally:
        timer_finish = datetime.now()
        d = timer_finish - timer_start
        log.info("Saved to: %s. duration=%s.%s sec" % (dest_filename, d.seconds, d.microseconds))


# orgs => list of at least 1 org
# login => method of login: REST or SOAP
# days => # of days back to collect logs
def run_log_collect(orgs, login, days):
    for org_name in orgs:
        timer_start = datetime.now()
        org = org_list[org_name]

        if not pass_org_check(org_name):
            continue

        # get header
        header_key = org['sessionid'] if login == 'soap' else org['token']

        # remember to decode header key
        header_key = b.b64decode(header_key)
        header = get_header(header_key)
        url, params = get_query(org['sf_instance'], days)

        log.debug('url: %s\tparams: %r' % (url, params))
        
        qres = requests.get(url, headers=header, params=params)
        
        if qres.status_code > 200:
            log.error('Request failed: ' +qres.reason)
            
        result = qres.json()
        if not qres.ok:
            bad = qres.json()[0]
            raise RuntimeError(': '.join("%s=%r" % (str(k), str(v)) for k,v in bad.items())) 
        if result['totalSize'] < 1:
            log.warning('No entries to pull for org: %s' %org_name)
            
        records = result['records']
        log.debug('ALL RECORDS: %r' % records)

        log_list = []
        for r in records:
            x = build_record_info(org_name, r)
            log.debug('Record: %r\trecord info: %r' % (r,x))
            log_list.append(x)
            download_file(x, header)

        timer_finish = datetime.now()
        d = timer_finish - timer_start
        log.info("Org: %s record_count=%d duration=%s.%s sec" % (org_name, len(records), d.seconds, d.microseconds))

def main (argv):
    global args, start_time

    start_time = datetime.now()
    try:
        parser = argparse.ArgumentParser(description='Execute log extraction from Salesforce API',
          epilog = 'USAGE: api.app.logs.py <file> -write -w <file> \
                    [-login {rest|soap}] [-dest_folder <path>] \
                    [-org {all|<org name>}] [-app {all| <org name>}] \
                    [-days {1..7}] \
                    [-console]')

        parser.add_argument('file', help='specify base config file')
        parser.add_argument('-w', help='specify dest base config file')

        parser.add_argument('-write', action='store_true', default=False, help='write config destination specified. default read from config file')
        parser.add_argument('-login', '-l', nargs='?', default='soap', help='login method')

        # default is current location
        parser.add_argument('-dest_folder', nargs='?', default='.', help='name of parent destination folder')

        parser.add_argument('-org', '-o', nargs='?', default='all', help='org name')
        parser.add_argument('-app', '-a', nargs='?', default=None, help='app name')

        parser.add_argument('-days', nargs=1, required=True, default=1, help='days of logs')
        
        
        parser.add_argument('-console', action='store_true', default=False)
        parser.add_argument('-v', action='store_true', default=False)
        
        #pdb.set_trace()
        args = parser.parse_args()       

    except argparse.ArgumentError, e:
        log.error(repr(e),exc_info=1)
        raise
        sys.exit(2)

    log.debug('Initiating program at: %s' % start_time.strftime('%m/%d/%Y %H:%M:%S.%f'))
    
    # validate config
    validate_config(args.file, False)

    try:
        if args.console:
            log.addHandler(ch)

        if args.v:
            verbose = True

        # if write, validate file
        if args.write:
            check_file(args.w, True)

            #write_config(src=args.file, dest=args.write)
        if args.login != 'rest' and args.login != 'soap':
            raise Exception('invalid login method. use rest or soap')

        # check/validate destination path
        if args.dest_folder:
            check_dir(args.dest_folder)

    except Exception, e:
        log.error(repr(e),exc_info=1)

    rest = (args.login == 'rest')

    extract_configs(rest, args.org, args.app)

    days = int(args.days[0])
    login = args.login
            
    if not (0 < days and days <= 7):
        log.error('invalid integer <%s>. specify 1-7 days' % str(days),exc_info=1)
        return -1

    org = args.org 
    log.info('attempting to collect %s days of logs from %s' % (days, org))
    
    try:
        org_collect = []
        if org == 'all':
            org_collect = sorted(org_list.keys())
        else:
            org_collect.append(org)

        log.info('Getting logs for: ' 
                 +','.join(map(str,org_collect)) 
                 + '. method: %s' % login
                 +'. days collect: %i' % days)
        
        run_log_init_check(orgs=org_collect, login=login)
        update_config(args.w)

        run_log_collect(orgs=org_collect, login=login, days=days)

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
  main(sys.argv)


