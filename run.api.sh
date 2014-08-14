#!/bin/bash

# process api log collection script
# author: henry canivel

# validate input; only input should be integer referring to # days back we can collect
# max: 7 default: 2
days=2

if [[ -n "$1" ]] && [ $1 == [0-9]* ]; then
  days=$1
fi

creds='.creds.enc'
dest='/opt/splunk/sfm-sec-splk-hf-lp4/logs'

# activate venv
source ~/venv/bin/activate

# navigate to scripts folder
cd /opt/splunk/sfm-sec-splk-hf-lp4/scripts

python api.app.logs.py $creds -days $days -dest_folder $dest

