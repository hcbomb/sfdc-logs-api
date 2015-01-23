#!/bin/bash

# process api log collection script
# author: henry canivel

# validate input; only input should be integer referring to # days back we can collect
# max: 7 default: 2
days=2

if [ -z "$1" ] || [ "$1" -ge 1 ]; then
  days=$1
fi

creds='.creds.enc'
dest='/log/org.log.collect/logs'

# activate venv
source ~/venv/bin/activate

# navigate to scripts folder
cd /log/org.log.collect/scripts

python api.app.logs.py settings.cfg -creds .creds.enc.org62 -days $days -dest_folder $dest &
python api.app.logs.py settings.cfg -creds .creds.enc.tz -days $days -dest_folder $dest &

