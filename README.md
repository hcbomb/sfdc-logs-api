Salesforce API Log Collection
======


USAGE: 
\>api.app.logs.py \<file\> -write -w \<file\> [-login {rest|soap}]
[-dest_folder \<path\>] [-org {all|\<org name\>}] [-app {all| \<org name\>}] [-days
{1..7}] [-console]

Example:
\>**api.app.logs.py** *.creds.enc* *-days 1* -v -dest_folder /opt/logs -console

Format of the raw credentials file should at the minimum look like this:

\[\<org name\>\]

type = org

env = production

user = \<user name\>

pass = \<password\>

orgId = \<some org id\>


Format of encoded credentials file will look similar to this:

\[\<org name\>\]

type = \<b64 encrypted type\>

env = \<b64 encrypted env\>

user = \<b64 encrypted username\>

pass = \<b64 encrypted password\>

orgid = \<b64 encrypted org id\>
