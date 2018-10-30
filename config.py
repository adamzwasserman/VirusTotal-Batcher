import os
import sys
from pathlib import Path

# VirusTotal Batch Machine Gun
version_info = (2, 0)
version = '.'.join(str(c) for c in version_info)

# ***General Params used by all (or any) modules****

debug = 0

# Server friendly. If 'yes' program will look for VTlookup.txt in this subdirectory of the user's home directory,
# and will save results to both the subdirectory of the user's home AND the same directory as the program file (with the
# user's username appended), MUST include the trailing forward slash. To store directly in home put "/".
server_friendly = 'no'

# If server_friendly = 'no', home_path is ignored
if server_friendly is 'yes':
    home_path = "/"
else:
    this_file = os.path.dirname(sys.argv[0])
    program_path = os.path.abspath(this_file)
    home_path = '/'.join(str(program_path).split('/')[:-1])

############################################################

# ***VirusTotal Specific Params****

#  VirusTotal API Key
api_key        = 'putkeyhere'

#  Time between requests (decricated parameter, leave at 0)
request_wait = 0

#  maximum time (in seconds) to wait for VT to respond before giving up (in case of the VT rate limiter kicking in)
max_wait = 1

# This sets the number of parallel VT lookups. Range is between 50-200.
process_pool_size = 50

# Set by the program DO NOT CHANGE
live_resolve = 'yes'
vt_auto_submit = 'yes'

############################################################

# ***Reno (live resolution) Specific Params****
reno_error_file_name = home_path+'/logs/Reno DNS Errors.txt'

# This sets the number of concurrent live resolutions. Range is between 30-100.
async_pool = 50

#What percentage of timeouts is acceptable in results (as a fraction. 10% is written as 0.1)
max_timeout_ratio = .1

# Resolution time out. Set to above 30 to get high accuracy. Less than 10 for speed. Do not go below 1.
reno_max_timeout_in_seconds = 4
reno_ns_timeout_in_seconds = 4
reno_overall_timeout = 60
run_reno_poolsize = 1

# reno_max_timeout_in_seconds = .15
# reno_ns_timeout_in_seconds = .15
# reno_overall_timeout = 1
# run_reno_poolsize = 100

# Hard limit on how many times to loop and retry batch of timed-out resolutions
max_resolution_retries = 5

riprova_max_retries = 1

riprova_retry_interval = 0.05


############################################################