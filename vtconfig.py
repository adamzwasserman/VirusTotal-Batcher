#  VTB 1.2.3 May 16, 2018

#  VirusTotal API Key
api_key        = '0000000000000000000000000000000000000000000000000000000000000000'

#  Time between requests (to try an not trigger the VT rate limiter)
request_wait = 0

#  maximum time (in seconds) to wait for VT to respond before giving up (in case of the VT rate limiter kicking in)
max_wait = 600

# Server friendly. If 'yes' program will look for VTlookup.txt in this subdirectory of the user's home directory,
# and will save results to both the subdirectroy of the user's home AND the same directory as the program file (with the
# user's username appended), MUST include the trailing forward slash. To store directly in home put "/".
server_friendly = 'no'
# If server_friendly = 'no', home_path is ignored
home_path = "/"
