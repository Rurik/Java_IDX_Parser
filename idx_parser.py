# Java Cache IDX parser
# Version 1.0 - 12 Jan 13 - @bbaskin
# Views cached Java download history files
# Typically located in %AppData%\LocalLow\Sun\Java\Deployment\Cache
# These files hold critical details for malware infections, especially
# Java related ones, e.g. BlackHole.

#Output example:
#IDX file: 1c20de82-1678cc50.idx
#URL: hxxp://80d3c146d3.gshjsewsf.su:82/forum/dare.php?hsh=6&key=b30a14e1c597bd7215d593d3f03bd1ab
#IP: 50.7.219.70
#File Size: 7162
#Type: application/x-java-archive
#Server Date: Mon, 26 Jul 2001 05:00:00 GMT
#Server type: nginx/1.0.15
#Download date: Sun, 13 Jan 2013 16:22:01 GMT

## This is very quick and ugly code, not very pythonistic
## I struggle with Python's lack of a 'struct', so just did this manually
## The IDX file structure is very ugly as well, mixing between C-strings (null term)
## and Pascal strings (len-prefixed), as well as both DWORD and WORD length fields. Ugh.
import sys
import struct
	
print "Java IDX Parser -- version 1.0 -- by @bbaskin"
print ""

try:
	fname = sys.argv[1]
except:
	print "Usage: idx_parser.py <filename>"
	quit()
	
try:	
	data = open(fname, 'rb').read()
except:
	print "File not found: %s" % fname
	quit()
	
header = data[0:8].encode("hex")
if header != "00000000025d0000":
	print "Invalid IDX header found"
	print "Found:    0x%s" % header
	print "Expected: 0x00000000025d0000"
	quit()

offset = data.find('http') - 1
if offset < 0:
	print "HTTP URL not found!"
	quit()
len_URL = ord(data[offset])+1
data_URL = data[offset+1:offset+len_URL]

#This is ugly, sorry. I should likely have done it with 
#dictionary or list appends.

offset += len_URL
len_IP = struct.unpack(">l", data[offset:offset+4])[0]
offset += 4
data_IP = data[offset:offset+len_IP]
offset += len_IP
data_unk1 = struct.unpack(">l", data[offset:offset+4])[0]
offset += 4

len_unk2 = struct.unpack(">h", data[offset:offset+2])[0]
offset += 2
data_unk2 = data[offset:offset+len_unk2]
offset += len_unk2

len_httpstatus = struct.unpack(">h", data[offset:offset+2])[0]
offset += 2
data_httpstatus = data[offset:offset+len_httpstatus]
offset += len_httpstatus

len_contentlenhdr = struct.unpack(">h", data[offset:offset+2])[0]
offset += 2
data_contentlenhdr = data[offset:offset+len_contentlenhdr]
offset += len_contentlenhdr

len_contentlen = struct.unpack(">h", data[offset:offset+2])[0]
offset += 2
data_contentlen = data[offset:offset+len_contentlen]
offset += len_contentlen

len_modifiedhdr = struct.unpack(">h", data[offset:offset+2])[0]
offset += 2
data_modifiedhdr = data[offset:offset+len_modifiedhdr]
offset += len_modifiedhdr

len_modified = struct.unpack(">h", data[offset:offset+2])[0]
offset += 2
data_modified = data[offset:offset+len_modified]
offset += len_modified

len_typehdr = struct.unpack(">h", data[offset:offset+2])[0]
offset += 2
data_typehdr = data[offset:offset+len_typehdr]
offset += len_typehdr

len_type = struct.unpack(">h", data[offset:offset+2])[0]
offset += 2
data_type = data[offset:offset+len_type]
offset += len_type

len_datehdr = struct.unpack(">h", data[offset:offset+2])[0]
offset += 2
data_datehdr = data[offset:offset+len_datehdr]
offset += len_datehdr

len_date = struct.unpack(">h", data[offset:offset+2])[0]
offset += 2
data_date = data[offset:offset+len_date]
offset += len_date

len_serverhdr = struct.unpack(">h", data[offset:offset+2])[0]
offset += 2
data_serverhdr = data[offset:offset+len_serverhdr]
offset += len_serverhdr

len_server = struct.unpack(">h", data[offset:offset+2])[0]
offset += 2
data_server = data[offset:offset+len_server]
offset += len_server

# Print results
print "IDX file: %s" % fname
print "URL: %s" % (data_URL)
print "IP: %s" % (data_IP)
print "File Size: %s" % (data_contentlen)
print "Type: %s" % (data_type)
print "Server Date: %s" % (data_modified)
print "Server type: %s" % (data_server)
print "Download date: %s" % (data_date)
