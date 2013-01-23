# Java Cache IDX parser
# Version 1.0 - 12 Jan 13 - @bbaskin
# Version 1.1, now supports various IDX file versions
# *	Updates based off research by Mark Woan (@woanwave) - https://github.com/woanware/javaidx/tree/master/Documents
# * Research also produced by 
# * Static data is found in sections 3 and 4, but no idea on their values yet.

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
import os

print "Java IDX Parser -- version 1.1 -- by @bbaskin"
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

filesize = os.path.getsize(fname)
header = data.read(8)
cache_ver = struct.unpack(">h", header[4:6])[0]
if cache_ver not in (602, 603, 604, 605, 606):
	print "Invalid IDX header found"
	print "Found:    0x%s" % header
	quit()
print "IDX file: %s (IDX File Version %d.%02d)" % (fname, cache_ver / 100, cache_ver - 600)


#Parse meta data	
data.seek(7)
meta_jar_len1 = struct.unpack(">l", data.read(4))[0]

# Different IDX cache versions have data in different offsets
# See Mark Woan's breakdown at https://github.com/woanware/javaidx/tree/master/Documents
if cache_ver == 605:
	data.seek(36)
	sec2_len = struct.unpack(">l", data.read(4))[0]
	sec3_len = struct.unpack(">l", data.read(4))[0]
	sec4_len = struct.unpack(">l", data.read(4))[0]
	sec5_len = struct.unpack(">l", data.read(4))[0]
elif cache_ver in [603, 604]:
	data.seek(38)
	sec2_len = struct.unpack(">l", data.read(4))[0]
	sec3_len = struct.unpack(">l", data.read(4))[0]
	sec4_len = struct.unpack(">l", data.read(4))[0]
	sec5_len = struct.unpack(">l", data.read(4))[0]
elif cache_ver == 602:
	sec2_len = filesize - 0x80
else:
	sec3_len = 0
	sec4_len = 0
	sec5_len = 0
	

if sec2_len:
	data.seek (128)
	len_URL = struct.unpack(">l", data.read(4))[0]
	data_URL = data.read(len_URL)
	
	len_IP = struct.unpack(">l", data.read(4))[0]
	data_IP = data.read(len_IP)
	data_unk1 = struct.unpack(">l", data.read(4))[0]
	
	len_unk2 = struct.unpack(">h", data.read(2))[0]
	data_unk2 = data.read(len_unk2)
	
	len_httpstatus = struct.unpack(">h", data.read(2))[0]
	data_httpstatus = data.read(len_httpstatus)
	
	len_contentlenhdr = struct.unpack(">h", data.read(2))[0]
	data_contentlenhdr = data.read(len_contentlenhdr)
	
	len_contentlen = struct.unpack(">h", data.read(2))[0]
	data_contentlen = data.read(len_contentlen)
	
	len_modifiedhdr = struct.unpack(">h", data.read(2))[0]
	data_modifiedhdr = data.read(len_modifiedhdr)
	
	len_modified = struct.unpack(">h", data.read(2))[0]
	data_modified = data.read(len_modified)
	
	len_typehdr = struct.unpack(">h", data.read(2))[0]
	data_typehdr = data.read(len_typehdr)
	
	len_type = struct.unpack(">h", data.read(2))[0]
	data_type = data.read(len_type)
	
	len_datehdr = struct.unpack(">h", data.read(2))[0]
	data_datehdr = data.read(len_datehdr)
	
	len_date = struct.unpack(">h", data.read(2))[0]
	data_date = data.read(len_date)
	
	len_serverhdr = struct.unpack(">h", data.read(2))[0]
	data_serverhdr = data.read(len_serverhdr)
	
	len_server = struct.unpack(">h", data.read(2))[0]
	data_server = data.read(len_server)
	
	# Print section 2 results
	print "\n[*] File Download Data found (offset 0x80, length %d bytes)" % sec2_len
	print "  URL : %s" % (data_URL)
	print "  IP : %s" % (data_IP)
	print "  JAR Size : %s" % (data_contentlen)
	print "  Type : %s" % (data_type)
	print "  Server Date : %s" % (data_modified)
	print "  Server type : %s" % (data_server)
	print "  Download date : %s" % (data_date)

if sec3_len:
	print "\n[*] Section 3 found (offset 0x%X, length %d bytes)" % (128 + sec2_len, sec3_len)
	data.seek (128+sec2_len)
	sec3_hdr = data.read(3)
	#print hex(sec3_len)
	if sec3_hdr == "\x1F\x8B\x08":
		print "  Valid section 3 found. Parsing not implemented at this time."

if sec4_len:
	print "\n[*] Section 4 found (offset 0x%X, length %d bytes)" % (128 + sec2_len + sec3_len, sec4_len)
	data.seek (128 + sec2_len + sec3_len)
	sec4_hdr = data.read(4)
	if sec4_hdr == "\xAC\xED\x00\x05":
		print "  Valid section 4 found. Parsing not implemented at this time."
