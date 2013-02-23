# Java Cache IDX parser
# Version 1.0 - 12 Jan 13 - @bbaskin
# Version 1.1 - 22 Jan 13 - now supports various IDX file versions
# Version 1.2 - 29 Jan 13 - now supports parsing more section 1 data and section 3 manifest
# Version 1.3 -  8 Feb 13 - Rewrote section 2 parsing. Removed all interpretive code (just parse and print whatever is there)
#			    Rewrote into subs, added very basic Java Serialization parsing.
#               Added CSV output to display all values. If you want fields, too, search this file for "CSVEDIT" and follow instructions

# * Parsing based off source: http://javasourcecode.org/html/open-source/jdk/jdk-6u23/com/sun/deploy/cache/CacheEntry.java.html
# * Some updates based off research by Mark Woan (@woanwave) - https://github.com/woanware/javaidx/tree/master/Documents
# * Thanks to Corey Harrell for providing a version 6.03 file for testing and for initial inspiration:
#        http://journeyintoir.blogspot.com/2011/02/almolsst-cooked-up-some-java.html

# Views cached Java download history files
# Typically located in %AppData%\LocalLow\Sun\Java\Deployment\Cache
# These files hold critical details for malware infections, especially
# Java related ones, e.g. BlackHole.

""" Output example:
E:\Development\Java_IDX_Parser>idx_parser.py Samples\malware\1c20de82-1678cc50.idx
Java IDX Parser -- version 1.3 -- by @bbaskin

IDX file: Samples\malware\1c20de82-1678cc50.idx (IDX File Version 6.05)

[*] Section 2 (Download History) found:
URL: http://80d3c146d3.gshjsewsf.su:82/forum/dare.php?hsh=6&key=b30a14e1c597bd7215d593d3f03bd1ab
IP: 50.7.219.70
<null>: HTTP/1.1 200 OK
content-length: 7162
last-modified: Mon, 26 Jul 2001 05:00:00 GMT
content-type: application/x-java-archive
date: Sun, 13 Jan 2013 16:22:01 GMT
server: nginx/1.0.15
deploy-request-content-type: application/x-java-archive

[*] Section 3 (Jar Manifest) found:
Manifest-Version: 1.0
Ant-Version: Apache Ant 1.8.3
X-COMMENT: Main-Class will be added automatically by build
Class-Path:
Created-By: 1.7.0_07-b11 (Oracle Corporation)

[*] Section 4 (Code Signer) found:
[*] Found: Data block.  Length: 4
Data:                   Hex: 00000000
[*] Found: Data block.  Length: 3
Data: 0                 Hex: 300d0a
"""

import sys
import struct
import os
import zlib

__VERSION__ = "1.3"
__602BUFFER__ = 2 # If script fails to parse your 6.02 files, adjust this. It accounts for a dead space in the data
__CSV__ = False

##########################################################
#    Section two contains all download history data
##########################################################
def sec2_parse():
    csv_body = ''
    data.seek (128)
    len_URL = struct.unpack(">l", data.read(4))[0]
    data_URL = data.read(len_URL)

    len_IP = struct.unpack(">l", data.read(4))[0]
    data_IP = data.read(len_IP)
    sec2_fields = struct.unpack(">l", data.read(4))[0]
    
    print "\n[*] Section 2 (Download History) found:"
    print "URL: %s" % (data_URL)
    print "IP: %s" % (data_IP)
    if __CSV__:
        csv_body = fname + "," + data_URL + "," + data_IP
    for i in range(0, sec2_fields):
        len_field = struct.unpack(">h", data.read(2))[0]
        field = data.read(len_field)
        len_value = struct.unpack(">h", data.read(2))[0]
        value = data.read(len_value)
        print "%s: %s" % (field, value)
        if __CSV__:
            #CSVEDIT: If you want both Field and Value in CSV output, uncomment next line and comment line after.
            #csv_body += "," + field + "," + value
            csv_body += "," + value
    if __CSV__:
        global csvfile
        csvfile = fname + ".csv"
        open(csvfile, 'w').write(csv_body)
        
#############################################################
#    Section two contains all download history data, for 6.02
#   Cache 6.02 files do NOT store IP addresses
#############################################################
def sec2_parse_old():
    data.seek (32)
    len_URL = struct.unpack("b", data.read(1))[0]
    data_URL = data.read(len_URL)
    buf = data.read(__602BUFFER__)
    sec2_fields = struct.unpack(">l", data.read(4))[0]
    
    print "\n[*] Section 2 (Download History) found:"
    print "URL: %s" % (data_URL)
    if __CSV__:
        csv_body = fname + "," + data_URL

    for i in range(0, sec2_fields):
        len_field = struct.unpack(">h", data.read(2))[0]
        field = data.read(len_field)
        len_value = struct.unpack(">h", data.read(2))[0]
        value = data.read(len_value)
        print "%s: %s" % (field, value)
        if __CSV__:
            #CSVEDIT: If you want both Field and Value in CSV output, uncomment next line and comment line after.
            #csv_body += "," + field + "," + value
            csv_body += "," + value

    if __CSV__:
        global csvfile
        csvfile = fname + ".csv"
        open(csvfile, 'w').write(csv_body)
        
    # See if section 3 exists
    if data.tell()+3 < filesize:
        sec3_magic, sec3_ver = struct.unpack(">HH", data.read(4))
    print "\n[*] Section 3 (Additional Data) found:"
    if sec3_magic == 0xACED:
        print "[*] Serialized data found of type:", 
        sec3_type = struct.unpack("b", data.read(1))[0]
        if sec3_type == 0x77: #Data block
            print "Data Block"
            throwaway = data.read(1)
            block_len = struct.unpack(">l", data.read(4))[0]
            block_raw = data.read(block_len)
            if block_raw[0:3] == "\x1F\x8B\x08": # Valid GZIP header
                print "[*] Compressed data found"
                sec3_unc = zlib.decompress(block_raw, 15+32) # Trick to force bitwindow size
                print sec3_unc
        else:
            print "Unknown serialization opcode found: 0x%X" % sec4_type
        return


        
##########################################################
#    Section three contains a copy of the JAR manifest
##########################################################
def sec3_parse():
    data.seek (128+sec2_len)
    sec3_data = data.read(sec3_len)

    if sec3_data[0:3] == "\x1F\x8B\x08": # Valid GZIP header
        sec3_unc = zlib.decompress(sec3_data, 15+32) # Trick to force bitwindow size
        print sec3_unc.strip()

##########################################################
#    Section four contains Code Signer details
#    Written from docs at:
#    http://docs.oracle.com/javase/6/docs/platform/serialization/spec/protocol.html
##########################################################
def sec4_parse():
    unknowns = 0
    data.seek (128 + sec2_len + sec3_len)
    sec4_magic, sec4_ver = struct.unpack(">HH", data.read(4))
    if sec4_magic == 0xACED: # Magic number for Java serialized data, version always appears to be 5
        while not data.tell() == filesize: # If current offset isn't at end of file yet
            if unknowns > 5:
                print "Too many unrecognized bytes. Exiting."
                return
            sec4_type = struct.unpack("B", data.read(1))[0]
            if sec4_type == 0x77: #Data block .. 
                                  #This _should_ parse for 0x78 (ENDDATABLOCK) but Oracle didn't follow their own specs for IDX files.
                print "[*] Found: Data block. ",
                block_len = struct.unpack("b", data.read(1))[0]
                block_raw = data.read(block_len)
                if block_raw[0:3] == "\x1F\x8B\x08": # Valid GZIP header
                    sec4_unc = zlib.decompress(block_raw, 15+32) # Trick to force bitwindow size
                    print sec4_unc.encode("hex")
                else:
                    print "Length: %-2d\nData: %-10s\tHex: %s" % (block_len, block_raw.strip(), block_raw.encode("hex"))
            elif sec4_type == 0x73: #Object
                print "[*] Found: Object\n->",
                continue
            elif sec4_type == 0x72: #Class Description
                print "[*] Found: Class Description:",
                block_len = struct.unpack(">h", data.read(2))[0]
                block_raw = data.read(block_len)
                print block_raw
            else:
                print "Unknown serialization opcode found: 0x%X" % sec4_type
                unknowns += 1
        return
        
        
##########################################################
#    Start __main__()
##########################################################    
if __name__ == "__main__":
    print "Java IDX Parser -- version %s -- by @bbaskin\n" % __VERSION__
    try:
        if sys.argv[1] in ["-c", "-C"]:
            __CSV__ = True
            fname = sys.argv[2]
        else:
            fname = sys.argv[1]
    except:
        print "Usage: idx_parser.py <filename>"
        print "\nTo generate a CSV output file:"
        print "     : idx_parser.py -c <filename>"
        sys.exit()
    try:    
        data = open(fname, 'rb')
    except:
        print "File not found: %s" % fname
        sys.exit()
    
    filesize = os.path.getsize(fname)
    
    busy_byte = data.read(1)
    complete_byte = data.read(1)
    cache_ver = struct.unpack(">i", data.read(4))[0]
    force_update = data.read(1)
    no_href = data.read(1)
    is_shortcut_img = data.read(1)
    content_len = struct.unpack(">l", data.read(4))[0] # Not really correct... spec goes off rails around here
    last_modified_date = struct.unpack(">l", data.read(4))[0]
    expiration_date = struct.unpack(">l", data.read(4))[0]

    if cache_ver not in (602, 603, 604, 605, 606):
        print "Invalid IDX header found"
        print "Found:    0x%s" % cache_ver
        sys.exit()
    print "IDX file: %s (IDX File Version %d.%02d)" % (fname, cache_ver / 100, cache_ver - 600)

    # Different IDX cache versions have data in different offsets
    if cache_ver in [603,604,605]:
        if cache_ver in [603, 604]:
            data.seek(38)
        else:
            data.seek(36)
        sec2_len = struct.unpack(">i", data.read(4))[0]
        sec3_len = struct.unpack(">i", data.read(4))[0]
        sec4_len = struct.unpack(">i", data.read(4))[0]
        sec5_len = struct.unpack(">i", data.read(4))[0]
        blacklist_timestamp = struct.unpack(">l", data.read(4))[0]
        cert_expiration_date = struct.unpack(">l", data.read(4))[0]
        sec4_old_cert_len = struct.unpack(">l", data.read(4))[0]
        sec4_unsigned_entries = struct.unpack("b", data.read(1))[0]
        sec4_single_code_src = struct.unpack("b", data.read(1))[0]
        sec4_certs_len = struct.unpack(">l", data.read(4))[0]
        sec4_signers_len = struct.unpack(">l", data.read(4))[0]
        sec4_signinfo_missing_entries = struct.unpack("b", data.read(1))[0]
    elif cache_ver == 602:
        sec2_len = 1
        sec3_len = 0
        sec4_len = 0
        sec5_len = 0
    else:
        print "Current file version, %d, is not supported at this time." % cache_ver
        sys.exit()

    if sec2_len:
        if cache_ver == 602: sec2_parse_old()
        else: sec2_parse()

    if sec3_len:
        print "\n[*] Section 3 (Jar Manifest) found:" 
        sec3_parse()

    if sec4_len:
        print "\n[*] Section 4 (Code Signer) found:"
        sec4_parse()
                
    if sec5_len:
        print "\n[*] Section 5 found (offset 0x%X, length %d bytes)" % (128 + sec2_len + sec3_len + sec4_len, sec5_len)
        
    if __CSV__:
        print "\n\n[*] CSV file written to %s" % csvfile
### End __main__()
