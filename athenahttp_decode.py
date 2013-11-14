# Author: Jason Jones, Arbor Networks ASERT
########################################################################
# Copyright 2013 Arbor Networks
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
########################################################################

import urllib
import string
import base64
import sys
from urlparse import parse_qs

"""
Example usage and output:

python athenahttp_decode.py "a=%59%32%70%77%64%32%64%75%64%47%46%6F%64%57%4A%76%64%6D%6C%6B%63%57%74%34%5A%58%4A%35%62%48%4E%6D%62%58%6F%36%5A%32%31%30%59%57%35%31%61%47%39%69%61%58%5A%77%5A%6E%70%6A%64%32%70%78%5A%47%74%34%5A%58%4A%35%62%48%4D%3D&b=yHR5gGU6v25yZXbeY3q1oWQ6OGY2NWJbNDBlZlRbNsEqMWUqMWE5MWNjODA2ZDYqNsI2OTZlyHBxoXY6YWRhoW58YXJmoDt4ODZ8Z2ViZDtjZXNkcG9ayGNfglVsOmF8v3M6V19YUHq2ZXI6cmEiMC44yG5ecDp0LmB8vlV3OmF8&c=%70%76%63%6A%70%77%64%6A%71%78%64%6B%72%78%65%6C%72%79%66%6C%73%7A%66%6D" cHZjanB3ZGpxeGRrcnhlbHJ5ZmxzemZtZjcrcWRHVuejvUZsUFRkc2ZBPT0KZjbSoGMxcHBoRDAsZjcOclJXMWbzvVE5SVcKclRHcHBzR3c1YsNSoGNiUmnK

Substituion Tables:   cjpwgntahubovidqkxerylsfmz:gmtanuhobivpfzcwjqdkxeryls
Decoded Phone-Home:   |type:on_exec|uid:8f65ba40ffda7111e11a91cd806d6172696f|priv:admin|arch:x86|gend:desktop|cores:1|os:W_XP|ver:v1.0.8|net:4.0|new:1|
Response Data Marker: cHZjanB3ZGpxeGRrcnhlbHJ5ZmxzemZt
Received Command            : |interval=90|
Received Command            : |taskid=7|command=!botkill.start|
"""

def decode_athena(pdata,response):
    pdata = parse_qs(pdata)
    set_abc = set(['a','b','c'])
    if set(pdata.keys()).intersection(set_abc) != set_abc:
        print "POST Data does not contain a,b,c values, exiting."
        return
    KEY_strtr=base64.b64decode(urllib.unquote(pdata['a'][0])).split(':')
    phone_home = urllib.unquote(pdata['b'][0])
    phone_home_decoded = base64.b64decode(phone_home.translate(string.maketrans(KEY_strtr[1],KEY_strtr[0])))
    OUTDATA_marker = base64.b64encode(urllib.unquote(pdata['c'][0]))
    print "Substituion Tables:   %s:%s" % tuple(KEY_strtr)
    print "Decoded Phone-Home:   %s" % phone_home_decoded
    print "Response Data Marker: %s" % OUTDATA_marker
    response_idx = response.find(OUTDATA_marker)
    if response_idx != -1:
        command = response[response_idx+len(OUTDATA_marker):]
        command = command.translate(string.maketrans(KEY_strtr[1],KEY_strtr[0]))
        command = base64.b64decode(command)
        for cmd in command.split('\n'):
            if cmd != "":
                print "Received Command            : %s" % base64.b64decode(cmd)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print "Usage: %s <post-data> <server-response>"
    else:
        decode_athena(sys.argv[1],sys.argv[2])
