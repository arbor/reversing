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

from idaapi import *
from idautils import *
from idc import *
def find_interesting_xor():
    for f in Functions(): 
        func = get_func(f)
        heads=Heads(func.startEA,func.endEA)
        xors = []
        for head in heads:
            if GetMnem(head).startswith('xor'):
                m = GetDisasm(head)
                arg1 = GetOpnd(head,0)
                arg2 = GetOpnd(head,1)
                if arg1 != arg2 and "0FFFFFFFFh" not in [arg1,arg2]:
                    print "Interesting in %s XOR %s %s @ 0x%X" % (get_func_name(f),arg1,arg2,head)
                    xors.append(head)
            elif GetMnem(head).startswith('j') and xors!= []:
                arg1 = GetOpnd(head,0)
                arg1 = get_name_ea(BADADDR,arg1)
                for addr in xors:
                    if addr > arg1:
                        print "Interesting XOR in a loop %s @ %X: %s" % (get_func_name(addr),addr,GetDisasm(addr))

if __name__ == "__main__":
    find_interesting_xor()
