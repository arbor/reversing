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
from idc import *
from idautils import *
import ctypes
from PySide import QtGui, QtCore


class ByteStringsViewer_t(PluginForm):
    def Show(self):
        return PluginForm.Show(self,"Byte Strings",options = PluginForm.FORM_PERSIST)

    def OnCreate(self,form):
        self.parent = self.FormToPySideWidget(form)
        self.byte_strings = {}
        self.table = QtGui.QTableWidget()
        self.table.setRowCount(1)
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(("Address","Function","String"))
        layout = QtGui.QVBoxLayout()
        layout.addWidget(self.table)
        self.clipboard = QtGui.QClipboard()
        self.Create()
        self.parent.setLayout(layout)
    def OnClose(self,form):
        global ByteStringForm
        del ByteStringForm
        print "Closed"

    def click_row(self):
        i = self.table.item(self.table.currentRow(),0)
        bstr = self.table.item(self.table.currentRow(),2)
        print self.table.currentRow()
        addr = i.text().strip()
        bstr = bstr.text()
        print bstr
        print addr
        if not addr.startswith("0x"):
            addr = get_name_ea(BADADDR,str(addr))
        else:
            addr = addr[2:10]
            addr= int(addr,16)
        Jump(addr)
        self.clipboard.setText(bstr)
        return

    def Create(self):
        title = "Byte Strings"
        self.table.clear()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(("Address","Function","String"))
        self.table.itemClicked.connect(self.click_row)
        self.find_byte_strings()
        self.table.setRowCount(len(self.byte_strings.keys()))
        row = 0
        for addr,bstr in self.byte_strings.items():
            self.table.setItem(row,0,QtGui.QTableWidgetItem(addr))
            self.table.setItem(row,1,QtGui.QTableWidgetItem(get_func_name(int(addr[2:],16))))
            self.table.setItem(row,2,QtGui.QTableWidgetItem(bstr))
            self.table.resizeRowToContents(row)
            row += 1
        self.table.setSortingEnabled(True)

        
        
    def find_byte_strings(self):
        #chrs = {}
        for f in Functions():
            func = get_func(f)
            chr_vals = {}
            eightbit = {}
            for head in Heads(func.startEA,func.endEA):
                if GetMnem(head) == "mov":
                    if re.match('[abcd]l',GetOpnd(head,0)) and GetOpType(head,1) == o_imm and ((GetOperandValue(head,1) >= 0x20 and GetOperandValue(head,1) <= 0x7f) or GetOperandValue(head,1) in [0xd,0xa]):
                        eightbit[GetOpnd(head,0)] = GetOperandValue(head,1)
                    if (GetOpnd(head,0).startswith('byte ptr') or GetOpnd(head,0).startswith('[e')) and GetOpType(head,1) == o_imm and  ((GetOperandValue(head,1) >= 0x20 and GetOperandValue(head,1) <= 0x7f) or GetOperandValue(head,1) in [0xd,0xa]):
                        reg = GetOpnd(head,0)
                        reg = reg[reg.find('['):]
                        if reg.count('+') == 0: offset = 0
                        else: 
                            ops = reg.split('+')
                            reg = reg[:reg.find('+')]+']'
                            offset = ctypes.c_int32(GetOperandValue(head,0)).value
                            reg_base=0
                            if len(ops) > 2 and ops[1].endswith('h'):
                                reg_base = int(ops[1][:-1],16)
                            offset = offset-reg_base
                        if reg not in chr_vals: chr_vals[reg] = {}
                        chr_vals[reg][offset] = (head,chr(GetOperandValue(head,1)))
                    elif (GetOpnd(head,0).startswith('byte ptr') or GetOpnd(head,0).startswith('[e')) and GetOpType(head,1) == o_reg and GetOpnd(head,1) in eightbit:
                        reg = GetOpnd(head,0)
                        reg = reg[reg.find('['):]
                        if reg.count('+') == 0: offset = 0
                        else:
                            ops = reg.split('+')
                            reg = reg[:reg.find('+')]+']'
                            offset = ctypes.c_int32(GetOperandValue(head,0)).value
                            reg_base=0
                            if len(ops) > 2 and ops[1].endswith('h'):
                                reg_base = int(ops[1][:-1],16)
                            offset = offset-reg_base

                        if reg not in chr_vals: chr_vals[reg] = {}
                        chr_vals[reg][offset] = (head,chr(eightbit[GetOpnd(head,1)]))
            for reg,c_v in chr_vals.items():
                keys = c_v.keys()
                keys.sort()
                last = None
                s = ""
                offset = 0
                for o in keys:
                    if last is None:
                        addr = c_v[o][0]
                        offset = o
                        s = c_v[o][1]
                    elif last + 1 == o and c_v[o] != '\x00':
                        s += c_v[o][1]
                    else:
                        if s != "" and len(s) > 3:
                            self.byte_strings["0x%X" % addr] = s
                            func = get_func(addr)
                            if offset > 0: 
                                s = ""
                                continue
                    
                        s = c_v[o][1]
                        offset = o
                        addr = c_v[o][0]
                    last = o
                if s != "" and len(s) > 1:
                    self.byte_strings["0x%X" % addr] = s
                    func = get_func(addr)

def find_all_byte_strings():
    global ByteStringForm
    ByteStringForm = ByteStringsViewer_t()
    ByteStringForm.Show()
    ByteStringForm.table.resizeRowsToContents()
    ByteStringForm.table.resizeColumnsToContents()


find_all_byte_strings()
