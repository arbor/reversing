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
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(("Address","String"))
        layout = QtGui.QVBoxLayout()
        layout.addWidget(self.table)

        self.Create()
        self.parent.setLayout(layout)
    def OnClose(self,form):
        global ByteStringForm
        del ByteStringForm
        print "Closed"

    def click_row(self):
        i = self.table.item(self.table.currentRow(),0)
        print self.table.currentRow()
        addr = i.text().strip()
        print addr
        if not addr.startswith("0x"):
            addr = get_name_ea(BADADDR,str(addr))
        else:
            addr = addr[2:10]
            addr= int(addr,16)
        Jump(addr)
        return
    def Create(self):
        title = "Byte Strings"
        self.table.clear()
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(("Address","String"))
        self.table.itemClicked.connect(self.click_row)
        self.find_byte_strings()
        self.table.setRowCount(len(self.byte_strings.keys()))
        row = 0
        for addr,bstr in self.byte_strings.items():
            self.table.setItem(row,0,QtGui.QTableWidgetItem(addr))
            self.table.setItem(row,1,QtGui.QTableWidgetItem(bstr))
            row += 1
        
        
    def find_byte_strings(self):
        #chrs = {}
        for f in Functions():
            func = get_func(f)
            chr_vals = {}
            for head in Heads(func.startEA,func.endEA):
                if GetMnem(head) == "mov":
                    if (GetOpnd(head,0).startswith('byte ptr') or GetOpnd(head,0).startswith('[e')) and GetOpType(head,1) == o_imm and GetOperandValue(head,1) >= 0x20 and GetOperandValue(head,1) <= 0x7f:
                        reg = GetOpnd(head,0)
                        reg = reg[reg.find('['):]
                        if reg.count('+') == 0: offset = 0
                        else: 
                            reg = reg[:reg.find('+')]+']'
                            offset = ctypes.c_int32(GetOperandValue(head,0)).value

                        if reg not in chr_vals: chr_vals[reg] = {}
                        if offset not in chr_vals[reg]: chr_vals[reg][offset] = (head,chr(GetOperandValue(head,1)))
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

find_all_byte_strings()
