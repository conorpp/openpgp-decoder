
from binascii import unhexlify, hexlify

from constants import DO_table

class DO:
    @staticmethod
    def parse(data, GET, parent = None):
        siblings = []
        do = DO(data, GET, parent)
        if do.constructed:
            do.children = DO.parse(do.payload, GET, do)
        siblings.append(do)
        while len(do.leftover):
            do = DO(do.leftover, GET, parent)
            if do.constructed:
                do.children = DO.parse(do.payload, GET, do)
            siblings.append(do)

        return siblings
        
        
    def __init__(self,data,GET, parent=None):
        self.constructed = False
        self.children = []
        self.tag = 0
        self.parent = parent

        if isinstance(data, str):
            data = unhexlify(data)
        
        self.data = data
        self.payload = ''
        tag = data[0]
        if (tag & 0x0f) == 0x0f:
            tag = tag << 8
            tag |= data[1]
            data = data[1:]
        self.tag = tag 

        l1 = data[1]

        length = l1
        self.payload = data[2:2+length]
        self.leftover = data[2:]
        if (l1 > 0x7F):
            if (l1 == 0x81):
                l2 = data[2]
                length = l2
                self.payload = data[3:3+length]
                self.leftover = data[3:]
            elif (l1 == 0x82):
                l2 = data[2]
                l3 = data[3]
                length = (l2<<8) | l3
                self.payload = data[4:4+length]
                self.leftover = data[4:]

        self.length = length
        if not self.isTemplate():
            self.leftover = self.leftover[len(self.payload):]

        table = DO_table['GET'] 
        if not GET:
            table = DO_table['PUT']

        info = table.get(self.tag, '')
        if not info:
            t1 = (self.tag&0xff00)>>8
            t2 = self.tag & 0xff
            des = '%02x%02x' % (t1, t2)
            if (t1 == 0):
                des = '%02x' % (t2)
            info = {'description': '?', 'type':'?'}

            self.known = False
        else:
            self.known = True

        if info['type'] in 'cC':
            self.constructed = True
            if self.isTemplate():
                raise RuntimeError('Cannot have template child be a constructed type.')
        
        self.info = info

    def toString(self, depth=1):
        space = '    ' * depth
        s = space + ('%s [%04x]: ' % (self.info['description'], self.tag))

        if not self.constructed:
            if self.isTemplate():
                s += ('%d bytes' % (self.length))
            else:
                s += ('%s' % hexlify(self.payload).decode())
        else:
            for child in self.children:
                s += '\n'
                s += child.toString(depth + 1)
        return s

    def isTemplate(self, ):
        if self.parent:
            if self.parent.info.get('template',False):
                return True
        return False