#!/usr/bin/env python3
#
# analyze.py
#
# loads a packet trace of USB CCID traffic and decodes in 
# a human readable format.  Useful for debugging.
#
# Handles:
# * OpenPGP
#
#
import sys
import binascii
from binascii import hexlify, unhexlify
import struct

from constants import DO_table
from do import DO

if sys.version_info < (3, 0):
    sys.stdout.write("Python 3.x is required.\n")
    sys.exit(1)
if len(sys.argv) != 2:
    print('usage: %s <input-file>' % sys.argv[0])
    sys.exit(1)

class APDUCode:
    codeTable = {
        0x9000: 'Success',
        0x6b00: 'Wrong P1-P2',
        0x6a82: 'File not found',
        0x6985: 'Conditions of use not satisfied',
    }
    def __init__(self,data):
        self.code = struct.unpack('>H',data[len(data)-2:])[0]

    def toString(self,):
        s = ''
        s += '%04x' % (self.code)
        s += " ("+self.codeTable.get(self.code, '?') +')'
        return s

class APDURequest:
    def __init__(self, data):
        self.data = data
        # CLA, INS, P1, P2
        self.header = [x for x in data[:4]]
        self.payload = b''
        self.length = 0
        self.expected_length = -1
        # print(binascii.hexlify(self.data))
        if len(data) > 5:
            if data[4] != 0:
                self.length = data[4]
                self.payload = data[5:]
                if len(self.payload) == 0:
                    self.length = 0
                    self.expected_length = data[4]

                # print('length = lc', )
            else:
                self.length = (data[5]<<8) | data[6]
                # print('length = le')
                self.payload = data[7:]
            if (len(self.payload) - 1) == self.length:
                # print('payload--')
                self.expected_length = data[-1]
                self.payload = self.payload[:len(self.payload)-1]

        # print(len(self.payload), self.length)
        assert(len(self.payload) == self.length)
    
    def toString(self,):
        return '%02x %02x %02x %02x  %s (len %d%s)' % (   
            self.header[0], self.header[1], self.header[2], self.header[3], 
            binascii.hexlify(self.payload).decode(),
            self.length, '' if  self.expected_length == -1 else ', expects %d bytes' % self.expected_length
        )


class APDUResponse:
    def __init__(self, data):
        self.data = data
        self.payload = ''
        if len(data) > 2:
            self.payload = data[:len(data)-2]
        self.code = APDUCode(data)

    
    def toString(self,):
        s = ''
        if (len(self.payload)) > 0:
            s += hexlify(self.payload).decode()
        s +=  ' '+ self.code.toString()
        return s

class CCIDPacket:
    def __init__(self, data, offset = 0x40):
        data = data[offset:]
        self.messageType = data[0]
        self.length = data[1] | (data[2]<<8)
        self.payload = data[10:]
        assert(len(self.payload) == self.length)            

        if self.messageType == 0x80:
            self.isDevice = True
            self.apdu = APDUResponse(self.payload)
        elif self.messageType == 0x6f:
            self.isDevice = False
            self.apdu = APDURequest(self.payload)
        else:
            self.isDevice = None

    def toString(self,):
        s = ''
        if self.isDevice == True:
            s += '<<'
        elif self.isDevice == False:
            s += '>>'
        else:
            s += 'Unknown CCID type: ' + self.messageType
            return s

        if self.apdu:
            s += ' ' + self.apdu.toString()
        return s

class Decoder:



    def __init__(self,req, res):
        self.req = req
        self.res = res

        self.cla = req.header[0]
        self.ins = req.header[1]
        self.p1 = req.header[2]
        self.p2 = req.header[3]
        self.P = (self.p1 << 8) | self.p2
    
    def toString(self,):
        s = '>> '
        parse_res_dos = False
        if self.ins == 0xCA:
            # xCA: get data
            info = {'description': '?', 'type': '?'}
            if self.P in DO_table['GET']:
                info = DO_table['GET'][self.P]

            s += 'GET DATA [CA] %s [%02x%02x]' % (info['description'], self.p1,self.p2)

            if info['type'] in 'Cc':
                parse_res_dos = True

            assert(self.req.length == 0)

        elif self.ins == 0xDA or self.ins == 0xDB:

            info = {'description': '?', 'type': '?'}
            if self.P in DO_table['PUT']:
                info = DO_table['PUT'][self.P]


            s += '%02x %02x PUT DATA [DB] %s [%02x%02x] ' % (self.cla, self.ins, info['description'], self.p1,self.p2)
            # s += hexlify(self.req.payload).decode()
            s += ' (%d)' % (self.req.length)

            if info['type'] in 'Cc':
                dos = DO.parse(self.req.payload, False)
                s += '\n'+(dos[0].toString())
            else:
                s +='\n    ' + hexlify(req.payload).decode()
            


        elif self.ins == 0x47:
            # x47: generate asymmetric key
            if self.p1 == 0x80:
                s += 'Generate asymmetric key pair [80]: '
            elif self.p1 == 0x81:
                s += 'Read asymmetric public key [81]: '
                parse_res_dos = True
            else:
                raise RuntimeError('Invalid P1 for x47 ins command: ' + hex(self.p1))
            assert(self.req.length == 2)
            crt = struct.unpack('>H', self.req.payload)[0]
            if crt == 0xb600:
                s += 'signing key'
            elif crt == 0xb800:
                s += 'encryption key'
            elif crt == 0xa400:
                s += 'auth key'
            else:
                raise RuntimeError('Invalid CRT for x47 ins command: ' + hex(crt))
        elif self.ins == 0x20:
            # x20:
            pw = self.p2 ^ 0x80
            assert(pw in (1,2,3))
            s += 'VERIFY PW%d  %s' % (pw, (req.payload).decode())
        elif self.ins == 0xC0:
            s += 'GET RESPONSE'
        else:
            s += self.req.toString()
        
        s += '\n<< ' 
        if parse_res_dos and len(self.res.payload):
            try:
                dos = DO.parse(self.res.payload, True)
                s += '\n'+(dos[0].toString()) 
            except:
                s += ('\nERROR (could not parse DO): ' + hexlify(self.res.payload).decode())

        else:
            s += self.res.toString()
        s = s + (' (%d bytes total)' % len(self.res.payload))

        return s


def textfile2packets(filename):

    inp = open(filename,'r').readlines()

    inp = [x[6:53].replace(' ','') for x in inp]
    pkts = []
    s = ''
    for x in inp:

        if len(x) == 0:
            pkts.append(s)
            s = ''
        else:
            s += x

    return [CCIDPacket(binascii.unhexlify(x)) for x in pkts]
    
def packets2pairs(pkts):
    # convert CCID packets to APDU pairs
    pairs = []
    pair = []
    for p in pkts:
        if p.isDevice == None:
            print('dropping non-apdu packet.')
            continue

        if len(pair) == 1:
            if not p.isDevice:
                raise RuntimeError('There are two consecutive host packets')
            pair.append(p.apdu)
        elif len(pair) == 0:
            if p.isDevice == True:
                print('dropping extra device packet')
                continue
            pair.append(p.apdu)

        if len(pair) == 2:
            pairs.append(pair)
            pair = []
    return pairs

def coalesce_pairs(pairs):
    # combine APDUs that were split due to payload size
    new_pairs = []
    firstreq = None
    # Combine requests
    for i,(req,res) in enumerate(pairs):
        if (req.header[0] & 0x10) and res.code.code == 0x9000:
            if firstreq is None:
                firstreq = req
            else:
                firstreq.payload = firstreq.payload + req.payload
                firstreq.length += req.length
        else:
            if firstreq is None:
                new_pairs.append((req,res))
            else:
                firstreq.payload = firstreq.payload + req.payload
                firstreq.length += req.length
                assert(len(firstreq.payload) == firstreq.length)
                new_pairs.append((firstreq, res))
                firstreq = None

    pairs = new_pairs[:]
    new_pairs = []
    firstres = None
    firstreq = None
    # Combine responses
    for i,(req,res) in enumerate(pairs):
        if (res.code.code & 0x6100) == 0x6100:
            if (req.header[1] == 0xC0):
                if firstres is None:
                    raise RuntimeError('Host sent unsolicited GET RESPONSE')
                firstres.payload = firstres.payload + res.payload
            else:
                firstres = res
                firstreq = req
        else:
            if firstres is None or (req.header[1] != 0xC0):
                new_pairs.append((req,res))
            else:
                firstres.payload = firstres.payload + res.payload
                new_pairs.append((firstreq, firstres))
                firstres = None
                firstreq = None
    return new_pairs


def aid2name(aid):
    aid_string = binascii.hexlify(aid).decode()
    table = {
        'a00000000101':'MUSCLE Card Applet',
        'a00000030800001000':'PIV',
        'a000000116db00':'Card Capability Container',
        'a0000000790100':'Identity Key',
        'a0000000790101':'Digital Signature Key',
        'a0000000790102':'Key Management Key',
        'd27600012401':'OpenPGP Card',
    }
    return table.get(aid_string.lower(), aid_string)

def isSelect(req):
    return req.header[1] == 0xa4 and req.header[2] == 0x04

pkts = textfile2packets(sys.argv[1])
pairs = packets2pairs(pkts)
pairs = coalesce_pairs(pairs)

for (req,res) in pairs:
    if isSelect(req):
        print('SELECT %s' % aid2name(req.payload))
        print(res.toString())
    else:
        d = Decoder(req,res)
        print(d.toString())
    
    print()