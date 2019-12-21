# OpenPGP Card message decoder

This python script reads a log of OpenPGP card messages and converts them
into a human readable transcript, to help with debugging.

The log is created using Wireshark and monitoring USB CCID traffic.

Example:
```bash
$ python3 decode.py device.log
SELECT OpenPGP Card
 9000 (Success)

>> GET DATA [CA] 5-16. Full AID. [004f]
<< d2760001240102010006086910620000 9000 (Success)

>> GET DATA [CA] 0-15.  Historical bytes. [5f52]
<< 0073000080059000 9000 (Success)

>> GET DATA [CA] 7. PW status Bytes (PW1, PW1 max length, RC max length, PW3 max length, ...) [00c4]
<< 017f7f7f030003 9000 (Success)

>> GET DATA [CA] var. Application Related Data. [006e]
<< 
    var. Application Related Data. [006e]: 
        5-16. Full AID. [004f]: d2760001240102010006086910620000
        0-15.  Historical bytes. [5f52]: 0073000080059000
        3. Optional general feature management. [7f74]: 
            RSA modulus. [0081]: 20
        var. Discretionary data objects. [0073]: 
            10. Extended capabilities. [00c0]: 3c00000004c000ff00ff
            var. Algorithm attributes signature. [00c1]: 010800001100
            var. Algorithm attributes decryption. [00c2]: 011000001100
            var. Algorithm attributes authentication. [00c3]: 011000001100
            7. PW status Bytes (PW1, PW1 max length, RC max length, PW3 max length, ...) [00c4]: 017f7f7f030003
            60. fingerprints, 20 bytes each for sig,dec,auth. [00c5]: 549e4beda81d4cfa51da463f6af3e30dc987c8fe43eee30ef73bfd53e25cb0d1dae105de65de9c0407c3573447987972785915e1bd5c5f1fc3c313bb
            60. CA fingerprints, 20 bytes each. [00c6]: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
            12. List of 3, 4-byte dates for pubkey pairs. [00cd]: 5dfcf6ba5dfc0bbc5dfc0c54 (224 bytes total)
...
...
...
```

## Creating log from WireShark

1. Use packet filter `usbccid && (usbccid.bMessageType == 0x6f||usbccid.bMessageType == 0x80)` to only display APDU traffic.
2. Start capturing.
3. Plug in / start OpenPGP card device and run your trace / experiment.
4. Export the packets.

You need to export the packets a particular way so that the Python script can read it.

1. File -> Export Packet Dissections -> As Plain Text...
2. Make sure that all displayed packets get exported, and ONLY the bytes is checked.

![](https://i.imgur.com/PEmY8lB.png)

Now that log file can be passed to `decode.py` as first argument.
