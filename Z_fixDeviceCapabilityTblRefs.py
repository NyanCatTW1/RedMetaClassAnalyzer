# A helper script to create missing memory references in the _DeviceCapabilityTbl
# @author Nyan Cat
# @category A_Red
# @keybinding
# @menupath
# @toolbar

# pyright: reportMissingImports=false
# pyright: reportUndefinedVariable=false

import binascii
import array
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.symbol import RefType


def makeByteArr(length):
    return array.array('b', b'\x00' * length)


def readMem(address, length, littleEndian=True):
    memVal = makeByteArr(length)
    mem.getBytes(address, memVal)
    if littleEndian:
        memVal = memVal[::-1]
    return binascii.hexlify(memVal)


# https://github.com/HackOvert/GhidraSnippets
def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)


mem = currentProgram.getMemory()
tblBegin = 0x4ba0b0
tblEnd = 0x4be480

cur = tblBegin
while cur < tblEnd:
    for i in range(5, 10):
        target = cur + i * 8
        fromAddr = getAddress(target)
        toAddr = getAddress(readMem(fromAddr, 8))
        refMgr = currentProgram.getReferenceManager()
        refMgr.addMemoryReference(fromAddr, toAddr, RefType.DATA, SourceType.ANALYSIS, 0)
    cur += 0x50
