# Does all kind of cool stuff to make analyzing meta classes easier. Check the changelog/code for detailed features.
# @author Nyan Cat
# @category A_Red
# @keybinding
# @menupath
# @toolbar

# Features (Newest at bottom)
# Rename metaClass/vtable pointers in __got.
# Find all references to safeMetaCast and retype variables according to the arguments fed.
# Add missing meta structs.
# Add many long fields to ATIController in order to ease the REing of its structure.
# Set up meta/vtable structs to display function name on vtable calls.
# Create vtable stubs in order to ease the REing of its structure.

# pyright: reportMissingImports=false
# pyright: reportUndefinedVariable=false

import array
import binascii

from java.util import ArrayList

from ghidra.program.model.symbol import SourceType
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# I literally found this by looking at Ghidra's source code (RetypeLocalAction.java)
from ghidra.program.model.pcode import HighFunctionDBUtil

# DataTypeEditorManager.java
# CreatePointerAction.java
from ghidra.program.model.data import CategoryPath, StructureDataType, PointerDataType, FunctionDefinitionDataType

# FindReferencesToField.java -> LocationReferencesPlugin.java -> GenericCompositeDataTypeProgramLocation.java -> ReferenceUtils.java
# Java.
from ghidra.program.model.data import DataTypeConflictHandler

# Used to recreate FunctionDefinitionDataType from signature string
from ghidra.program.model.data import GenericCallingConvention, ParameterDefinitionImpl

verbose = False
vtableREMode = False
overrideMetaStructs = False


def makeByteArr(length):
    return array.array('b', b'\x00' * length)


def readMem(address, length, littleEndian=True):
    memVal = makeByteArr(length)
    mem.getBytes(address, memVal)
    if littleEndian:
        memVal = memVal[::-1]
    return binascii.hexlify(memVal)


def getCommentAtPtr(ptr, ptrSize=8, commentType=3):
    addr = getAddress(readMem(ptr, ptrSize))
    return codeManager.getComment(commentType, addr)


# https://github.com/HackOvert/GhidraSnippets
def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)


def getDataType(typeName, typeManager):
    matches = ArrayList()
    typeManager.findDataTypes(typeName, matches)

    if len(matches) > 1:
        print("Warning: Using the first " + typeName)
    elif len(matches) == 0:
        return None

    return matches[0]


def makePtrTypeName(typeName, ptrLevel):
    return typeName + " *" * ptrLevel


def ensureDataType(typeName, typeManager, ptrLevel, forceStructSize):
    # Because I kept on misusing this function somehow
    assert "*" not in typeName

    ret = getDataType(makePtrTypeName(typeName, ptrLevel), typeManager)
    if ret is not None:
        # Don't touch other types
        if not isinstance(ret, StructureDataType):
            return ret

        if ptrLevel == 0 and forceStructSize is not None and ret.getLength() != forceStructSize:
            if verbose:
                print("    Resizing {}/{} from {} bytes to {} bytes".format(ret.getCategoryPath(), ret.getName(), ret.getLength(), forceStructSize))
            ret.replaceWith(StructureDataType(ret.getCategoryPath(), ret.getName(), forceStructSize))
        return ret

    # Create our own data type
    if ptrLevel == 0:
        targetLen = forceStructSize if forceStructSize is not None else 0
        if verbose:
            print("Creating {}-bytes struct data type {}".format(targetLen, typeName))
        ret = StructureDataType(CategoryPath("/AMDGen/Structs"), typeName, targetLen, typeManager)
    else:
        prevType = ensureDataType(typeName, typeManager, ptrLevel - 1, forceStructSize)
        if verbose:
            print("Creating pointer data type " + makePtrTypeName(typeName, ptrLevel))
        ret = PointerDataType(prevType, typeManager)
    ret = typeManager.addDataType(ret, DataTypeConflictHandler.REPLACE_HANDLER)

    return ret


state = getState()
mem = currentProgram.getMemory()
funcManager = currentProgram.getFunctionManager()
codeManager = currentProgram.getCodeManager()
typeManager = currentProgram.getDataTypeManager()
symbolTable = currentProgram.getSymbolTable()

print("Renaming pointers in __got...")
got = mem.getBlock("__got")
print("Found __got at {}~{}".format(got.getStart(), got.getEnd()))

metaTypeNames = set()

addr = got.getStart()
renameCount = 0
# This step SHOULD NOT be skipped because it populates the metaTypeNames set
while True:
    name = getCommentAtPtr(addr)
    if name is None:
        break
    elif "etaClass" in name:
        name = name.replace("::", "__")
        metaTypeNames.add(name.split("__")[0])
        pass
    elif "vtable" in name:
        metaTypeNames.add(name.split(" ")[2])
        name = "{}__vtable".format(name.split(" ")[2])
    else:
        break

    renameCount += 1
    symbol = symbolTable.createLabel(addr, name, SourceType.ANALYSIS)
    addr = addr.add(8)
print("Renamed {} symbols".format(renameCount))

print("")
print("Retyping variables that uses OSMetaClassBase::safeMetaCast...")
for func in funcManager.getFunctions(True):
    if "safeMetaCast" in func.getName():
        metaCast = func
        break
print("Found safeMetaCast at {}".format(metaCast.getEntryPoint()))

refs = getReferencesTo(metaCast.getEntryPoint())
print("Found {} references to safeMetaCast".format(len(refs)))
todoFuncs = []
for xref in refs:
    func = funcManager.getFunctionContaining(xref.getFromAddress())
    if func not in todoFuncs:
        todoFuncs.append(func)

print("Found {} functions that uses safeMetaCast".format(len(todoFuncs)))

options = DecompileOptions()
# Prevent line wrapping
options.setMaxWidth(10000)
monitor = ConsoleTaskMonitor()
ifc = DecompInterface()
ifc.setOptions(options)
ifc.openProgram(func.getProgram())

for iter in range(25):
    if vtableREMode:
        print("Skipping variable retype")
        break

    print("Running pass {}/{}".format(iter + 1, 25))
    retypeCount = 0
    for func in todoFuncs:
        results = ifc.decompileFunction(func, 0, monitor)
        code = results.getDecompiledFunction().getC().split('\n')

        funcName = [x for x in code if "::" in x][0][3:-3]
        castRefs = [x for x in code if "OSMetaClassBase::safeMetaCast(" in x]
        for castRef in castRefs:
            try:
                symbolMap = results.getHighFunction().getLocalSymbolMap().getNameToSymbolMap()
                parts = castRef.strip().split(" = ")
                assert len(parts) == 2 and not any(x in parts[0] for x in "()&! ")
                varName = parts[0]
                className = parts[1].split(")")[-2].strip()

                if className.endswith("__metaClass"):
                    className = className[:-len("__metaClass")]
                elif "::" in className:
                    # [1:] to remove &
                    className = className.split("::")[0][1:]
                elif className == "&gMetaClass":
                    # Class of "this"
                    className = funcName.split("::")[0]
                else:
                    raise AssertionError

                metaTypeNames.add(className)
                varSymbol = symbolMap[str(varName)]
                dataType = ensureDataType(className, typeManager, 1, None)

                if varSymbol.getDataType() != dataType:
                    if verbose:
                        print("    Retyping {} from {} to {} in {}".format(varName, varSymbol.getDataType().getName(), makePtrTypeName(className, 1), funcName))
                    retypeCount += 1
                    # Here goes nothing...
                    HighFunctionDBUtil.updateDBVariable(varSymbol, None, dataType, SourceType.USER_DEFINED)
            except AssertionError:
                pass
                # print("Warning: Error processing code")
                # print(" " * 4 + castRef.strip())
    print("Retyped {} variables".format(retypeCount))
    if retypeCount == 0:
        break

print("")
print("Setting up meta struct basic structure...")
demanglerPath = typeManager.getCategory(CategoryPath("/Demangler"))
dataTypes = demanglerPath.getDataTypes()
print("Found {} data types directly under /Demangler".format(len(dataTypes)))
metaDataTypes = []
for dataType in dataTypes:
    name = dataType.getName()
    if "*" not in name and (demanglerPath.getCategory(name) is not None or name in metaTypeNames):
        metaDataTypes.append(dataType)

newStructs = typeManager.getCategory(CategoryPath("/AMDGen/Structs"))
if newStructs is not None:
    for dataType in newStructs.getDataTypes():
        if "*" not in dataType.getName() and "_vtableStruct" not in dataType.getName():
            metaDataTypes.append(dataType)

print("Found {} meta structs".format(len(metaDataTypes)))

long = ensureDataType("long", typeManager, 0, None)
longPtr = ensureDataType("long", typeManager, 1, None)
setCount = 0
for dataType in metaDataTypes:
    # Don't touch data type with content
    if dataType.isZeroLength():
        # print("    Appending long * in {}".format(dataType.getName()))
        setCount += 1
        dataType.add(longPtr, 8, "vtable", "Generated by RedMetaClassAnalyzer.py")
        # Ensure the DataType in typeManager is updated
        typeManager.addDataType(dataType, DataTypeConflictHandler.REPLACE_HANDLER)
    elif overrideMetaStructs:
        dataType.replaceAtOffset(0, longPtr, 8, "vtable", "Generated by RedMetaClassAnalyzer.py")
        # Ensure the DataType in typeManager is updated
        typeManager.addDataType(dataType, DataTypeConflictHandler.REPLACE_HANDLER)

    if dataType.getName() == "ATIController" and dataType.getLength() == 8:
        print("Spraying 32768 fields in ATIController :crab: :crab: :crab:")
        for i in range(1, 32769):
            dataType.add(long, 8, "field_0x{}".format(hex(i * 8)[2:].zfill(5)), "Generated by RedMetaClassAnalyzer.py")
        # Ensure the DataType in typeManager is updated
        typeManager.addDataType(dataType, DataTypeConflictHandler.REPLACE_HANDLER)
print("Set structure on {} meta structs".format(setCount))

callTypes = {
    "__stdcall": GenericCallingConvention.stdcall,
    "__cdecl": GenericCallingConvention.cdecl,
    "__fastcall": GenericCallingConvention.fastcall,
    "__thiscall": GenericCallingConvention.thiscall,
    "__vectorcall": GenericCallingConvention.vectorcall
}

# 1. The spacing must be exactly like the examples.
# 2. * must stick to the type name.
knownVtables = {}
knownVtables["OSDictionary"] = ["Unknown"] * 66
knownVtables["OSDictionary"][58] = "__thiscall bool OSDictionary::setObject(OSDictionary* this, char* aKey, OSMetaClassBase* anObject)"
knownVtables["OSDictionary"][63] = "__thiscall OSObject* OSDictionary::getObject(OSDictionary* this, OSSymbol* aKey)"
knownVtables["OSDictionary"][65] = "__thiscall OSObject* OSDictionary::getObject(OSDictionary* this, char* aKey)"

print("")
print("Creating and assigning vtable structs...")

for i in range(len(metaDataTypes)):
    print("{}/{}:".format(i + 1, len(metaDataTypes)))
    dataType = metaDataTypes[i]
    name = dataType.getName()

    if name in knownVtables.keys():
        print("    Using predefined vtable for {}".format(name))
        vtable = []
        funcs = knownVtables[name]
        for i in range(len(funcs)):
            curFunc = funcs[i]
            if curFunc == "Unknown":
                funcName = "field_" + str(i).zfill(3)
            else:
                # I apologize for all the .split around here.
                funcName = curFunc.split("(")[0].split(" ")[-1]
                funcType = FunctionDefinitionDataType(CategoryPath("/AMDGen/FuncSigns"), funcName + "_sign")

                callType = curFunc.split(" ")[0]
                funcType.setGenericCallingConvention(callTypes[callType])

                retType = curFunc.split(" ")[1]
                funcType.setReturnType(ensureDataType(retType.replace("*", ""), typeManager, retType.count("*"), None))

                paraStrs = curFunc.split("(")[1].split(")")[0].split(", ")
                parameters = []
                for paraStr in paraStrs:
                    typeName, paraName = paraStr.split(" ")
                    paraType = ensureDataType(typeName.replace("*", ""), typeManager, typeName.count("*"), None)
                    parameters.append(ParameterDefinitionImpl(paraName, paraType, ""))
                funcType.setArguments(parameters)

                typeManager.addDataType(funcType, DataTypeConflictHandler.REPLACE_HANDLER)
            vtable.append(funcName)
    else:
        if vtableREMode:
            print("    Skipping {}".format(name))
            continue
        vtableAddr = None
        for func in funcManager.getFunctions(True):
            if name != func.getName():
                continue
            results = ifc.decompileFunction(func, 0, monitor)
            code = results.getDecompiledFunction().getC().split('\n')
            matches = [line for line in code if line.strip().startswith("this->vtable = ") and "{}_".format(name) in line]
            if len(matches) != 0:
                extractedAddr = getAddress(matches[0].split("_")[-1].replace(";", ""))
                if vtableAddr is None:
                    vtableAddr = extractedAddr
                else:
                    if vtableAddr != extractedAddr:
                        print("    Error: Conflicting vtable addresses for {}".format(name))
                        print(vtableAddr, code)
                        vtableAddr = None
                        break

        if vtableAddr is None:
            print("    Warning: Failed to find vtable for {}".format(name))
            continue

        print("    Analyzing {} vtable at {}...".format(name, vtableAddr))
        vtable = []
        addr = vtableAddr
        while True:
            ptrAddr = getAddress(readMem(addr, 8))
            if ptrAddr.getOffset() == 0:
                break

            func = funcManager.getFunctionContaining(ptrAddr)
            if func is not None:
                funcName = str(func)
                # print(func.getSignature(False).getPrototypeString(True))
                funcType = FunctionDefinitionDataType(CategoryPath("/AMDGen/FuncSigns"), funcName + "_sign", func.getSignature(False))
                typeManager.addDataType(funcType, DataTypeConflictHandler.REPLACE_HANDLER)
            else:
                # Remove L with [:-1]
                funcName = "field_0x" + hex(addr.subtract(vtableAddr))[2:-1].zfill(3)

            vtable.append(funcName)
            addr = addr.add(8)

    print("    Creating {}_vtableStruct with {} entries...".format(name, len(vtable)))
    vtableStruct = ensureDataType(name + "_vtableStruct", typeManager, 0, 0)
    vtableStruct.deleteAll()
    for funcName in vtable:
        if funcName.startswith("field_"):
            vtableStruct.add(longPtr, 8, funcName, "Generated by RedMetaClassAnalyzer.py")
        else:
            signPtr = ensureDataType(funcName + "_sign", typeManager, 1, None)
            vtableStruct.add(signPtr, 8, funcName, "Generated by RedMetaClassAnalyzer.py")
    # Ensure the DataType in typeManager is updated
    typeManager.addDataType(vtableStruct, DataTypeConflictHandler.REPLACE_HANDLER)

    vtableStructPtr = ensureDataType(name + "_vtableStruct", typeManager, 1, None)
    dataType.replaceAtOffset(0, vtableStructPtr, 8, "vtable", "Generated by RedMetaClassAnalyzer.py")
