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
import json
import os

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

# Used to update existing functions from signature string
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.listing.Function import FunctionUpdateType

# Used for handling getAddress failure
from ghidra.program.model.address import AddressFormatException

verbose = False
# If importVtables is not empty, then *only* meta classes in the list will have their vtable processed
importVtables = []
# Computed by comparing the address of the actual function to the pointer in the vtable
# The first function in the vtable is always one of the destructors
# dyldOffset = 0x7dff20000000
dyldOffset = 0
# When set to True, discover the return type of functions by decompiling them
# Warning: It's slow and may take more than 10 minutes on large programs.
discoverReturnType = True


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
def getAddress(offset, applyDyldOffset=False):
    if applyDyldOffset:
        offset = int(offset, 16) + dyldOffset
        offset = hex(offset)[2:].replace("L", "")

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
                print("    Resizing {}/{} from {} bytes to {} bytes".format(
                    ret.getCategoryPath(), ret.getName(), ret.getLength(), forceStructSize))
            ret.replaceWith(StructureDataType(
                ret.getCategoryPath(), ret.getName(), forceStructSize))
        return ret

    # Create our own data type
    if ptrLevel == 0:
        targetLen = forceStructSize if forceStructSize is not None else 0
        if verbose:
            print("Creating {}-bytes struct data type {}".format(targetLen, typeName))
        ret = StructureDataType(CategoryPath(
            "/AMDGen/Structs"), typeName, targetLen, typeManager)
    else:
        prevType = ensureDataType(
            typeName, typeManager, ptrLevel - 1, forceStructSize)
        if verbose:
            print("Creating pointer data type " + makePtrTypeName(typeName, ptrLevel))
        ret = PointerDataType(prevType, typeManager)
    ret = typeManager.addDataType(ret, DataTypeConflictHandler.REPLACE_HANDLER)

    return ret


def strToFunc(funcStr, suffix=""):
    funcName = funcStr.split("(")[0].split(" ")[-1]
    funcType = FunctionDefinitionDataType(CategoryPath(
        "/AMDGen/FuncSigns"), funcName + "_sign" + suffix)

    callType = funcStr.split(" ")[0]
    funcType.setGenericCallingConvention(callTypes[callType])

    retType = funcStr.split(" ")[1]
    funcType.setReturnType(ensureDataType(retType.replace(
        "*", ""), typeManager, retType.count("*"), None))

    paraStrs = funcStr.split("(")[1].split(")")[0].split(", ")
    if (paraStrs[0] == "void"):
        return funcType

    parameters = []
    for paraStr in paraStrs:
        try:
            typeName, paraName = paraStr.split(" ")
            paraType = ensureDataType(typeName.replace(
                "*", ""), typeManager, typeName.count("*"), None)
            parameters.append(ParameterDefinitionImpl(paraName, paraType, ""))
        except Exception:
            pass
    funcType.setArguments(parameters)

    return funcType


def funcToStr(curFunc):
    funcSign = curFunc.getSignature(False)

    funcStr = invCallTypes[funcSign.getGenericCallingConvention()]
    funcStr += " " + curFunc.getReturnType().getName()  # Return type
    funcStr += " " + str(curFunc)  # Function name
    protoStr = funcSign.getPrototypeString(False)
    funcStr += "(" + protoStr.split("(")[-1].replace(" *", "*")  # Parameters
    return funcStr


def DBIndex(index):
    return str(index).zfill(3)


def askVtablePreference(title, dbStr, progStr):
    print("    {}\n          DB: {}\n        Prog: {}".format(title, dbStr, progStr))
    global globalVtablePreference, classVtablePreference
    if globalVtablePreference is not None:
        return globalVtablePreference
    if classVtablePreference is not None:
        return classVtablePreference

    modes = ["Prog and update DB",
             "Prog but don't update DB", "DB and update Prog"]
    optionTemplates = [
        "Always use {}", "Use {} in this meta class", "Use {} just for this conflict"]

    options = []
    for mode in modes:
        for template in optionTemplates:
            options.append(template.format(mode))

    choice = options.index(askChoice(title,
                                     "Which one should I use? (See console for details)",
                                     options, None))

    if choice % 3 == 0:
        globalVtablePreference = modes[choice // 3]
        return globalVtablePreference
    elif choice % 3 == 1:
        classVtablePreference = modes[choice // 3]
        return classVtablePreference
    elif choice % 3 == 2:
        return modes[choice // 3]


globalVtablePreference = None
classVtablePreference = None

# Change directory to script location
abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)

state = getState()
mem = currentProgram.getMemory()
funcManager = currentProgram.getFunctionManager()
codeManager = currentProgram.getCodeManager()
typeManager = currentProgram.getDataTypeManager()
symbolTable = currentProgram.getSymbolTable()

print("Renaming pointers in __got...")
got = mem.getBlock("__got")
print("Found __got at {}~{}".format(got.getStart(), got.getEnd()))

metaTypeNames = set(importVtables)

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

options = DecompileOptions()
# Prevent line wrapping
options.setMaxWidth(10000)
monitor = ConsoleTaskMonitor()
ifc = DecompInterface()
ifc.setOptions(options)
ifc.openProgram(currentProgram)

print("")
print("Retyping variables that uses OSMetaClassBase::safeMetaCast...")
metaCast = None
for func in funcManager.getFunctions(True):
    if "safeMetaCast" in func.getName():
        metaCast = func
        break

if metaCast is None:
    print("Warning: safeMetaCast not found, skipping variable retype")
else:
    print("Found safeMetaCast at {}".format(metaCast.getEntryPoint()))

    refs = getReferencesTo(metaCast.getEntryPoint())
    print("Found {} references to safeMetaCast".format(len(refs)))
    todoFuncs = []
    for xref in refs:
        func = funcManager.getFunctionContaining(xref.getFromAddress())
        if func is not None and func not in todoFuncs:
            todoFuncs.append(func)

    print("Found {} functions that uses safeMetaCast".format(len(todoFuncs)))

    retypeCounts = []
    for iter in range(25):
        if len(importVtables) != 0:
            print("Skipping variable retype")
            break

        print("Running pass {}/{}".format(iter + 1, 25))
        retypeCount = 0
        for func in todoFuncs:
            try:
                results = ifc.decompileFunction(func, 0, monitor)
                code = results.getDecompiledFunction().getC().split('\n')
            except AttributeError:
                continue

            funcName = [x for x in code if "::" in x][0][3:-3]
            castRefs = [
                x for x in code if "OSMetaClassBase::safeMetaCast(" in x]
            for castRef in castRefs:
                try:
                    parts = castRef.strip().split(" = ")
                    assert len(parts) == 2 and not any(
                        x in parts[0] for x in "()&! ")
                    varName = parts[0]
                    try:
                        className = parts[1].split(
                            "safeMetaCast(")[-1].split(")")[-2].strip()
                    except IndexError:
                        raise AssertionError

                    if className.endswith("__metaClass"):
                        className = className[:-len("__metaClass")]
                    elif "::" in className:
                        className = className.split("::")[0].replace("&", "")
                    elif className == "&gMetaClass":
                        # Class of "this"
                        className = funcName.split("::")[0]
                    else:
                        raise AssertionError

                    metaTypeNames.add(className)

                    try:
                        varSymbol = results.getHighFunction().getLocalSymbolMap().getNameToSymbolMap()[
                            str(varName)]
                    except KeyError:
                        raise AssertionError
                    dataType = ensureDataType(className, typeManager, 1, None)

                    if varSymbol.getDataType() != dataType:
                        if verbose:
                            print("    Retyping {} from {} to {} in {}".format(
                                varName, varSymbol.getDataType().getName(), makePtrTypeName(className, 1), funcName))
                        retypeCount += 1
                        # Here goes nothing...
                        HighFunctionDBUtil.updateDBVariable(
                            varSymbol, None, dataType, SourceType.ANALYSIS)
                except AssertionError:
                    pass
                    # print("Warning: Error processing code")
                    # print(" " * 4 + castRef.strip())
        print("Retyped {} variables".format(retypeCount))
        retypeCounts.append(retypeCount)
        if retypeCount == 0 or sum(retypeCounts[-5:]) == retypeCounts[-1] * 5:
            break

print("")
print("Setting up meta struct basic structure...")
demanglerPath = typeManager.getCategory(CategoryPath("/Demangler"))
dataTypes = demanglerPath.getDataTypes()
print("Found {} data types directly under /Demangler".format(len(dataTypes)))
metaDataTypes = []
for dataType in dataTypes:
    name = dataType.getName()
    if "*" not in name and ("_t" not in name or name in metaTypeNames):
        metaDataTypes.append(dataType)

blacklist = ["mach_timespec", "longlong", "IOPCIAddressSpace", "IOACPIAddress"]
newStructs = typeManager.getCategory(CategoryPath("/AMDGen/Structs"))
if newStructs is not None:
    for dataType in newStructs.getDataTypes():
        name = dataType.getName()
        if "*" not in name and "_vtableStruct" not in name and not name.startswith("FuncDef") and name not in blacklist:
            metaDataTypes.append(dataType)

print("Found {} meta structs".format(len(metaDataTypes)))

ulong = ensureDataType("ulong", typeManager, 0, None)
ulongPtr = ensureDataType("ulong", typeManager, 1, None)

callTypes = {
    "__stdcall": GenericCallingConvention.stdcall,
    "__cdecl": GenericCallingConvention.cdecl,
    "__fastcall": GenericCallingConvention.fastcall,
    "__thiscall": GenericCallingConvention.thiscall,
    "__vectorcall": GenericCallingConvention.vectorcall
}

# https://stackoverflow.com/questions/2568673/inverse-dictionary-lookup-in-python
invCallTypes = {v: k for k, v in callTypes.items()}
invCallTypes[GenericCallingConvention.unknown] = "__stdcall"

try:
    vtableDB = json.load(open("vtableDB.json"))
except Exception:
    print("Warning: Failed to load vtableDB.json!")
    vtableDB = {}

print("")
print("Creating and assigning vtable structs...")

for i in range(len(metaDataTypes)):
    print("{}/{}:".format(i + 1, len(metaDataTypes)))
    dataType = metaDataTypes[i]
    name = dataType.getName()

    if len(importVtables) != 0 and name not in importVtables:
        print("    Skipping " + name)
        continue

    vtable = {}
    classVtablePreference = None

    # Find vtable address
    vtableAddr = None
    func = next((v for v in funcManager.getFunctions(
        True) if name == v.getName()), None)
    if func is not None:
        try:
            results = ifc.decompileFunction(func, 0, monitor)
            code = results.getDecompiledFunction().getC().splitlines()
            matches = [v for v in code if "this->vtable = " in v or "this = " in v]
            if len(matches) != 0:
                arg = matches[0].split(" ")[-1].split(")")[-1].replace("&", "").strip()
                valid = arg.startswith("DAT_") or arg.startswith(
                    "PTR_") or arg.startswith(name + "_")
                extractedAddr = getAddress(
                    arg.split("_")[-1][:-1].replace(";", "")) if valid else None

                if vtableAddr is None:
                    vtableAddr = extractedAddr
                elif vtableAddr != extractedAddr:
                    print("    Error: Conflicting vtable addresses for {}".format(name))
                    print(vtableAddr, code)
                    raise AssertionError
        except AttributeError:
            pass

    if vtableAddr is not None:
        # Analyze vtable
        print("    Analyzing {} vtable at {}...".format(name, vtableAddr))
        addr = vtableAddr
        i = 0

        if name not in vtableDB:
            vtableDB[name] = {}

        funcOccurances = {}

        while True:
            try:
                ptrAddr = getAddress(readMem(addr, 8), applyDyldOffset=True)
                if ptrAddr.getOffset() == 0:
                    break
            except AddressFormatException:
                break

            func = funcManager.getFunctionContaining(ptrAddr)
            if func is not None:
                if discoverReturnType:
                    try:
                        code = ifc.decompileFunction(func, 0, monitor).getDecompiledFunction().getC()
                        signLine = [x.strip() for x in code.split("\n") if "/*" not in x and len(x.strip()) != 0][0]
                        retType = " ".join(signLine.split("(")[0].split(" ")[:-1])

                        # Remove call convention annotation, if any
                        for callConvention in ["MSABI", "syscall", "__thiscall"]:
                            retType = retType.replace(" {}".format(callConvention), "")

                        retTypeName = retType.replace("*", "").strip()
                        retTypePtrLevel = retType.count("*")
                        func.setReturnType(ensureDataType(retTypeName, typeManager, retTypePtrLevel, None), SourceType.ANALYSIS)
                    except Exception:
                        print("    Warning: Failed to discover return type of " + str(func))

                funcName = str(func)
                funcStr = funcToStr(func)
                funcSign = func.getSignature(False)
                if vtableDB[name].get(DBIndex(i), funcStr) != funcStr:
                    title = "Merge conflict on {} field_{}".format(
                        name, DBIndex(i))
                    prefer = askVtablePreference(
                        title, vtableDB[name][DBIndex(i)], funcStr)
                    print("        About to use {}".format(prefer))

                    if prefer == "Prog and update DB":
                        vtableDB[name][DBIndex(i)] = funcStr
                    elif prefer == "Prog but don't update DB":
                        pass
                    elif prefer == "DB and update Prog":
                        funcStr = vtableDB[name][DBIndex(i)]
                        funcName = funcStr.split("(")[0].split(" ")[-1]
                        funcSign = strToFunc(funcStr)
                        func.setCallingConvention(funcStr.split(" ")[0])
                        func.setReturnType(
                            funcSign.getReturnType(), SourceType.ANALYSIS)
                        if "::" in funcName:
                            func.setCallFixup(funcName.split("::")[0])
                        func.setName(funcName.split("::")
                                     [-1], SourceType.ANALYSIS)

                        # ParameterImpl vs ParameterDefinition smh
                        paras = ArrayList()
                        for para in funcSign.getArguments():
                            paras.add(ParameterImpl(para.getName(),
                                      para.getDataType(), currentProgram))
                        func.replaceParameters(
                            paras, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, True, SourceType.ANALYSIS)
                    else:
                        # If this happens I made a typo lol
                        raise AssertionError
                else:
                    vtableDB[name][DBIndex(i)] = funcStr
                vtable[i] = funcName

                if funcName not in funcOccurances:
                    funcOccurances[funcName] = 0
                occurId = funcOccurances[funcName]
                funcOccurances[funcName] += 1

                funcType = FunctionDefinitionDataType(CategoryPath(
                    "/AMDGen/FuncSigns"), funcName + "_sign_" + str(occurId), funcSign)
                typeManager.addDataType(
                    funcType, DataTypeConflictHandler.REPLACE_HANDLER)

            addr = addr.add(8)
            i += 1

            if discoverReturnType and i % 100 == 0:
                print("    Processed {} functions".format(i))

            if dyldOffset != 0 and len(symbolTable.getSymbols(addr)) != 0:
                break
        vtableDB[name]["length"] = max(
            vtableDB[name].get("length", 0), len(vtable))
        vtable["length"] = vtableDB[name]["length"]

    funcOccurances = {}
    if name in vtableDB.keys():
        length = vtableDB[name]["length"]
        for i in range(length):
            if i in vtable:
                continue

            funcStr = vtableDB[name].get(DBIndex(i))
            if funcStr is not None:
                funcName = funcStr.split("(")[0].split(" ")[-1]
                if funcName not in funcOccurances:
                    funcOccurances[funcName] = 0
                occurId = funcOccurances[funcName]
                funcOccurances[funcName] += 1

                typeManager.addDataType(strToFunc(
                    funcStr, "_" + str(occurId)), DataTypeConflictHandler.REPLACE_HANDLER)
                vtable[i] = funcName
        vtable["length"] = max(vtable.get("length", 0), length)
        vtableDB[name]["length"] = vtable["length"]

    if len(vtable) == 0:
        print("    Warning: Failed to find vtable for {}".format(name))
        continue

    print("    Creating {}_vtableStruct with {} entries...".format(
        name, vtable["length"]))
    vtableStruct = ensureDataType(name + "_vtableStruct", typeManager, 0, 0)
    vtableStruct.deleteAll()
    funcOccurances = {}

    for i in range(vtable["length"]):
        funcName = vtable.get(i)
        if funcName is None:
            funcName = "field_" + str(i).zfill(3)
            vtableStruct.add(ulongPtr, 8, funcName,
                             "Generated by RedMetaClassAnalyzer.py")
        else:
            if funcName not in funcOccurances:
                funcOccurances[funcName] = 0
            occurId = funcOccurances[funcName]
            funcOccurances[funcName] += 1

            signPtr = ensureDataType(
                funcName + "_sign_" + str(occurId), typeManager, 1, None)
            vtableStruct.add(signPtr, 8, funcName,
                             "Generated by RedMetaClassAnalyzer.py")
    # Ensure the DataType in typeManager is updated
    typeManager.addDataType(
        vtableStruct, DataTypeConflictHandler.REPLACE_HANDLER)

    vtableStructPtr = ensureDataType(
        name + "_vtableStruct", typeManager, 1, None)
    if dataType.isZeroLength():
        dataType.add(vtableStructPtr, 8, "vtable",
                     "Generated by RedMetaClassAnalyzer.py")
        # Ensure the DataType in typeManager is updated
        typeManager.addDataType(
            dataType, DataTypeConflictHandler.REPLACE_HANDLER)
    elif dataType.getComponentContaining(0) is None or dataType.getComponentContaining(0).getFieldName() != "0":
        dataType.replaceAtOffset(
            0, vtableStructPtr, 8, "vtable", "Generated by RedMetaClassAnalyzer.py")
        # Ensure the DataType in typeManager is updated
        typeManager.addDataType(
            dataType, DataTypeConflictHandler.REPLACE_HANDLER)

with open("vtableDB.json", "w") as f:
    json.dump(vtableDB, f, sort_keys=True, indent=4)
