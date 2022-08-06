# A helper script that recursively fixes the signature of functions that takes in CAILData* as parameter
# @author Nyan Cat
# @category A_Red
# @keybinding
# @menupath
# @toolbar

# pyright: reportMissingImports=false
# pyright: reportUndefinedVariable=false

from java.util import ArrayList

from ghidra.util.datastruct import ListAccumulator
from ghidra.app.plugin.core.navigation.locationreferences.ReferenceUtils import findDataTypeReferences
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.listing.Function import FunctionUpdateType
from ghidra.program.model.symbol import SourceType


def getDataType(typeName, typeManager):
    matches = ArrayList()
    typeManager.findDataTypes(typeName, matches)

    if len(matches) > 1:
        print("Warning: Using the first " + typeName)
    elif len(matches) == 0:
        return None

    return matches[0]


typeName = "PP_Instance"
varName = "ppInstance"

funcManager = currentProgram.getFunctionManager()
typeManager = currentProgram.getDataTypeManager()
cailData = getDataType(typeName, typeManager)

while True:
    print("Finding references...")
    accu = ListAccumulator()
    findDataTypeReferences(accu, cailData, currentProgram, True, None)
    print("Found {} references".format(accu.size()))

    boldStart = "<span style=\"background-color: #a3e4d7; color: black;\"><b><font size=4>"

    funcs = set()
    for ref in accu:
        refText = ref.getContext().getBoldMatchingText().replace("&nbsp;", " ")
        callSign = refText.split(boldStart)[0]
        if any(callSign.endswith(x) for x in ["((long)", "((ulong)", "((int)", "((uint)",
                                              "((long *)", "((ulong *)", "((int *)", "((uint *)"]):
            funcName = callSign.split(" ")[-1].split("(")[0]
            if funcName != "":
                funcs.add(funcName)
    print("Found {} functions".format(len(funcs)))

    count = 0
    cailDataPtr = getDataType(typeName + " *", typeManager)
    for func in funcManager.getFunctions(True):
        if func.getName() not in funcs:
            continue

        paras = func.getParameters()
        i = 0
        while i < len(paras):
            if not paras[i].isAutoParameter():
                break
            i += 1
        if i == len(paras):
            continue

        paras[i] = ParameterImpl(varName, cailDataPtr, currentProgram)

        # A hack to convert Python List to Java ArrayList
        jParas = ArrayList()
        for para in paras:
            jParas.add(para)

        func.replaceParameters(jParas, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                               True, SourceType.USER_DEFINED)
        count += 1
    print("Modified {} functions".format(count))
    if count == 0:
        break
