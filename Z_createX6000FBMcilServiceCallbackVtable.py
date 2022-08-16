# A helper script to populate vtable in _MCIL_SERVICE_CALLBACKS of AmdAppleMcilServices
# @author Nyan Cat
# @category A_Red
# @keybinding
# @menupath
# @toolbar

# pyright: reportMissingImports=false
# pyright: reportUndefinedVariable=false

from java.util import ArrayList

from ghidra.program.model.data import CategoryPath, FunctionDefinitionDataType, PointerDataType
from ghidra.program.model.data import DataTypeConflictHandler


def getDataType(typeName, typeManager):
    matches = ArrayList()
    typeManager.findDataTypes(typeName, matches)

    if len(matches) > 1:
        print("Warning: Using the first " + typeName)
    elif len(matches) == 0:
        return None

    return matches[0]


funcManager = currentProgram.getFunctionManager()
typeManager = currentProgram.getDataTypeManager()

funcNames = ['dummyCallBack', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', '_MCIL_DelayInMicroseconds', 'dummyCallBack', '_MCIL_GetRegistrykey', 'dummyCallBack', '_MCIL_SyncExecution', 'allocateMemory', 'releaseMemory', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', '_MCIL_QuerySystemInfo', 'isAsicCapEnabled', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', '_MCIL_CopyMemory', '_MCIL_ZeroMemory', 'dummyCallBack', '_MCIL_ModifyRegister', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', '_MCIL_InterpretAddress', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', 'obtainIri', 'dummyCallBack', 'getMemoryAddressList', 'allocateMemoryInDescriptor', 'freeMemoryInDescriptor', 'dummyCallBack', 'dummyCallBack', '_MCIL_LockMemory', '_MCIL_UnLockMemory', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', '_MCIL_InterlockedList', '_MCIL_LookasideList', 'DPC', '_MCIL_KernelEvent', 'dummyCallBack', '_MCIL_WorkerThread', '_MCIL_SystemTimestamp', '_MCIL_GetExecutionLevel', '_MCIL_InterlockedCompareExchange', '_MCIL_InterlockedExchange', '_MCIL_InterlockedExchangeAdd', '_MCIL_InterlockedIncrement', '_MCIL_InterlockedDecrement', '_MCIL_InterlockedCompareExchangePointer', '_MCIL_InterlockedExchangePointer', '_MCIL_SpinLock', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', '_MCIL_AcquireOperationPermission', '_MCIL_ReleaseOperationPermission', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack', 'dummyCallBack']
# funcNames = ["AtiAppleCailServices::" + x for x in funcNames]
done = [False] * len(funcNames)
ptrs = [None] * len(funcNames)

for func in funcManager.getFunctions(True):
    fullName = str(func)
    funcName = fullName.split("::")[-1]
    if funcName not in funcNames:
        continue

    funcSign = func.getSignature(False)

    funcType = FunctionDefinitionDataType(CategoryPath("/AMDGen/FuncSigns"), funcName + "_sign", funcSign)
    funcType = typeManager.addDataType(funcType, DataTypeConflictHandler.REPLACE_HANDLER)
    ptrType = PointerDataType(funcType, typeManager)
    ptrType = typeManager.addDataType(ptrType, DataTypeConflictHandler.REPLACE_HANDLER)

    for i in range(len(funcNames)):
        if funcNames[i] == funcName:
            assert not done[i]
            done[i] = True
            ptrs[i] = ptrType
            funcNames[i] = fullName

print(done)
assert all([done[i] or funcNames[i] is None for i in range(len(funcNames))])

serviceCallback = getDataType("_MCIL_SERVICE_CALLBACKS", typeManager)
for i in range(len(funcNames)):
    if funcNames[i] is None:
        continue
    serviceCallback.replaceAtOffset(8 * (i + 2), ptrs[i], 8, funcNames[i], "Generated by Z_createX6000FBMcilServiceCallbackVtable.py")