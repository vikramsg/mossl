from collections import List

from python import Python, PythonObject


fn to_python_bytes(data: List[UInt8]) raises -> PythonObject:
    var builtins = Python.import_module("builtins")
    var py_list = builtins.list()
    for i in range(len(data)):
        py_list.append(Int(data[i]))
    return builtins.bytes(py_list)


fn from_python_bytes(py_bytes: PythonObject) raises -> List[UInt8]:
    var out = List[UInt8]()
    var builtins = Python.import_module("builtins")
    var length = Int(builtins.len(py_bytes))
    for i in range(length):
        out.append(UInt8(Int(py_bytes[i])))
    return out^


fn assert_equal_bytes(
    mojo_bytes: List[UInt8], py_bytes: PythonObject, msg: String
) raises:
    var builtins = Python.import_module("builtins")
    var py_len = Int(builtins.len(py_bytes))
    if len(mojo_bytes) != py_len:
        raise Error(
            msg
            + ": length mismatch: mojo="
            + String(len(mojo_bytes))
            + " py="
            + String(py_len)
        )

    for i in range(py_len):
        if mojo_bytes[i] != UInt8(Int(py_bytes[i])):
            raise Error(msg + ": byte mismatch at index " + String(i))
