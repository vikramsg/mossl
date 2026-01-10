# Calling Mojo from Python

Mojo is designed to be a high-performance alternative to Python while maintaining seamless interoperability. This document explains how to call Mojo code from Python, ensuring maximum performance through compilation.

## 1. Overview

Mojo code can be called from Python in two main ways:
1. **Ahead-of-Time (AOT) Compilation**: Compiling Mojo code into a shared library (`.so`, `.dylib`) that Python can import. This is the recommended way for production.
2. **Just-In-Time (JIT) / Automatic Compilation**: Using `mojo.importer` in Python to compile Mojo files on demand.

In both cases, the Mojo code is **fully optimized** by the Mojo compiler.

## 2. Preparing Mojo Code for Python (AOT)

To expose Mojo functions to Python, you must define a special initialization function named `PyInit_<module_name>` and use `PythonModuleBuilder` to register your functions.

### Example: `math_utils.mojo`

```mojo
from python import PythonObject
from python.bindings import PythonModuleBuilder

# Mojo functions intended for Python typically take PythonObject arguments
# and return a PythonObject.
fn add(a: PythonObject, b: PythonObject) raises -> PythonObject:
    return PythonObject(Int(a) + Int(b))

@export
fn PyInit_math_utils() -> PythonObject:
    try:
        var m = PythonModuleBuilder("math_utils")
        m.def_function[add]("add")
        return m.finalize()
    except e:
        # Return an empty object on error
        return PythonObject()
```

- **`@export`**: Required on the `PyInit` function so the linker makes it visible to Python.
- **`PyInit_<module_name>`**: Must match the filename (without extension) and the name passed to `PythonModuleBuilder`.
- **`PythonModuleBuilder`**: Located in `python.bindings`.
- **`m.def_function[fn_name]("python_name")`**: Registers the function.
- **`m.finalize()`**: Completes the module and returns the Python object.

## 3. Building the Extension

Compile the Mojo module into a shared library:

```bash
mojo build --emit shared-lib -O3 math_utils.mojo -o math_utils.so
```

- `--emit shared-lib`: Produces a dynamic library.
- `-O3`: Enables maximum optimizations.
- `-o math_utils.so`: The output filename must match the module name.

## 4. Using the Extension in Python

```python
import math_utils

result = math_utils.add(10, 20)
print(f"Result: {result}") # Output: 30
```

## 5. Automatic Importer (Development)

For development, you can use `mojo.importer` to import `.mojo` files directly. This requires the `mojo` package to be installed in your Python environment.

```python
import mojo.importer
import math_utils # This will compile math_utils.mojo if it's in sys.path
```

*Note: The `math_utils.mojo` file must still contain the `PyInit_math_utils` function as described above.*