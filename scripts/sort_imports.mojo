from sys import argv
from collections import List
from os import listdir, path

fn is_stdlib(m: String) -> Bool:
    return m == "collections" or m == "os" or m == "sys" or m == "testing" or m == "math" or m == "time" or m == "pathlib" or m == "random" or m == "builtin"

fn is_local(m: String) -> Bool:
    return m == "crypto" or m == "tls"

fn sort_list(mut l: List[String]):
    for i in range(len(l)):
        for j in range(len(l) - 1):
            if l[j] > l[j+1]:
                var tmp = l[j]
                l[j] = l[j+1]
                l[j+1] = tmp

fn sort_mojo_imports(file_path: String) raises:
    if not file_path.endswith(".mojo"):
        return

    var f = open(file_path, "r")
    var content = f.read()
    f.close()

    var lines = content.split("\n")
    var stdlib_imports = List[String]()
    var thirdparty_imports = List[String]()
    var local_imports = List[String]()
    var other_lines = List[String]()
    var leading_lines = List[String]()
    
    var stage = 0 # 0: leading (docstrings/comments), 1: imports, 2: code
    
    for i in range(len(lines)):
        var line = String(lines[i])
        var l = line.strip()
        
        if stage == 0:
            if l.startswith("from ") or l.startswith("import "):
                stage = 1
            elif l == "":
                leading_lines.append(line)
                continue
            else:
                # Still docstring or comment
                leading_lines.append(line)
                continue

        if stage == 1:
            if l.startswith("from ") or l.startswith("import "):
                var parts = l.split(" ")
                var module_name = String("")
                if len(parts) > 1:
                    module_name = String(parts[1].split(".")[0])
                
                if is_stdlib(module_name):
                    stdlib_imports.append(String(l))
                elif is_local(module_name):
                    local_imports.append(String(l))
                else:
                    thirdparty_imports.append(String(l))
            elif l == "":
                continue
            else:
                stage = 2
                other_lines.append(line)
        else:
            other_lines.append(line)

    if len(stdlib_imports) == 0 and len(thirdparty_imports) == 0 and len(local_imports) == 0:
        return

    sort_list(stdlib_imports)
    sort_list(thirdparty_imports)
    sort_list(local_imports)

    var out = open(file_path, "w")
    
    for i in range(len(leading_lines)):
        out.write(leading_lines[i] + "\n")
        
    var wrote_anything = False
    if len(stdlib_imports) > 0:
        for i in range(len(stdlib_imports)):
            out.write(stdlib_imports[i] + "\n")
        wrote_anything = True
        
    if len(thirdparty_imports) > 0:
        if wrote_anything: out.write("\n")
        for i in range(len(thirdparty_imports)):
            out.write(thirdparty_imports[i] + "\n")
        wrote_anything = True
        
    if len(local_imports) > 0:
        if wrote_anything: out.write("\n")
        for i in range(len(local_imports)):
            out.write(local_imports[i] + "\n")
        wrote_anything = True

    if wrote_anything:
        out.write("\n")

    for i in range(len(other_lines)):
        out.write(other_lines[i])
        if i < len(other_lines) - 1:
            out.write("\n")
    out.close()

fn process_path(p: String) raises:
    if path.isfile(p):
        sort_mojo_imports(p)
    elif path.isdir(p):
        var items = listdir(p)
        for i in range(len(items)):
            var name = items[i]
            if name == ".pixi" or name == ".git":
                continue
            var full_path = path.join(p, name)
            process_path(full_path)

fn main() raises:
    if len(argv()) < 2:
        return

    for i in range(1, len(argv())):
        process_path(argv()[i])