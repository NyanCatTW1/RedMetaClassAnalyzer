#!/usr/bin/python3
print("Instructions:")
print("1. Find the vtableStruct you want to RE under AMDGen/Structs")
print("2. Right click on it and press 'Find Uses of'")
print("3. Once it's complete, select all uses with Ctrl+A and copy it by pressing Ctrl+C")
print("4. Paste the texts here and press enter **twice**")
print("5. Let the script handle the rest")

uses = {}
while True:
    inp = input()
    if inp.strip() == "":
        break
    if "->vtable->field_" not in inp:
        continue
    fieldName = "field_" + inp.split("->vtable->field_")[-1][:3]
    if fieldName not in uses.keys():
        uses[fieldName] = []
    uses[fieldName].append(inp)

uses = list(uses.items())
uses.sort(key=lambda x: (-len(x[1]), x[0]))

tab = '\t'
for item in uses:
    print(f"### {item[0]} ({len(item[1])})")
    for use in item[1]:
        print(f"`{use.replace(tab, '  ')}`")
