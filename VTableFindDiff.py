#!/usr/bin/python3
import sys
import json


def removeVersion(func):
    if func is None:
        return "None"

    func = getFuncName(func)

    keywords = ["X5000", "X6000", "Vega10", "Navi10", "GFX9", "GFX10"]
    for keyword in keywords:
        func = func.replace(keyword, "")
    return func


def getFuncName(func):
    if func is None:
        return "None"
    return func.split("(")[0].split(" ")[-1]


if len(sys.argv) < 3:
    print(f"Usage: {sys.argv[0]} typeA typeB")
    sys.exit()

db = json.load(open("vtableDB.json"))
a = db[sys.argv[1]]
b = db[sys.argv[2]]

keys = set()
keys.update(a.keys())
keys.update(b.keys())
keys.remove("length")
keys = sorted(list(keys))

aNoVer = {}
bNoVer = {}

misaligns = []
for key in keys:
    A = a.get(key, None)
    B = b.get(key, None)

    aNoVer[key] = removeVersion(A)
    bNoVer[removeVersion(B)] = key
    if removeVersion(A) != removeVersion(B):
        offset = hex(int(key) * 8)
        misaligns.append("field_" + offset)
        print(f"{key} ({offset.ljust(5)}): {getFuncName(A).ljust(80)}  {getFuncName(B)}")


matches = []
while True:
    line = input().strip()
    if line == "":
        break
    if any(x in line for x in misaligns):
        addr = line.split("\t")[0]
        offset = line.split("field_")[-1].split(")")[0]
        key = str(int(offset, 16) // 8).rjust(3, "0")

        try:
            fixed = bNoVer[aNoVer[key]]
        except KeyError:
            fixed = None

        matches.append(str((addr, offset, key, aNoVer[key], fixed)))
print("\n".join(matches))

