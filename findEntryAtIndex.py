#!/usr/bin/python3
import json

db = json.load(open("vtableDB.json"))
index = input("Index: ").strip()
if "0x" in index:
    index = str(int(index, 16) // 8)
index = index.zfill(3)

matches = {}

for key in db.keys():
    if index in db[key]:
        func = db[key][index]
        if func not in matches:
            matches[func] = []
        matches[func].append(key)

sorter = sorted([(len(x[1]), x[0]) for x in matches.items()], reverse=True)
for count, func in sorter:
    print(f"{func} with {count} matches:")
    print("  " + "\n  ".join(matches[func]))
