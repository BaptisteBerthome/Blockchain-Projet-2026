import json

print("Lecture")
with open('autotest_chain.json') as f:
    d = json.load(f)
    print(json.dumps(d, indent=4, sort_keys=False))
