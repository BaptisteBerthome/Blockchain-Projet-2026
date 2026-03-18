import json
import sys   

if len(sys.argv) != 2:
    print("Usage: python testjson.py <json_file>")
    sys.exit(1)

if __name__ == "__main__":
    json_file = sys.argv[1]
    print(f"Lecture de {json_file}")
    with open(json_file) as f:
        d = json.load(f)
        print(json.dumps(d, indent=4, sort_keys=False))