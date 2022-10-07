import jsonschema
import json
import sys

if __name__ == "__main__":
    schema = json.load(open(sys.argv[1]))
    document = json.load(open(sys.argv[2]))
    jsonschema.validate(document, schema)