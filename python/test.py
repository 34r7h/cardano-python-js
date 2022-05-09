import sys
import json
 
args = list(sys.argv[1:]) 
# sys.argv contains script at index 0, followed by supplied args
# [1:] shorthand to remove index 0 from args

print(json.dumps(args))
# json.dumps converts to JSON-parsable
