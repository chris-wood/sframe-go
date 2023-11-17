import sys
import json

if "header_test_vectors" in sys.argv[1]:
    with open(sys.argv[1]) as file:
        lines = [line.rstrip() for line in file]
        vectors = []
        i = 0
        while True:
            if i >= len(lines):
                break
            kid = lines[i].replace("kid: 0x", "")
            ctr = lines[i+1].replace("ctr: 0x", "")
            header = lines[i+2].replace("header: ", "")
            i += 4
            vectors.append({
                "kid": kid,
                "ctr": ctr,
                "header": header,
            })
        print(json.dumps(vectors))
        