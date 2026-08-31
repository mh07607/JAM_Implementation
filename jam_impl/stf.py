import json
import os

def join():
    pass

def accumulate():
    pass

# Refine should hopefully not be needed for ML1
# def refine():
#    pass

if __name__ == "__main__":
    state = None
    print(sorted([i for i in os.listdir("./jamtestvectors/traces/fallback/") if i.endswith(".json")]))
    with open ("./jamtestvectors/traces/fallback/genesis.json", "r") as f:
        file = json.load(f)
        block_header = file["header"]