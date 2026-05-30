with open("jamtestvectors/codec/tiny/assurances_extrinsic.bin", "rb") as f:
    a = f.readlines()
    for line in a:
        print(line)
        print("\n")