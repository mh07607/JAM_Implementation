test_vector_path = "jamtestvectors/codec/tiny/tickets_extrinsic"

with open(test_vector_path+'.bin', 'rb') as file:
    print(file.read().hex())