# A simple python script for Rabin Signature

1. Generate key pairs with a seed. **Replace** `nrabin` in `rabin.py` with the `nrabin` in the output.
```bash
> python rabin.py G 01
 generate primes ... 
nrabin =  0x15525796ddab817a3c54c4bea4ef564f090c5909b36818c1c13b9e674cf524aa3387a408f9b63c0d88d11a76471f9f2c3f29c47a637aa60bf5e120d1f5a65221
```

2. Sign a message: get number of padding bytes and signature
```bash
> python rabin.py S 00112233445566778899aabbccddeeff
paddingnum: 4
 digital signature:
 0x12f1dd2e0965dc433b0d32b86333b0fb432df592f6108803d7afe51a14a0e867045fe22af85862b8e744700920e0b7e430a192440a714277efb895b51120e4cc
```

3. Verify signature with results from step 2
```bash
> python rabin.py V 00112233445566778899aabbccddeeff 4 12f1dd2e0965dc433b0d32b86333b0fb432df592f6108803d7afe51a14a0e867045fe22af85862b8e744700920e0b7e430a192440a714277efb895b51120e4cc
result of verification: True
```