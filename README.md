# Enhancing Automotive Security

Trusted Applications for OP-TEE for compromise assessment and an authenticated encryption protocol for secure communication

## Compromise Assessment
### Usage

Create files.txt with the list of filenames(newline separated) in the directory on which you want to run compromise assessment. Run the following command in the normal world environment.
```
assess <flag> 
```

the value of flag can be: 
- 0 : calculates the root hash of the merkle tree in the secure storage
- 1 : calculates the root hash of the merkle tree and compares with the value in the secure storage
- 2 : deletes the root hash stored in the secure storage

## Authenticated Encryption
### Usage

```
authenticated_encryption <flag1> <flag2> 
```
flag1: 
- -x for the key-exchange protocols
- -m for the message exchange protocols

flag2: 
- -s for source and -t for target key exchange protocol
- -e for encryption and -d for decryption for message exchange protocol

<br>

The requirements for each of the protocols are as follows:
- Key Exchange - Source Protocol: This requires no input. Produces symmetric keys for message exchange and stores them in the secure storage. Uses RSA to encrypt and sign these keys. Creates two files - key_exchange.txt and sign.txt
- Key Exchange - Target Protocol: This requires key_exchange.txt and sign.txt. Stores the decrypted symmetric keys for message exchange in the secure storage after authentication.
- Message Exchange - Encryption: This requires message.txt as input and that key exchange has taken place. Creates two files - message.txt and mac.txt which contain the IV+ciphertext and the MAC respectively.
- Message Exchange - Decryption: This requires message.txt and mac.txt as input. Produces the decrypted message after authentication.
