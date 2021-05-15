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