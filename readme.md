# Labo 1 CAA

## 1. Generic Composition Implementation
Generic composition combines a MAC and an encryption algorithm in a generic way to obtain authen-
ticated encryption. We will study the following three algorithms:
- Encrypt-then-MAC 
- MAC-then-encrypt 
- Encrypt-and-MAC

If needed, you will find more details about these constructions in the following paper: https://link.springer.com/content/pdf/10.1007/3-540-44448-3_41.pdf.
1. Implement all three algorithms (encryption and decryption). For the encryption primitive, you  can use AES-CTR, for the MAC, you can use HMAC. Make sure that the key sizes are coherent. 
Justify your choices in your report.

Hint: Useful packages in pycryptodome: Crypto.Cipher.AES, Crypto.Hash.HMAC, Crypto.Random 

Hint2: Be careful in the use of IVs. Some constructions are not as straightforward as they look.
2. Implement now the same algorithms with AES-CBC and CMAC as underlying algorithms. What can you say about the size of the resulting ciphertext? Justify.

## 2. IoT Scenarios
We will now analyse different IoT scenarios in which you will have to make algorithmic choices. To
simplify, we will only consider the following five algorithms:
- AES-ECB
- AES-CBC
- AES-CTR
- AES-GCM
- Chacha20-Poly1305

When you explain your algorithmic choices, do not forget to specify the key sizes.
1. The IoT device sends 256-bit messages to a recipient device. The ciphertext should have the same
size as the plaintext due to physical constraints. We are considering only passive adversaries.
Devices do not have any memory except for storing the symmetric key. For each of the five
algorithms, justify if it can be used in this scenario or not. What is your final proposition? Be
precise and analyse the security of your answer.
2. The IoT device has to send every hour during a year a 8-bit message that gives instructions
to another device. Each bit of the message is mapped to a particular behavior of the recipient
(ex: turn the green light on). The emitting and receiving devices both have a 16-bit memory that
you can use as you wish. They both also have enough additionnal space to store a symmetric
key. The physical constraints do not allow you to send more than 64 bits per hour. We want to
protect against an active adversary that can replay messages. The messages have also to stay
confidential. For each of the five algorithms, justify if it can be used in this scenario or not. You
can also slightly modify them. What is your final proposition? Be precise, justify your answer and
analyse its security.