package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/exec"
)

func FileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

func DeleteFile(filename string) error {
	if FileExists(filename) {
		return os.Remove(filename)
	}
	return nil
}

func generate() error {
	cmd := exec.Command("python3", "./certificate.py")
	if err := cmd.Run(); err != nil {
		return err
	}

	file1, file2 := FileExists("./jetbra.key"), FileExists("./jetbra.pem")
	if !file1 && !file2 {
		return errors.New("generate failed")
	}

	return nil
}

func generateEqualResult() (string, error) {
	var crt *x509.Certificate

	crtPem, err := os.ReadFile("./jetbra.pem")
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(crtPem)

	crt, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}

	rootCertificatePem, err := os.ReadFile("./root_certificate.pem")
	if err != nil {
		return "", err
	}

	x := new(big.Int).SetBytes(crt.Signature)
	y := 65537
	block1, _ := pem.Decode(rootCertificatePem)
	rootCertificate, err := x509.ParseCertificate(block1.Bytes)
	if err != nil {
		return "", err
	}

	p, _ := rootCertificate.PublicKey.(*rsa.PublicKey)
	z := p.N
	zp, _ := crt.PublicKey.(*rsa.PublicKey)

	r := new(big.Int)
	r.Exp(x, big.NewInt(int64(y)), zp.N)
	output := fmt.Sprintf("EQUAL,%d,%d,%d->%d", x, y, z, r)

	return output, nil
}

func init() {
	DeleteFile("./jetbar.key")
	DeleteFile("./jetbra.pem")
	DeleteFile("./power.txt")
}

func main() {
	if err := generate(); err != nil {
		log.Fatal(err)
	}
	filePath := "./power.txt"
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	content, err := generateEqualResult()
	if err != nil {
		log.Fatal(err)
	}
	_, err = file.WriteString(content)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("generate success")
}
