package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"os"
)

/*
 * Source borrowed from Django project.
 * https://github.com/django/django/blob/master/django/utils/crypto.py
 */
func SaltedHMAC(key, value, secret string) string {
	hsh := hmac.New(sha1.New, []byte(key + secret))
	hsh.Write([]byte(value))
	return hex.EncodeToString(hsh.Sum(nil))
}

var inputFlag = flag.String("input", "", "Newline separated input file")

func init() {
	flag.Parse()
}

func main() {
	if *inputFlag == "" {
		flag.Usage()
		return
	}
	input, err := os.Open(*inputFlag)
	if err != nil {
		panic(err)
	}
	defer input.Close()
	output, err := os.Create("out.txt")
	if err != nil {
		panic(err)
	}
	defer output.Close()
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		hsh := SaltedHMAC(HMAC_SALT, scanner.Text(), HMAC_SECRET)
		_, err = output.WriteString(hsh + "\n")
		if err != nil {
			panic(err)
		}
	}
	output.Sync()
	if err := scanner.Err(); err != nil {
		panic(err)
	}
}
