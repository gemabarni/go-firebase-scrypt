package main

import "fmt"
import "github.com/gemabarni/go-firebase-scrypt/encoder"

func main() {
	password := "one two three four five six seven eight nine ten"
	saltBase := "Rx4UJViMrCVJJA=="
	saltSeparator := "Bw=="
	signerKey := "NkZlKPkYEFfnbh1nYTfLsbqQnQ6jyRV4itK7iUD+hjO96tsAYhBG40BVS3AuJyiwHinqc5RR3oA+lppOXPNRmw=="

	result, _ := encoder.Encode(saltBase, saltSeparator, signerKey, password, 14, 8)
	fmt.Println(result)
}
