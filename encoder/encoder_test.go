package encoder

import (
	"bufio"
	"encoding/csv"
	"io"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

const ROUNDS = 14
const MEMCOST = 8
const SIGNER_KEY_1 = "NkZlKPkYEFfnbh1nYTfLsbqQnQ6jyRV4itK7iUD+hjO96tsAYhBG40BVS3AuJyiwHinqc5RR3oA+lppOXPNRmw=="
const SIGNER_KEY_2 = "U01Ba7WbeBZyY/HjvbEp+N9KkB2h/oF7uSSbBSCj803usz1GV7YIhM+LlusLiU+t3qbz8hh5PLOUSekExEY04w=="
const SALT_SEPARATOR = "Bw=="

type testCase struct {
	Password string
	Expected string
	Salt     string
}

func readTestCases(path string) []testCase {
	testCaseFile, _ := os.Open(path)
	reader := csv.NewReader(bufio.NewReader(testCaseFile))

	var testCases []testCase
	for {
		line, error := reader.Read()

		if error == io.EOF {
			break
		} else if error != nil {
			log.Fatal(error)
		}

		testCases = append(testCases, testCase{
			Password: line[0],
			Expected: line[1],
			Salt:     line[2],
		})
	}

	return testCases
}

func TestEncode(t *testing.T) {
	testCases1 := readTestCases("test_cases/1.csv")
	testCases2 := readTestCases("test_cases/2.csv")
	saltBase := "42xEC+ixf3L2lw=="
	saltSeparator := "Bw=="
	signerKey := "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA=="
	password := "hunter2"
	expected := "70k8Vg5B3/OrvJOiqusnasv0dLcBHoDAqJrJr7TRLBfMw4MitWx51YXJYFdGiyMbMeKtWtLf5HiBDcN0SUOm4A=="

	t.Run("simple test", func(t *testing.T) {
		result, err := Encode(saltBase, saltSeparator, signerKey, password, ROUNDS, MEMCOST)
		assert.Nil(t, err)
		assert.Equal(t, expected, result)
	})

	t.Run("invalid salt base", func(t *testing.T) {
		_, err := Encode("invalid", saltSeparator, signerKey, password, ROUNDS, MEMCOST)
		assert.NotNil(t, err)
	})

	t.Run("invalid salt separator", func(t *testing.T) {
		_, err := Encode(saltBase, "invalid", signerKey, password, ROUNDS, MEMCOST)
		assert.NotNil(t, err)
	})

	t.Run("invalid signer key", func(t *testing.T) {
		_, err := Encode(saltBase, saltSeparator, "invalid", password, ROUNDS, MEMCOST)
		assert.NotNil(t, err)
	})

	for _, testCase := range testCases1 {
		t.Run("Batch test 1", func(t *testing.T) {
			result, err := Encode(testCase.Salt, SALT_SEPARATOR, SIGNER_KEY_1, testCase.Password, ROUNDS, MEMCOST)
			assert.Nil(t, err)
			assert.Equal(t, testCase.Expected, result)

		})
	}

	for _, testCase := range testCases2 {
		t.Run("Batch test 2", func(t *testing.T) {
			result, err := Encode(testCase.Salt, SALT_SEPARATOR, SIGNER_KEY_2, testCase.Password, ROUNDS, MEMCOST)
			assert.Nil(t, err)
			assert.Equal(t, testCase.Expected, result)

		})
	}
}
