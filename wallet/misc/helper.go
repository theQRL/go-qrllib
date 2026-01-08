package misc

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/theQRL/go-qrllib/qrl"
)

// wordLookup is a pre-computed map for efficient mnemonic word lookup
var wordLookup map[string]int

func init() {
	wordLookup = make(map[string]int, len(qrl.WordList))
	for i, word := range qrl.WordList {
		wordLookup[word] = i
	}
}

func BinToMnemonic(input []uint8) (string, error) {
	if len(input)%3 != 0 {
		return "", errors.New("byte count needs to be a multiple of 3")
	}

	buf := bytes.NewBuffer(nil)
	separator := ""
	for nibble := 0; nibble < len(input)*2; nibble += 3 {
		p := nibble >> 1
		b1 := uint32(input[p])
		b2 := uint32(0)
		if p+1 < len(input) {
			b2 = uint32(input[p+1])
		}
		idx := uint32(0)
		if nibble%2 == 0 {
			idx = (b1 << 4) + (b2 >> 4)
		} else {
			idx = ((b1 & 0x0F) << 8) + b2
		}
		_, err := fmt.Fprint(buf, separator, qrl.WordList[idx])
		if err != nil {
			return "", fmt.Errorf("BinToMnemonic Fprint error %s", err)
		}
		separator = " "
	}

	return buf.String(), nil
}

func MnemonicToBin(mnemonic string) ([]uint8, error) {
	mnemonicWords := strings.Split(mnemonic, " ")
	wordCount := len(mnemonicWords)
	if wordCount%2 != 0 {
		return nil, fmt.Errorf("word count = %d must be even", wordCount)
	}

	result := make([]uint8, wordCount*15/10)
	current := 0
	buffering := 0
	resultIndex := 0
	for _, w := range mnemonicWords {
		value, found := wordLookup[w]
		if !found {
			return nil, fmt.Errorf("invalid word %s in mnemonic", w)
		}

		buffering += 3
		current = (current << 12) + value

		for buffering > 2 {
			shift := 4 * (buffering - 2)
			mask := (1 << shift) - 1
			tmp := current >> shift
			buffering -= 2
			current &= mask
			result[resultIndex] = uint8(tmp)
			resultIndex++
		}
	}

	if buffering > 0 {
		result[resultIndex] = uint8(current & 0xFF)
	}

	return result, nil
}
