package main

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"math"
	"math/big"
	"os"
	"slices"

	"github.com/spf13/cobra"
)

type ErrAlphabet struct {
	msg string
}

func NewErrAlphabet(msg string) error {
	return ErrAlphabet{msg: msg}
}

func (e ErrAlphabet) Error() string {
	return e.msg
}

type ErrText struct {
	msg string
}

func NewErrText(msg string) error {
	return ErrText{msg: msg}
}

func (e ErrText) Error() string {
	return e.msg
}

type ErrKey struct {
	msg string
}

func NewErrKey(msg string) error {
	return ErrKey{msg: msg}
}

func (e ErrKey) Error() string {
	return e.msg
}

func GetMapFromAlphabet(alphabet []rune) map[rune]int {
	alphabetMap := make(map[rune]int)

	for i, v := range alphabet {
		alphabetMap[v] = i
	}

	return alphabetMap
}

func ValidateAlphabet(alphabet []rune) error {
	if len(alphabet) == 0 {
		return NewErrAlphabet("alphabet is empty")
	}

	runeMap := make(map[rune]struct{})

	for _, v := range alphabet {
		if _, ok := runeMap[v]; ok {
			return NewErrAlphabet(fmt.Sprintf("symbol `%c` repeating in alphabet", v))
		}
	}

	return nil
}

func ValidateText(text []rune, alphabetMap map[rune]int) error {
	if len(text) == 0 {
		return NewErrText("text is empty")
	}

	for _, v := range text {
		if _, ok := alphabetMap[v]; !ok {
			return NewErrText(fmt.Sprintf("text contains symbol '%c' that isn't in alphabet", v))
		}
	}

	return nil
}

func ValidateKey(key []rune, alphabetMap map[rune]int) error {
	if len(key) == 0 {
		return NewErrKey("key is empty")
	}

	for _, v := range key {
		if _, ok := alphabetMap[v]; !ok {
			return NewErrKey(fmt.Sprintf("key contains symbol '%c' that isn't in alphabet", v))
		}
	}

	return nil
}

const defaultAlphabet = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ "

type EncryptionData struct {
	Text        []rune
	Key         []rune
	Alphabet    []rune
	AlphabetMap map[rune]int
	isDecrypt   bool
}

func NewEncryptionData(
	alphabetFileName, textFileName, keyFileName string,
	isDecrypt bool,
) (EncryptionData, error) {
	data := EncryptionData{}

	if len(alphabetFileName) == 0 {
		data.Alphabet = []rune(defaultAlphabet)
	} else {
		alphabet, err := os.ReadFile(alphabetFileName)
		if err != nil {
			return EncryptionData{}, fmt.Errorf("read alphabet file %q: %w", alphabetFileName, err)
		}

		data.Alphabet = []rune(string(alphabet))
		if err := ValidateAlphabet(data.Alphabet); err != nil {
			return EncryptionData{}, fmt.Errorf("invalid alphabet: %w", err)
		}
	}

	data.AlphabetMap = GetMapFromAlphabet(data.Alphabet)

	text, err := os.ReadFile(textFileName)
	if err != nil {
		return EncryptionData{}, fmt.Errorf("read text file %q: %w", textFileName, err)
	}

	data.Text = []rune(string(text))
	if err := ValidateText(data.Text, data.AlphabetMap); err != nil {
		return EncryptionData{}, fmt.Errorf("invalid text: %w", err)
	}

	key, err := os.ReadFile(keyFileName)
	if err != nil {
		return EncryptionData{}, fmt.Errorf("read key file %q: %w", keyFileName, err)
	}

	data.Key = []rune(string(key))
	if err := ValidateKey(data.Key, data.AlphabetMap); err != nil {
		return EncryptionData{}, fmt.Errorf("invalid key: %w", err)
	}

	data.isDecrypt = isDecrypt

	return data, nil
}

const ShiftKeyLen = 1

func ShiftEncryption(data EncryptionData) ([]rune, error) {
	if len(data.Key) != ShiftKeyLen {
		return nil, NewErrKey(
			fmt.Sprintf("shift encryption key length must be equal %d", ShiftKeyLen),
		)
	}

	shift := data.AlphabetMap[data.Key[0]]

	if data.isDecrypt {
		shift = len(data.Alphabet) - shift
	}

	encryptionText := make([]rune, len(data.Text))

	for i, v := range data.Text {
		num := data.AlphabetMap[v]
		num = (num + shift) % len(data.Alphabet)
		encryptionText[i] = data.Alphabet[num]
	}

	return encryptionText, nil
}

func GCD(first, second int) int {
	for second != 0 {
		first, second = second, first%second
	}

	return first
}

func BinaryExponentiation(numb, power, mod int) int {
	if power == 0 {
		return 1
	}

	ans := BinaryExponentiation((numb*numb)%mod, power/2, mod)
	if (power & 1) == 1 {
		ans = (ans * numb) % mod
	}

	return ans
}

func Phi(numb, mod int) int {
	phi := 1

	for i := 2; i <= numb; i++ {
		cnt := 0
		for numb%i == 0 {
			cnt++
			numb /= i
		}
		if cnt != 0 {
			phi = (phi * BinaryExponentiation(i, cnt-1, mod) * (i - 1)) % mod
		}
	}

	return phi
}

func ReverseNumb(numb, mod int) int {
	phi := Phi(mod, mod)

	rev := BinaryExponentiation(numb, phi-1, mod)
	return rev
}

const AffineKeyLen = 2

func AffineEncryption(data EncryptionData) ([]rune, error) {
	if len(data.Key) != AffineKeyLen {
		return nil, NewErrKey(
			fmt.Sprintf("affine encryption key length must be equal %d", AffineKeyLen),
		)
	}

	key1, key2 := data.AlphabetMap[data.Key[0]], data.AlphabetMap[data.Key[1]]
	if key1 == 0 || GCD(key1, len(data.Alphabet)) != 1 {
		return nil, NewErrKey("first affine key symbol must be coprime with alphabet length")
	}

	if data.isDecrypt {
		key1 = ReverseNumb(key1, len(data.Alphabet))

		key2 = (-key2 * key1) % len(data.Alphabet)
		key2 = (key2 + len(data.Alphabet)) % len(data.Alphabet)
	}

	encryptionText := make([]rune, len(data.Text))

	for i, v := range data.Text {
		num := data.AlphabetMap[v]
		num = (key1*num + key2) % len(data.Alphabet)
		encryptionText[i] = data.Alphabet[num]
	}

	return encryptionText, nil
}

func SubstitutionEncryption(data EncryptionData) ([]rune, error) {
	if len(data.Key) != len(data.Alphabet) {
		return nil, NewErrKey("substitution key length and alphabet length must match")
	}

	substitutionMap := make(map[rune]rune)
	existsMap := make(map[rune]struct{})

	for i, v := range data.Key {
		if _, ok := existsMap[v]; ok {
			return nil, NewErrKey(fmt.Sprintf("substitution key symbol `%c` is contained twice", v))
		}

		existsMap[v] = struct{}{}

		if data.isDecrypt {
			substitutionMap[v] = data.Alphabet[i]
		} else {
			substitutionMap[data.Alphabet[i]] = v
		}
	}

	encryptionText := make([]rune, len(data.Text))

	for i, v := range data.Text {
		encryptionText[i] = substitutionMap[v]
	}

	return encryptionText, nil
}

type Matrix2x2 struct {
	K11 int
	K12 int
	K21 int
	K22 int
}

func (m Matrix2x2) Determinant(mod int) int {
	det := (m.K11*m.K22 - m.K12*m.K21) % mod
	det = (det + mod) % mod

	return det
}

func (m Matrix2x2) Inverse(mod int) Matrix2x2 {
	inv := Matrix2x2{
		K11: m.K22,
		K12: mod - m.K12,
		K21: mod - m.K21,
		K22: m.K11,
	}

	det := m.Determinant(mod)
	revDet := ReverseNumb(det, mod)

	inv.K11 = (inv.K11 * revDet) % mod

	inv.K12 = (inv.K12 + mod) % mod
	inv.K12 = (inv.K12 * revDet) % mod

	inv.K21 = (inv.K21 + mod) % mod
	inv.K21 = (inv.K21 * revDet) % mod

	inv.K22 = (inv.K22 * revDet) % mod

	return inv
}

func PadTextToMultiple(text, alphabet []rune, multiple int) ([]rune, error) {
	maxValue := big.NewInt(int64(len(alphabet)))

	randID, err := rand.Int(rand.Reader, maxValue)
	if err != nil {
		return nil, fmt.Errorf("cannot generate random index for alphabet: %w", err)
	}

	extraSymbol := alphabet[randID.Int64()]

	for len(text)%multiple != 0 {
		text = append(text, extraSymbol)
	}

	return text, nil
}

const hill2x2KeyLength = 4

func Hill2x2Encryption(data EncryptionData) ([]rune, error) {
	if len(data.Key) != hill2x2KeyLength {
		return nil, NewErrKey(fmt.Sprintf("hill 2x2 key length must be equal %d", hill2x2KeyLength))
	}

	matrix := Matrix2x2{
		K11: data.AlphabetMap[data.Key[0]],
		K12: data.AlphabetMap[data.Key[1]],
		K21: data.AlphabetMap[data.Key[2]],
		K22: data.AlphabetMap[data.Key[3]],
	}

	if det := matrix.Determinant(len(data.Alphabet)); det == 0 || GCD(det, len(data.Alphabet)) != 1 {
		return nil, NewErrKey("hill key determinant must be coprime with alphabet length")
	}

	if data.isDecrypt {
		matrix = matrix.Inverse(len(data.Alphabet))
	}

	hillKeyBatchLength := int(math.Sqrt(hill2x2KeyLength))

	if len(data.Text)%hillKeyBatchLength != 0 {
		var err error
		if data.Text, err = PadTextToMultiple(data.Text, data.Alphabet, hillKeyBatchLength); err != nil {
			return nil, fmt.Errorf(
				"PadTextToMultiple(%q, %q, %d): %w",
				data.Text,
				data.Alphabet,
				hillKeyBatchLength,
				err,
			)
		}
	}

	encryptionText := make([]rune, len(data.Text))

	for i := 0; i < len(data.Text); i += 2 {
		first, second := data.AlphabetMap[data.Text[i]], data.AlphabetMap[data.Text[i+1]]
		first, second = (first*matrix.K11+second*matrix.K21)%len(
			data.Alphabet,
		), (first*matrix.K12+second*matrix.K22)%len(
			data.Alphabet,
		)

		encryptionText[i], encryptionText[i+1] = data.Alphabet[first], data.Alphabet[second]
	}

	return encryptionText, nil
}

func TranspositionEncrypt(data EncryptionData) ([]rune, error) {
	if len(data.Text)%len(data.Key) != 0 {
		var err error
		if data.Text, err = PadTextToMultiple(data.Text, data.Alphabet, len(data.Key)); err != nil {
			return nil, fmt.Errorf(
				"PadTextToMultiple(%q, %q, %d): %w",
				data.Text,
				data.Alphabet,
				len(data.Key),
				err,
			)
		}
	}

	sortedKeyRunes := slices.SortedFunc(slices.Values(data.Key), func(a, b rune) int {
		return data.AlphabetMap[a] - data.AlphabetMap[b]
	})

	sortedKeyRuneIndexMap := make(map[rune]int)

	for i, v := range sortedKeyRunes {
		sortedKeyRuneIndexMap[v] = i
	}

	encryptedText := make([]rune, len(data.Text))

	for i := range data.Text {
		curNum := i % len(data.Key)
		num := sortedKeyRuneIndexMap[data.Key[curNum]]
		encryptedText[i+num-curNum] = data.Text[i]
	}

	return encryptedText, nil
}

func TranspositionDecrypt(data EncryptionData) ([]rune, error) {
	if len(data.Text)%len(data.Key) != 0 {
		return nil, NewErrText("transposition text length must be multiple of key length")
	}

	keyRuneIndexMap := make(map[rune]int)

	for i, v := range data.Key {
		keyRuneIndexMap[v] = i
	}

	sortedKeyRunes := slices.SortedFunc(slices.Values(data.Key), func(a, b rune) int {
		return data.AlphabetMap[a] - data.AlphabetMap[b]
	})

	decryptedText := make([]rune, len(data.Text))

	for i := range data.Text {
		curNum := i % len(data.Key)
		num := keyRuneIndexMap[sortedKeyRunes[curNum]]
		decryptedText[i+num-curNum] = data.Text[i]
	}

	return decryptedText, nil
}

func Transposition(data EncryptionData) ([]rune, error) {
	existsMap := make(map[rune]struct{})

	for _, v := range data.Key {
		if _, ok := existsMap[v]; ok {
			return nil, NewErrKey(
				fmt.Sprintf("transposition key symbol `%c` is contained twice", v),
			)
		}

		existsMap[v] = struct{}{}
	}

	if data.isDecrypt {
		decryptedText, err := TranspositionDecrypt(data)
		if err != nil {
			return nil, fmt.Errorf("transposition decryption: %w", err)
		}

		return decryptedText, nil
	}

	encryptedText, err := TranspositionEncrypt(data)
	if err != nil {
		return nil, fmt.Errorf("transposition encryption: %w", err)
	}

	return encryptedText, nil
}

func ViginereEncryption(data EncryptionData) ([]rune, error) {
	if data.isDecrypt {
		for i, v := range data.Key {
			num := data.AlphabetMap[v]
			num = len(data.Alphabet) - num
			data.Key[i] = data.Alphabet[num]
		}
	}

	encryptionText := make([]rune, len(data.Text))

	for i, v := range data.Text {
		num, keyNum := data.AlphabetMap[v], data.AlphabetMap[data.Key[i%len(data.Key)]]
		num = (num + keyNum) % len(data.Alphabet)
		encryptionText[i] = data.Alphabet[num]
	}

	return encryptionText, nil
}

func PrintSuccessfulMsg(isDecrypt bool, outputFileName string) {
	if isDecrypt {
		fmt.Printf("text successfully decrypted in file %s\n", outputFileName)
	} else {
		fmt.Printf("text successfully encrypted in file %s\n", outputFileName)
	}
}

func main() {
	rootCommand := &cobra.Command{
		Use:   "crypto",
		Short: "Encryption program",
		Long: `Crypto is a CLI tool for encrypting and decrypting text using different algorithms.
You can specify the text, alphabet, key, and output file as well as choose whether to encrypt or decrypt`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	var (
		alphabetFileName string
		textFileName     string
		keyFileName      string
		isDecrypt        bool
		outputFileName   string
	)

	rootCommand.PersistentFlags().
		StringVarP(&alphabetFileName, "alphabet", "a", "", "specify alphabet file for encryption/decryption")

	rootCommand.PersistentFlags().
		StringVarP(&textFileName, "text", "t", "", "specify text file for encryption/decryption")

	if err := rootCommand.MarkPersistentFlagRequired("text"); err != nil {
		slog.Error(fmt.Sprintf("cannot make text flag required: %s", err))
	}

	rootCommand.PersistentFlags().
		StringVarP(&keyFileName, "key", "k", "", "specify key file for encryption/decryption")

	if err := rootCommand.MarkPersistentFlagRequired("key"); err != nil {
		slog.Error(fmt.Sprintf("cannot make key flag required: %s", err))
	}

	rootCommand.PersistentFlags().
		BoolVarP(&isDecrypt, "decrypt", "d", false, "decrypt text if true")

	rootCommand.PersistentFlags().
		StringVarP(&outputFileName, "output", "o", "output.txt", "specify output file for encrypted/decrypted text")

	shiftEncryptionCommand := &cobra.Command{
		Use:   "shift",
		Short: "Shift encryption",
		Long: `The shift encryption (also known as Caesar cipher) is a simple substitution cipher where each letter 
in the text is shifted by a certain number of positions in the alphabet. You must specify the key (one symbol) for how much to shift each character

Example:
  crypto shift -t "text.txt" -k "key.txt" -a "alphabet.txt" -o output.txt -d`,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := NewEncryptionData(alphabetFileName, textFileName, keyFileName, isDecrypt)
			if err != nil {
				return fmt.Errorf("invalid input: %w", err)
			}

			encryptionText, err := ShiftEncryption(data)
			if err != nil {
				return fmt.Errorf("shift encryption: %w", err)
			}

			if err := os.WriteFile(outputFileName, []byte(string(encryptionText)), 0o600); err != nil {
				return fmt.Errorf("write file %q: %w", outputFileName, err)
			}

			PrintSuccessfulMsg(data.isDecrypt, outputFileName)

			return nil
		},
	}

	affineEncryptionCommand := &cobra.Command{
		Use:   "affine",
		Short: "Affine encryption",
		Long: `Affine encryption is an encryption method that uses linear functions to encrypt the text.
It requires two keys (symbols from alphabet) to perform encryption (a multiplier and an offset). Multiplier must be coprime with alphabet length

Example:
  crypto affine -t "text.txt" -k "key.txt" -a "alphabet.txt" -o output.txt -d`,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := NewEncryptionData(alphabetFileName, textFileName, keyFileName, isDecrypt)
			if err != nil {
				return fmt.Errorf("invalid input: %w", err)
			}

			encryptionText, err := AffineEncryption(data)
			if err != nil {
				return fmt.Errorf("affine encryption: %w", err)
			}

			if err := os.WriteFile(outputFileName, []byte(string(encryptionText)), 0o600); err != nil {
				return fmt.Errorf("write file %q: %w", outputFileName, err)
			}

			PrintSuccessfulMsg(data.isDecrypt, outputFileName)

			return nil
		},
	}

	substitutionEncryptionCommand := &cobra.Command{
		Use:   "substitution",
		Short: "Substitution encryption",
		Long: `Substitution encryption replaces each letter in the plaintext with another letter based on the provided key. The key must be a permutation of the alphabet characters

Example:
  crypto substitution -t "text.txt" -k "key.txt" -a "alphabet.txt" -o output.txt -d`,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := NewEncryptionData(alphabetFileName, textFileName, keyFileName, isDecrypt)
			if err != nil {
				return fmt.Errorf("invalid input: %w", err)
			}

			encryptionText, err := SubstitutionEncryption(data)
			if err != nil {
				return fmt.Errorf("substitution encryption: %w", err)
			}

			if err := os.WriteFile(outputFileName, []byte(string(encryptionText)), 0o600); err != nil {
				return fmt.Errorf("write file %q: %w", outputFileName, err)
			}

			PrintSuccessfulMsg(data.isDecrypt, outputFileName)

			return nil
		},
	}

	hillEncryptionCommand := &cobra.Command{
		Use:   "hill",
		Short: "Hill 2x2 encryption",
		Long: `Hill cipher is a cipher based on linear algebra, where each block of plaintext is multiplied by a 2x2 matrix. The determinant of a matrix must not be equal to zero. The key must consist of 4 characters that form a matrix: k11, k12, k21 and k22

Example:
  crypto hill -t "text.txt" -k "key.txt" -a "alphabet.txt" -o output.txt -d`,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := NewEncryptionData(alphabetFileName, textFileName, keyFileName, isDecrypt)
			if err != nil {
				return fmt.Errorf("invalid input: %w", err)
			}

			encryptionText, err := Hill2x2Encryption(data)
			if err != nil {
				return fmt.Errorf("hill 2x2 encryption: %w", err)
			}

			if err := os.WriteFile(outputFileName, []byte(string(encryptionText)), 0o600); err != nil {
				return fmt.Errorf("write file %q: %w", outputFileName, err)
			}

			PrintSuccessfulMsg(data.isDecrypt, outputFileName)

			return nil
		},
	}

	transpositionEncryptionCommand := &cobra.Command{
		Use:   "transposition",
		Short: "Transposition encryption",
		Long: `Transposition encryption scrambles the letters of the text according to a certain system, keeping the same characters but changing their positions. Key must be a word without repeating symbols

Example:
  crypto transposition -t "text.txt" -k "key.txt" -a "alphabet.txt" -o output.txt -d`,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := NewEncryptionData(alphabetFileName, textFileName, keyFileName, isDecrypt)
			if err != nil {
				return fmt.Errorf("invalid input: %w", err)
			}

			encryptionText, err := Transposition(data)
			if err != nil {
				return fmt.Errorf("transposition encryption: %w", err)
			}

			if err := os.WriteFile(outputFileName, []byte(string(encryptionText)), 0o600); err != nil {
				return fmt.Errorf("write file %q: %w", outputFileName, err)
			}

			PrintSuccessfulMsg(data.isDecrypt, outputFileName)

			return nil
		},
	}

	vigenereEncryptionCommand := &cobra.Command{
		Use:   "vigenere",
		Short: "Viginere encryption",
		Long: `Vigenere cipher is a method of encrypting alphabetic text using a series of Caesar ciphers based on the letters of a key

Example:
  crypto vigenere -t "text.txt" -k "key.txt" -a "alphabet.txt" -o output.txt -d`,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := NewEncryptionData(alphabetFileName, textFileName, keyFileName, isDecrypt)
			if err != nil {
				return fmt.Errorf("invalid input: %w", err)
			}

			encryptionText, err := ViginereEncryption(data)
			if err != nil {
				return fmt.Errorf("vigenere encryption: %w", err)
			}

			if err := os.WriteFile(outputFileName, []byte(string(encryptionText)), 0o600); err != nil {
				return fmt.Errorf("write file %q: %w", outputFileName, err)
			}

			PrintSuccessfulMsg(data.isDecrypt, outputFileName)

			return nil
		},
	}

	rootCommand.AddCommand(shiftEncryptionCommand)
	rootCommand.AddCommand(affineEncryptionCommand)
	rootCommand.AddCommand(substitutionEncryptionCommand)
	rootCommand.AddCommand(hillEncryptionCommand)
	rootCommand.AddCommand(transpositionEncryptionCommand)
	rootCommand.AddCommand(vigenereEncryptionCommand)

	if err := rootCommand.Execute(); err != nil {
		// ignore error as cobra itself displays it on the screen
		os.Exit(1)
	}
}
