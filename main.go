package main

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"maps"
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

func ValidateString(str []rune, name string, alphabetMap map[rune]int) error {
	for _, v := range str {
		if _, ok := alphabetMap[v]; !ok {
			return NewErrText(
				fmt.Sprintf("%s contains symbol '%c' that isn't in alphabet", name, v),
			)
		}
	}

	return nil
}

func ValidateText(text []rune, alphabetMap map[rune]int) error {
	for _, v := range text {
		if _, ok := alphabetMap[v]; !ok {
			return NewErrText(fmt.Sprintf("text contains symbol '%c' that isn't in alphabet", v))
		}
	}

	return nil
}

func ValidateKey(key []rune, alphabetMap map[rune]int) error {
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
		K12: (-m.K12) % mod,
		K21: (-m.K21) % mod,
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

	if det := matrix.Determinant(len(data.Alphabet)); det == 0 {
		return nil, NewErrKey("hill key determinant mustn't be equal 0")
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

	keyTextMap := make(map[rune][]rune)

	for i, v := range data.Text {
		keyTextMap[data.Key[i%len(data.Key)]] = append(keyTextMap[data.Key[i%len(data.Key)]], v)
	}

	sortedKeyRunes := slices.SortedFunc(maps.Keys(keyTextMap), func(a, b rune) int {
		return data.AlphabetMap[a] - data.AlphabetMap[b]
	})

	encryptedText := make([]rune, len(data.Text))

	for _, v := range sortedKeyRunes {
		encryptedText = append(encryptedText, keyTextMap[v]...)
	}

	return encryptedText, nil
}

func TranspositionDecrypt(data EncryptionData) ([]rune, error) {
	if len(data.Text)%len(data.Key) != 0 {
		return nil, NewErrText("transposition text length must be multiple of key length")
	}

	sortedKeyRunes := slices.SortedFunc(slices.Values(data.Key), func(a, b rune) int {
		return data.AlphabetMap[a] - data.AlphabetMap[b]
	})

	keyRuneIndexMap := make(map[rune]int)

	for i, v := range data.Key {
		keyRuneIndexMap[v] = i
	}

	keyID := 0
	decryptedText := make([]rune, len(data.Text))

	for _, v := range sortedKeyRunes {
		for offset := keyRuneIndexMap[v]; offset < len(decryptedText); offset += len(data.Key) {
			decryptedText[offset] = data.Text[keyID]
			keyID++
		}
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
	existsMap := make(map[rune]struct{})

	for _, v := range data.Key {
		if _, ok := existsMap[v]; ok {
			return nil, NewErrKey(fmt.Sprintf("vigenere key symbol `%c` is contained twice", v))
		}

		existsMap[v] = struct{}{}
	}

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

func main() {
	rootCommand := &cobra.Command{
		Use:   "encryption",
		Short: "Text encryption console program",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	var (
		alphabetFileName string
		textFileName     string
		keyFileName      string
		isDecrypt        bool
	)

	rootCommand.PersistentFlags().
		StringVarP(&alphabetFileName, "alphabet", "a", "", "specify alphabet for encryption/decryption")

	rootCommand.PersistentFlags().
		StringVarP(&textFileName, "text", "t", "", "specify text for encryption/decryption")

	if err := rootCommand.MarkPersistentFlagRequired("text"); err != nil {
		slog.Error(fmt.Sprintf("cannot make text flag required: %s", err))
	}

	rootCommand.PersistentFlags().
		StringVarP(&keyFileName, "key", "k", "", "specify key for encryption/decryption")

	if err := rootCommand.MarkPersistentFlagRequired("key"); err != nil {
		slog.Error(fmt.Sprintf("cannot make key flag required: %s", err))
	}

	rootCommand.PersistentFlags().
		BoolVarP(&isDecrypt, "decrypt", "d", false, "decrypt text if true")

	shiftEncryptionCommand := &cobra.Command{
		Use:   "shift",
		Short: "Shift encryption",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := NewEncryptionData(alphabetFileName, textFileName, keyFileName, isDecrypt)
			if err != nil {
				return fmt.Errorf("invalid input: %w", err)
			}

			encryptionText, err := ShiftEncryption(data)
			if err != nil {
				return fmt.Errorf("shift encryption: %w", err)
			}

			fmt.Println(string(encryptionText))
			return nil
		},
	}

	affineEncryptionCommand := &cobra.Command{
		Use:   "affine",
		Short: "Affine encryption",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := NewEncryptionData(alphabetFileName, textFileName, keyFileName, isDecrypt)
			if err != nil {
				return fmt.Errorf("invalid input: %w", err)
			}

			encryptionText, err := AffineEncryption(data)
			if err != nil {
				return fmt.Errorf("affine encryption: %w", err)
			}

			fmt.Println(string(encryptionText))
			return nil
		},
	}

	substitutionEncryptionCommand := &cobra.Command{
		Use:   "substitution",
		Short: "Substitution encryption",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := NewEncryptionData(alphabetFileName, textFileName, keyFileName, isDecrypt)
			if err != nil {
				return fmt.Errorf("invalid input: %w", err)
			}

			encryptionText, err := SubstitutionEncryption(data)
			if err != nil {
				return fmt.Errorf("substitution encryption: %w", err)
			}

			fmt.Println(string(encryptionText))
			return nil
		},
	}

	hillEncryptionCommand := &cobra.Command{
		Use:   "hill",
		Short: "Hill 2x2 encryption",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := NewEncryptionData(alphabetFileName, textFileName, keyFileName, isDecrypt)
			if err != nil {
				return fmt.Errorf("invalid input: %w", err)
			}

			encryptionText, err := Hill2x2Encryption(data)
			if err != nil {
				return fmt.Errorf("hill 2x2 encryption: %w", err)
			}

			fmt.Println(string(encryptionText))
			return nil
		},
	}

	transpositionEncryptionCommand := &cobra.Command{
		Use:   "transposition",
		Short: "Transposition encryption",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := NewEncryptionData(alphabetFileName, textFileName, keyFileName, isDecrypt)
			if err != nil {
				return fmt.Errorf("invalid input: %w", err)
			}

			encryptionText, err := Transposition(data)
			if err != nil {
				return fmt.Errorf("transposition encryption: %w", err)
			}

			fmt.Println(string(encryptionText))
			return nil
		},
	}

	vigenereEncryptionCommand := &cobra.Command{
		Use:   "vigenere",
		Short: "Viginere encryption",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := NewEncryptionData(alphabetFileName, textFileName, keyFileName, isDecrypt)
			if err != nil {
				return fmt.Errorf("invalid input: %w", err)
			}

			encryptionText, err := ViginereEncryption(data)
			if err != nil {
				return fmt.Errorf("vigenere encryption: %w", err)
			}

			fmt.Println(string(encryptionText))
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
