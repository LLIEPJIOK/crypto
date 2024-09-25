package main

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"math"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

func GetMapFromAlph(alph []rune) map[rune]int {
	alphMap := make(map[rune]int)

	for i, v := range alph {
		alphMap[v] = i
	}

	return alphMap
}

type ErrEmptyAlph struct{}

func (e ErrEmptyAlph) Error() string {
	return "empty alphabet"
}

type ErrRepeatingAlphSymbols string

func (e ErrRepeatingAlphSymbols) Error() string {
	return fmt.Sprintf("repeating symbols in alphabet = %q", string(e))
}

func ValidateAlph(alph []rune) error {
	if len(alph) == 0 {
		return ErrEmptyAlph{}
	}

	runeMap := make(map[rune]struct{})

	for _, v := range alph {
		if _, ok := runeMap[v]; ok {
			return ErrRepeatingAlphSymbols(alph)
		}
	}

	return nil
}

type ErrNoSymbolInAlph rune

func (e ErrNoSymbolInAlph) Error() string {
	return fmt.Sprintf("text contains symbol '%c' that isn't in alphabet", e)
}

func ValidateText(text []rune, alphMap map[rune]int) error {
	for _, v := range text {
		if _, ok := alphMap[v]; !ok {
			return ErrNoSymbolInAlph(v)
		}
	}

	return nil
}

const defaultAlph = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ "

type EncryptionData struct {
	Text      []rune
	Key       []rune
	Alph      []rune
	AlphMap   map[rune]int
	isDecrypt bool
}

func NewEncryptionData(
	alphFileName, textFileName, keyFileName string,
	isDecrypt bool,
) (EncryptionData, error) {
	data := EncryptionData{}

	if len(alphFileName) == 0 {
		data.Alph = []rune(defaultAlph)
	} else {
		alph, err := os.ReadFile(alphFileName)
		if err != nil {
			return EncryptionData{}, fmt.Errorf("cannot read alphabet file %q: %w", alphFileName, err)
		}

		data.Alph = []rune(string(alph))
		if err := ValidateAlph(data.Alph); err != nil {
			return EncryptionData{}, fmt.Errorf("invalid alphabet: %w", err)
		}
	}

	data.AlphMap = GetMapFromAlph(data.Alph)

	text, err := os.ReadFile(textFileName)
	if err != nil {
		return EncryptionData{}, fmt.Errorf("cannot read text file %q: %w", textFileName, err)
	}

	data.Text = []rune(string(text))
	if err := ValidateText(data.Text, data.AlphMap); err != nil {
		return EncryptionData{}, fmt.Errorf("invalid text: %w", err)
	}

	key, err := os.ReadFile(keyFileName)
	if err != nil {
		return EncryptionData{}, fmt.Errorf("cannot read key file %q: %w", keyFileName, err)
	}

	data.Key = []rune(string(key))

	data.isDecrypt = isDecrypt

	return data, nil
}

type ErrKeyOutOfRange struct {
	key      int
	alphaLen int
}

func (e ErrKeyOutOfRange) Error() string {
	return fmt.Sprintf("key = %d out of range [0, len(alphabet)-1 = %d]", e.key, e.alphaLen-1)
}

func ShiftEncryption(data EncryptionData) ([]rune, error) {
	shift, err := strconv.Atoi(strings.TrimSpace(string(data.Key)))
	if err != nil {
		return nil, fmt.Errorf("cannot convert key to int: %w", err)
	}

	fmt.Println(shift)
	if shift < 0 || shift >= len(data.Alph) {
		return nil, ErrKeyOutOfRange{
			key:      shift,
			alphaLen: len(data.Alph),
		}
	}

	if data.isDecrypt {
		shift *= -1
	}

	encryptedText := make([]rune, len(data.Text))

	for i, v := range data.Text {
		num := data.AlphMap[v]
		num = (num + shift) % len(data.Alph)
		num = (num + len(data.Alph)) % len(data.Alph)
		encryptedText[i] = data.Alph[num]
	}

	return encryptedText, nil
}

type ErrInvalidNumberOfKeys struct {
	expected int
	got      int
}

func (e ErrInvalidNumberOfKeys) Error() string {
	return fmt.Sprintf("invalid number of keys: expected: %d, but got: %d", e.expected, e.got)
}

type ErrFirstKeyNotCoprimeWithAlphaLen struct {
	key      int
	alphaLen int
}

func (e ErrFirstKeyNotCoprimeWithAlphaLen) Error() string {
	return fmt.Sprintf("first key = %d isn't comprime with len(alphabet) = %d", e.key, e.alphaLen)
}

func GCD(first, second int) int {
	for second != 0 {
		first, second = second, first%second
	}

	return first
}

func bpow(numb, power, mod int) int {
	if power == 0 {
		return 1
	}

	ans := bpow((numb*numb)%mod, power/2, mod)
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
			phi = (phi * bpow(i, cnt-1, mod) * (i - 1)) % mod
		}
	}

	return phi
}

func GetReversed(numb, mod int) int {
	phi := Phi(mod, mod)

	rev := bpow(numb, phi-1, mod)
	return rev
}

func AffineEncryption(data EncryptionData) ([]rune, error) {
	keys := strings.Fields(string(data.Key))
	if len(keys) != 2 {
		return nil, ErrInvalidNumberOfKeys{
			expected: 2,
			got:      len(keys),
		}
	}

	key1, err := strconv.Atoi(keys[0])
	if err != nil {
		return nil, fmt.Errorf("cannot convert first key to int: %w", err)
	}

	if key1 < 0 || key1 >= len(data.Alph) {
		return nil, ErrKeyOutOfRange{
			key:      key1,
			alphaLen: len(data.Alph),
		}
	}

	if key1 == 0 || GCD(key1, len(data.Alph)) != 1 {
		return nil, ErrFirstKeyNotCoprimeWithAlphaLen{
			key:      key1,
			alphaLen: len(data.Alph),
		}
	}

	key2, err := strconv.Atoi(keys[1])
	if err != nil {
		return nil, fmt.Errorf("cannot convert second key to int: %w", err)
	}

	if key2 < 0 || key2 >= len(data.Alph) {
		return nil, ErrKeyOutOfRange{
			key:      key2,
			alphaLen: len(data.Alph),
		}
	}

	if data.isDecrypt {
		key1 = GetReversed(key1, len(data.Alph))

		key2 = (-key2 * key1) % len(data.Alph)
		key2 = (key2 + len(data.Alph)) % len(data.Alph)
	}

	encryptedText := make([]rune, len(data.Text))

	for i, v := range data.Text {
		num := data.AlphMap[v]
		num = (key1*num + key2) % len(data.Alph)
		num = (num + len(data.Alph)) % len(data.Alph)
		encryptedText[i] = data.Alph[num]
	}

	return encryptedText, nil
}

type ErrInvalidSubstitutionKey string

func (e ErrInvalidSubstitutionKey) Error() string {
	return fmt.Sprintf("invalid substitution key: %s", string(e))
}

func SubstitutionEncryption(data EncryptionData) ([]rune, error) {
	if len(data.Key) != len(data.Alph) {
		return nil, ErrInvalidSubstitutionKey("key and alphabet length doesn't match")
	}

	substitutionMap := make(map[rune]rune)
	existsMap := make(map[rune]struct{})

	for i, v := range data.Key {
		if _, ok := data.AlphMap[v]; !ok {
			return nil, ErrInvalidSubstitutionKey(fmt.Sprintf("%c isn't contained in alphabet", v))
		}

		if _, ok := existsMap[v]; ok {
			return nil, ErrInvalidSubstitutionKey(fmt.Sprintf("%c is contained twice", v))
		}

		existsMap[v] = struct{}{}

		if data.isDecrypt {
			substitutionMap[v] = data.Alph[i]
		} else {
			substitutionMap[data.Alph[i]] = v
		}
	}

	encryptedText := make([]rune, len(data.Text))

	for i, v := range data.Text {
		encryptedText[i] = substitutionMap[v]
	}

	return encryptedText, nil
}

type ErrInvalidHillKey string

func (e ErrInvalidHillKey) Error() string {
	return fmt.Sprintf("invalid hill key: %s", string(e))
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
	revDet := GetReversed(det, mod)

	inv.K11 = (inv.K11 * revDet) % mod

	inv.K12 = (inv.K12 + mod) % mod
	inv.K12 = (inv.K12 * revDet) % mod

	inv.K21 = (inv.K21 + mod) % mod
	inv.K21 = (inv.K21 * revDet) % mod

	inv.K22 = (inv.K22 * revDet) % mod

	return inv
}

const (
	hill2x2KeyLength = 4
)

func Hill2x2Encryption(data EncryptionData) ([]rune, error) {
	if len(data.Key) != hill2x2KeyLength {
		return nil, ErrInvalidHillKey("length must be equal 4")
	}

	for _, v := range data.Key {
		if _, ok := data.AlphMap[v]; !ok {
			return nil, ErrInvalidHillKey(fmt.Sprintf("%c isn't contained in alphabet", v))
		}
	}

	matrix := Matrix2x2{
		K11: data.AlphMap[data.Key[0]],
		K12: data.AlphMap[data.Key[1]],
		K21: data.AlphMap[data.Key[2]],
		K22: data.AlphMap[data.Key[3]],
	}

	if det := matrix.Determinant(len(data.Alph)); det == 0 {
		return nil, ErrInvalidHillKey("key determinant mustn't be equal 0")
	}

	if data.isDecrypt {
		matrix = matrix.Inverse(len(data.Alph))
	}

	hillKeyBatchLength := int(math.Sqrt(hill2x2KeyLength))

	if len(data.Text)%hillKeyBatchLength != 0 {
		maxValue := big.NewInt(int64(len(data.Alph)))

		randID, err := rand.Int(rand.Reader, maxValue)
		if err != nil {
			return nil, fmt.Errorf("cannot generate random index for alphabet: %w", err)
		}

		data.Text = append(data.Text, data.Alph[randID.Int64()])
	}

	encryptedText := make([]rune, len(data.Text))

	for i := 0; i < len(data.Text); i += 2 {
		first, second := data.AlphMap[data.Text[i]], data.AlphMap[data.Text[i+1]]
		first, second = (first*matrix.K11+second*matrix.K21)%len(
			data.Alph,
		), (first*matrix.K12+second*matrix.K22)%len(
			data.Alph,
		)

		encryptedText[i], encryptedText[i+1] = data.Alph[first], data.Alph[second]
	}

	return encryptedText, nil
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
		alphFileName string
		textFileName string
		keyFileName  string
		isDecrypt    bool
	)

	rootCommand.PersistentFlags().
		StringVarP(&alphFileName, "alphabet", "a", "", "specify alphabet for encryption/decryption")

	rootCommand.PersistentFlags().
		StringVarP(&textFileName, "text", "t", "", "specify text for encryption/decryption")

	if err := rootCommand.MarkPersistentFlagRequired("text"); err != nil {
		slog.Error("cannot make text flag required")
	}

	rootCommand.PersistentFlags().
		StringVarP(&keyFileName, "key", "k", "", "specify key for encryption/decryption")

	if err := rootCommand.MarkPersistentFlagRequired("key"); err != nil {
		slog.Error("cannot make key flag required")
	}

	rootCommand.PersistentFlags().
		BoolVarP(&isDecrypt, "decrypt", "d", false, "decrypt text if true")

	shiftEncryptionCommand := &cobra.Command{
		Use:   "shift",
		Short: "Shift encryption",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := NewEncryptionData(alphFileName, textFileName, keyFileName, isDecrypt)
			if err != nil {
				return fmt.Errorf("invalid input: %w", err)
			}

			encryptedText, err := ShiftEncryption(data)
			if err != nil {
				return fmt.Errorf("cannot apply shift encryption: %w", err)
			}

			fmt.Println(string(encryptedText))
			return nil
		},
	}

	affineEncryptionCommand := &cobra.Command{
		Use:   "affine",
		Short: "Affine encryption",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := NewEncryptionData(alphFileName, textFileName, keyFileName, isDecrypt)
			if err != nil {
				return fmt.Errorf("invalid input: %w", err)
			}

			encryptedText, err := AffineEncryption(data)
			if err != nil {
				return fmt.Errorf("cannot apply affine encryption: %w", err)
			}

			fmt.Println(string(encryptedText))
			return nil
		},
	}

	substitutionEncryptionCommand := &cobra.Command{
		Use:   "substitution",
		Short: "Substitution encryption",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := NewEncryptionData(alphFileName, textFileName, keyFileName, isDecrypt)
			if err != nil {
				return fmt.Errorf("invalid input: %w", err)
			}

			encryptedText, err := SubstitutionEncryption(data)
			if err != nil {
				return fmt.Errorf("cannot apply substitution encryption: %w", err)
			}

			fmt.Println(string(encryptedText))
			return nil
		},
	}

	hillEncryptionCommand := &cobra.Command{
		Use:   "hill",
		Short: "Hill 2x2 encryption",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := NewEncryptionData(alphFileName, textFileName, keyFileName, isDecrypt)
			if err != nil {
				return fmt.Errorf("invalid input: %w", err)
			}

			encryptedText, err := Hill2x2Encryption(data)
			if err != nil {
				return fmt.Errorf("cannot apply hill 2x2 encryption: %w", err)
			}

			fmt.Println(string(encryptedText))
			return nil
		},
	}

	rootCommand.AddCommand(shiftEncryptionCommand)
	rootCommand.AddCommand(affineEncryptionCommand)
	rootCommand.AddCommand(substitutionEncryptionCommand)
	rootCommand.AddCommand(hillEncryptionCommand)

	if err := rootCommand.Execute(); err != nil {
		// ignore error as cobra itself displays it on the screen
		os.Exit(1)
	}
}
