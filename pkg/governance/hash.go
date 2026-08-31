/*
Copyright © 2025 Docker, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package governance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strings"
)

func CanonicalSchemaHash(raw []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	value, err := decodeCanonicalJSONValue(dec)
	if err != nil {
		return "", fmt.Errorf("decode schema: %w", err)
	}

	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return "", fmt.Errorf("multiple JSON values")
		}
		return "", fmt.Errorf("trailing JSON: %w", err)
	}

	var canonical bytes.Buffer
	if err := writeCanonical(&canonical, value); err != nil {
		return "", err
	}

	hash := sha256.Sum256(canonical.Bytes())
	return "sha256:" + hex.EncodeToString(hash[:]), nil
}

func decodeCanonicalJSONValue(dec *json.Decoder) (any, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}

	switch v := token.(type) {
	case json.Delim:
		switch v {
		case '{':
			object := make(map[string]any)
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, fmt.Errorf("object key is not a string")
				}
				if _, exists := object[key]; exists {
					return nil, fmt.Errorf("duplicate object key %q", key)
				}
				value, err := decodeCanonicalJSONValue(dec)
				if err != nil {
					return nil, err
				}
				object[key] = value
			}
			closing, err := dec.Token()
			if err != nil {
				return nil, err
			}
			if closing != json.Delim('}') {
				return nil, fmt.Errorf("unexpected object terminator %v", closing)
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for dec.More() {
				value, err := decodeCanonicalJSONValue(dec)
				if err != nil {
					return nil, err
				}
				array = append(array, value)
			}
			closing, err := dec.Token()
			if err != nil {
				return nil, err
			}
			if closing != json.Delim(']') {
				return nil, fmt.Errorf("unexpected array terminator %v", closing)
			}
			return array, nil
		default:
			return nil, fmt.Errorf("unexpected delimiter %q", v)
		}
	case nil, bool, string, json.Number:
		return v, nil
	default:
		return nil, fmt.Errorf("unsupported JSON token type %T", token)
	}
}

func writeCanonical(buf *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case nil:
		buf.WriteByte('n')
	case bool:
		if v {
			buf.WriteString("bt")
		} else {
			buf.WriteString("bf")
		}
	case string:
		buf.WriteByte('s')
		encoded, _ := json.Marshal(v)
		buf.Write(encoded)
	case json.Number:
		number, err := normalizeJSONNumber(v.String())
		if err != nil {
			return err
		}
		buf.WriteByte('d')
		buf.WriteString(number)
	case []any:
		buf.WriteByte('[')
		for _, item := range v {
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
			buf.WriteByte(';')
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for _, key := range keys {
			encodedKey, _ := json.Marshal(key)
			buf.WriteByte('k')
			buf.Write(encodedKey)
			buf.WriteByte(':')
			if err := writeCanonical(buf, v[key]); err != nil {
				return err
			}
			buf.WriteByte(';')
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unsupported JSON value type %T", value)
	}
	return nil
}

func normalizeJSONNumber(raw string) (string, error) {
	s := raw
	sign := ""
	if strings.HasPrefix(s, "-") {
		sign = "-"
		s = s[1:]
	}

	exponent := new(big.Int)
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		exponentText := s[i+1:]
		s = s[:i]
		if _, ok := exponent.SetString(exponentText, 10); !ok {
			return "", fmt.Errorf("invalid JSON exponent %q", raw)
		}
	}

	fractionDigits := 0
	if i := strings.IndexByte(s, '.'); i >= 0 {
		fractionDigits = len(s) - i - 1
		s = s[:i] + s[i+1:]
	}

	if strings.Trim(s, "0") == "" {
		return "0e0", nil
	}

	s = strings.TrimLeft(s, "0")
	trailingZeros := len(s) - len(strings.TrimRight(s, "0"))
	if trailingZeros > 0 {
		s = strings.TrimRight(s, "0")
	}

	adjustedExponent := new(big.Int).Set(exponent)
	adjustedExponent.Sub(adjustedExponent, big.NewInt(int64(fractionDigits)))
	adjustedExponent.Add(adjustedExponent, big.NewInt(int64(trailingZeros)))

	return sign + s + "e" + adjustedExponent.String(), nil
}
