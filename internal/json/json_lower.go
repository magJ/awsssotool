package json

import (
	"encoding/json"
	"regexp"
	"unicode"
	"unicode/utf8"
)

// from https://gist.github.com/piersy/b9934790a8892db1a603820c0c23e4a7

// Regexp definitions
var keyMatchRegex = regexp.MustCompile(`"(\w+)":`)

type LowerCamelJsonMarshallable struct {
	Value interface{}
}

// the fact that a "modern" programming language doesnt seem to have any better way to control
// how object keys are serialized to json, boggles my mind
func (c LowerCamelJsonMarshallable) MarshalJSON() ([]byte, error) {
	marshalled, err := json.Marshal(c.Value)

	converted := keyMatchRegex.ReplaceAllFunc(
		marshalled,
		func(match []byte) []byte {
			// Empty keys are valid JSON, only lowercase if we do not have an
			// empty key.
			if len(match) > 2 {
				// Decode first rune after the double quotes
				r, width := utf8.DecodeRune(match[1:])
				r = unicode.ToLower(r)
				utf8.EncodeRune(match[1:width+1], r)
			}
			return match
		},
	)

	return converted, err
}

var _ json.Marshaler = (*LowerCamelJsonMarshallable)(nil)
