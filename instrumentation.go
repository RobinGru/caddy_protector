package caddyprotector

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
	"strings"

	"github.com/zeebo/blake3"
)

const (
	instrumentationResultBytes  = 32
	instrumentationResultHexLen = instrumentationResultBytes * 2
	maxInstrumentationDuration  = 30_000
)

type instrumentationProof struct {
	Result     string `json:"result"`
	DurationMS int    `json:"durationMs"`
	HasDOM     bool   `json:"hasDom"`
	HasCrypto  bool   `json:"hasCrypto"`
	HasRAF     bool   `json:"hasRaf"`
	Webdriver  bool   `json:"webdriver"`
}

type instrumentationSpec struct {
	TreeDepth   int
	TreeBase    int
	TreeStep    int
	AttrCount   int
	AttrBase    int
	TypedRounds int
	TypedSalt   uint32
}

func (bb *CaddyProtector) instrumentationEnabled() bool {
	return bb.Instrumentation != nil && *bb.Instrumentation
}

func (bb *CaddyProtector) instrumentationLogOnlyEnabled() bool {
	return bb.InstrumentationLogOnly != nil && *bb.InstrumentationLogOnly
}

func deriveInstrumentationSpec(seed []byte) instrumentationSpec {
	if len(seed) < 16 {
		panic("instrumentation seed too short")
	}

	return instrumentationSpec{
		TreeDepth:   3 + int(seed[0]%4),
		TreeBase:    11 + int(seed[1]%19),
		TreeStep:    1 + int(seed[2]%7),
		AttrCount:   3 + int(seed[3]%5),
		AttrBase:    2 + int(seed[4]%17),
		TypedRounds: 4 + int(seed[5]%4),
		TypedSalt:   binary.BigEndian.Uint32(seed[6:10]) ^ 0x9e3779b9,
	}
}

func computeInstrumentationResultFromHex(seedHex string) (string, error) {
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return "", fmt.Errorf("seed fuer instrumentation ist kein gueltiger Hex-Wert: %w", err)
	}
	if len(seed) != challengeSeedLength {
		return "", fmt.Errorf("seed fuer instrumentation hat unerwartete Laenge: %d", len(seed))
	}
	return computeInstrumentationResult(seed), nil
}

func computeInstrumentationResult(seed []byte) string {
	spec := deriveInstrumentationSpec(seed)
	tree := instrumentationTreeAccumulator(spec)
	attrs := instrumentationAttributeAccumulator(seed, spec)
	typed := instrumentationTypedAccumulator(seed, spec)

	payload := make([]byte, 0, 36)
	payload = binary.BigEndian.AppendUint32(payload, uint32(tree))
	payload = binary.BigEndian.AppendUint32(payload, uint32(attrs))
	payload = binary.BigEndian.AppendUint32(payload, typed)
	payload = binary.BigEndian.AppendUint32(payload, uint32(spec.TreeDepth))
	payload = binary.BigEndian.AppendUint32(payload, uint32(spec.TreeBase))
	payload = binary.BigEndian.AppendUint32(payload, uint32(spec.TreeStep))
	payload = binary.BigEndian.AppendUint32(payload, uint32(spec.AttrCount))
	payload = binary.BigEndian.AppendUint32(payload, uint32(spec.AttrBase))
	payload = binary.BigEndian.AppendUint32(payload, uint32(spec.TypedRounds))

	sum := blake3.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func instrumentationTreeAccumulator(spec instrumentationSpec) int {
	sum := 0
	for level := 0; level < spec.TreeDepth; level++ {
		value := (spec.TreeBase + level*spec.TreeStep) & 0xff
		attributeCount := 2
		sum += value + attributeCount + level
	}
	return sum
}

func instrumentationAttributeAccumulator(seed []byte, spec instrumentationSpec) int {
	sum := 0
	for i := 0; i < spec.AttrCount; i++ {
		b := int(seed[(10+i)%len(seed)])
		textLength := 3 + b%5
		attributeCount := 2
		marker := (spec.AttrBase + b) % 11
		sum += textLength + attributeCount + i + marker
	}
	return sum
}

func instrumentationTypedAccumulator(seed []byte, spec instrumentationSpec) uint32 {
	acc := spec.TypedSalt
	for i := 0; i < 4; i++ {
		word := binary.BigEndian.Uint32(seed[i*4 : i*4+4])
		rotation := (spec.TypedRounds + i) % 32
		if rotation == 0 {
			rotation = 1
		}
		mixed := bits.RotateLeft32(acc^word^uint32((i+1)*0x45d9f3b), rotation)
		acc = mixed + uint32(spec.TreeBase+i*17)
	}
	return acc
}

func verifyInstrumentation(seedHex string, proof *instrumentationProof) error {
	if proof == nil {
		return fmt.Errorf("instrumentation payload fehlt")
	}
	if proof.DurationMS < 0 || proof.DurationMS > maxInstrumentationDuration {
		return fmt.Errorf("instrumentation durationMs ist ungueltig: %d", proof.DurationMS)
	}
	if !proof.HasDOM {
		return fmt.Errorf("instrumentation meldet fehlende DOM-Unterstuetzung")
	}
	if !proof.HasCrypto {
		return fmt.Errorf("instrumentation meldet fehlende WebCrypto-Unterstuetzung")
	}
	if !proof.HasRAF {
		return fmt.Errorf("instrumentation meldet fehlendes requestAnimationFrame")
	}
	if proof.Webdriver {
		return fmt.Errorf("instrumentation meldet webdriver=true")
	}
	if len(proof.Result) != instrumentationResultHexLen {
		return fmt.Errorf("instrumentation result hat ungueltige Laenge: %d", len(proof.Result))
	}
	actual, err := hex.DecodeString(strings.ToLower(proof.Result))
	if err != nil || len(actual) != instrumentationResultBytes {
		return fmt.Errorf("instrumentation result ist kein gueltiger Hex-Wert")
	}
	expectedHex, err := computeInstrumentationResultFromHex(seedHex)
	if err != nil {
		return err
	}
	expected, _ := hex.DecodeString(expectedHex)
	if subtleCompare(expected, actual) != 1 {
		return fmt.Errorf("instrumentation result stimmt nicht mit der erwarteten Browser-Ausfuehrung ueberein")
	}
	return nil
}

func subtleCompare(a, b []byte) int {
	if len(a) != len(b) {
		return 0
	}
	result := 1
	for i := range a {
		if a[i] != b[i] {
			result = 0
		}
	}
	return result
}
