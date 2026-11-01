package abi

import "fmt"

// Methods on the types a module holds. A method cannot stay in the kernel
// once its type lives here, so these moved with it.

// String renders a verdict for the console and the audit chain.
func (v TokenVerdict) String() string {
	switch v {
	case TokenConsistent:
		return "consistent"
	case TokenSuspicious:
		return "suspicious"
	case TokenImpossible:
		return "impossible"
	default:
		return fmt.Sprintf("verdict(%d)", int(v))
	}
}
