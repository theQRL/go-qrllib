// !mode2 left out to make it implicit

// +build !mode0,!mode1,!mode3

package dilithium

const (
	// Settings for the current strength mode "recommended".
	// You can change the mode used via build tags mode0 to mode3.
	K        = 5
	L        = 4
	ETA      = 5
	SETABITS = 4
	BETA     = 275
	OMEGA    = 96
)
