package a

// Small is fine.
type Small struct {
	A int
	B int
	C int
}

// Exactly24 is fine (boundary).
type Exactly24 struct {
	A, B, C, D, E, F, G, H, I, J, K, L int
	M, N, O, P, Q, R, S, T, U, V, W, X int
}

// Twenty5 should trigger.
type Twenty5 struct { // want `struct Twenty5 declares 25 fields`
	A, B, C, D, E, F, G, H, I, J, K, L int
	M, N, O, P, Q, R, S, T, U, V, W, X int
	Y                                  int
}

// GodStruct with 40 fields must trigger.
type GodStruct struct { // want `struct GodStruct declares 40 fields`
	F01, F02, F03, F04, F05, F06, F07, F08, F09, F10 int
	F11, F12, F13, F14, F15, F16, F17, F18, F19, F20 int
	F21, F22, F23, F24, F25, F26, F27, F28, F29, F30 int
	F31, F32, F33, F34, F35, F36, F37, F38, F39, F40 int
}

// Allowed via marker.
//
//cerebro:lint:allow maxfields legacy Config https://example.com/issue/999
type Allowed struct {
	F01, F02, F03, F04, F05, F06, F07, F08, F09, F10 int
	F11, F12, F13, F14, F15, F16, F17, F18, F19, F20 int
	F21, F22, F23, F24, F25, F26, F27, F28, F29, F30 int
}
