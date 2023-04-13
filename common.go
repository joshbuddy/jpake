package jpake

type HashFnType func([]byte) []byte
type ZKPMsg[P CurvePoint[P, S], S CurveScalar[S]] struct {
	T P
	R S
}
