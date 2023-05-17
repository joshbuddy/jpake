package jpake

type HashFnType func(in []byte) []byte
type MacFnType func(key, msg []byte) []byte
type ZKPMsg[P CurvePoint[P, S], S CurveScalar[S]] struct {
	T P
	R S
}
