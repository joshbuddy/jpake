# J-PAKE

[![Go Reference](https://pkg.go.dev/badge/github.com/joshbuddy/jpake.svg)](https://pkg.go.dev/github.com/joshbuddy/jpake)

This implements https://www.rfc-editor.org/rfc/rfc8236 for go using ECC. Currently only the
[three-pass variant](https://www.rfc-editor.org/rfc/rfc8236#section-4) is implemented.
The interface allows for passing in any EC that conforms to `Curve[P CurvePoint[P, S], S CurveScalar[S]]` interface.
At present, only Curve-25519 has a compatible interface. The package [filippo.io/edwards25519](https://pkg.go.dev/filippo.io/edwards25519) provides the underlying implementation used by this interface.

For key confirmation, the procedure outlined in the rfc based on the SPEKE protocol is implemented.

Pull requests are welcome! If you wish to add more curves, add the 2-pass variant or other key confirmation methods, please do, and thanks in advance.

Also thanks to @choonkiatlee for https://github.com/choonkiatlee/jpake-go which was very helpful in making this. This library improves on this by adding support for a user id within the ZKP. As well, it no longer relies on `crypto/elliptic` (see https://github.com/golang/go/issues/52221).

This code is currently unaudited and should not be used without a formal security audit.
