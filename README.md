# Jpake

This implements https://www.rfc-editor.org/rfc/rfc8236 for go using ECC. Currently only the
(three-pass variant)[https://www.rfc-editor.org/rfc/rfc8236#section-4] is implemented.
The interface allows for passing in any EC that conforms to `jpake.Curve[P CurvePoint[P]]` interface.
At present, only Curve-25519 is implemented. For the underlying EC math, (filippo.io/edwards25519)[https://pkg.go.dev/filippo.io/edwards25519#section-readme].

For key confirmation, the procedure outlined in the rfc based on the SPEKE protocol is implemented.

Pull requests are welcome! If you wish to add more curves, add the 2-pass variant or other key confirmation methods, please do, and thanks.