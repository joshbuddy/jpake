# J-PAKE

[![Go Reference](https://pkg.go.dev/badge/github.com/joshbuddy/jpake.svg)](https://pkg.go.dev/github.com/joshbuddy/jpake)

This implements https://www.rfc-editor.org/rfc/rfc8236 for go using ECC. Currently only the
[three-pass variant](https://www.rfc-editor.org/rfc/rfc8236#section-4) is implemented.
The interface allows for passing in any EC that conforms to `Curve[P CurvePoint[P, S], S CurveScalar[S]]` interface.
At present, only Curve-25519 has a compatible interface. The package [filippo.io/edwards25519](https://pkg.go.dev/filippo.io/edwards25519) provides the underlying implementation used by this interface.

## Security considerations

Password selection for J-PAKE is defined as s "a secret value derived from a low-entropy password shared between Alice and Bob". As such, care should be taken to ensure the entropy of that password matches your target application. The configuration provided to the initializing function allows for setting a KDF for both stretching the secret value and the derived session key. The default secret key kdf uses a fixed-salt, so in cases where a low entropy password is used, a different salt should be used.

As well, the default curve used here (curve25519) will panic if given uninitialized inputs. As such, if you use this curve you must recover from this panic in processing any of the J-PAKE steps. For example, the following code could be used within a function calling one of the processing functions:

```
defer func() {
  if r := recover(); r != nil {
    switch x := r.(type) {
    case string:
      if x == "edwards25519: use of uninitialized Point" {
        err = errors.New(x)
      }
    default:
      panic(r)
    }
  }
}()
```

For key confirmation, the procedure outlined in the rfc based on [NIST SP 800-56A Revision 1](http://csrc.nist.gov/publications/nistpubs/800-56A/SP800-56A_Revision1_Mar08-2007.pdf) is implemented.

This code is currently unaudited and should not be used in a production setting without a full audit.

## Contributing and ackwoledgements

Pull requests are welcome! If you wish to add more curves, add the 2-pass variant or other key confirmation methods, please do, and thanks in advance.

Also thanks to @choonkiatlee for https://github.com/choonkiatlee/jpake-go which was very helpful in making this. This library improves on this by adding support for a
user id within the ZKP. As well, it no longer relies on `crypto/elliptic` (see https://github.com/golang/go/issues/52221).
