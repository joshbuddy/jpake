package jpake

type HashFnType func(in []byte) []byte
type MacFnType func(key, msg []byte) []byte
type ZKPMsg[P CurvePoint[P, S], S CurveScalar[S]] struct {
	T P
	R S
}

type Config struct {
	sessionConfirmationBytes []byte
	secretGenerationBytes    []byte
	sessionGenerationBytes   []byte
	hashFn                   HashFnType
	macFn                    MacFnType
}

func NewConfig() *Config {
	return &Config{
		sessionConfirmationBytes: []byte("JPAKE_CONFIRM"),
		secretGenerationBytes:    []byte("SECRET"),
		sessionGenerationBytes:   []byte("SESSION"),
		hashFn:                   sha256HashFn,
		macFn:                    hmacsha256KDF,
	}
}

func (c *Config) SetSessionConfirmationBytes(scb []byte) *Config {
	c.sessionConfirmationBytes = scb
	return c
}

func (c *Config) SetSecretGenerationBytes(s []byte) *Config {
	c.secretGenerationBytes = s
	return c
}

func (c *Config) SetSessionGenerationBytes(s []byte) *Config {
	c.sessionGenerationBytes = s
	return c
}

func (c *Config) SetHashFn(h HashFnType) *Config {
	c.hashFn = h
	return c
}

func (c *Config) SetMacFn(f MacFnType) *Config {
	c.macFn = f
	return c
}

func (c *Config) generateSecret(pw []byte) []byte {
	return c.hashFn(c.macFn(pw, c.secretGenerationBytes))
}

func (c *Config) generateConfirmationMac(k, msg []byte) []byte {
	return c.macFn(c.macFn(k, c.sessionConfirmationBytes), msg)
}

func (c *Config) generateSessionKey(k []byte) []byte {
	return c.macFn(k, c.sessionGenerationBytes)
}
