package key

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

type user struct {
	ID   uint64
	Name string
}

func TestParseKey(t *testing.T) {
	key, err := ParsePrivateKey("b41ed39ac35adcee9121dbc7331134f28693ae1103a7f59c2850c4dcf4352848")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 32, len(key.k))
}

func TestKeys(t *testing.T) {
	p1, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	p2, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	msg, err := p1.SealBase58(p2.Public(), &user{1, "John"})
	if err != nil {
		t.Fatal(err)
	}

	var u user
	if err := p2.OpenBase58(p1.Public(), msg, &u); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, uint64(1), u.ID)
	assert.Equal(t, "John", u.Name)
}
