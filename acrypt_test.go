// Package acrypt provides an interface similar to the bcrypt library interface,
// but uses the Argon2id hashing algorithm for improved security.
package acrypt

import (
	"fmt"
	"testing"
)

func TestMatching(t *testing.T) {
	tests := []struct {
		name     string
		password string
		hash     []byte
		matches  bool
	}{
		{
			name:     "good password matches",
			password: "secret",
			hash:     nil,
			matches:  true,
		},
		{
			name:     "bad password does not match",
			password: "secret",
			hash:     nil,
			matches:  false,
		},
	}

	badPassword := "bad password"
	badPwdHash, err := Hash(badPassword)
	if err != nil {
		t.Fatalf("failed to hash pwd: %s", badPassword)
	}

	for i := 0; i < len(tests); i++ {
		if tests[i].matches {
			h, err := Hash(tests[i].password)
			if err != nil {
				t.Fatalf("failed to hash pwd: %s", tests[i].password)
			}
			tests[i].hash = h
		} else {
			tests[i].hash = badPwdHash
		}
	}

	for i := 0; i < len(tests); i++ {
		tt := tests[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if Verify(tt.hash, tt.password) != tt.matches {
				t.Errorf("%s failed, expected: %v", tt.name, tt.matches)
				return
			}
		})
	}
}

func TestPasswordRoundTripEasyAPI(t *testing.T) {

	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "basic password",
			password: "123456",
			wantErr:  false,
		},
		{
			name:     "basic password",
			password: "123456",
			wantErr:  false,
		},
	}

	for i := 0; i < len(tests); i++ {
		tt := tests[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Hash(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("Hash() error = %v, wantErr = %v", err, tt.wantErr)
				return
			}
			if !Verify(got, tt.password) {
				t.Errorf("round trip of password %v failed", tt.password)
				return
			}
		})
	}
}

func TestPasswordRoundTripBcryptAPI(t *testing.T) {

	configs := []*Config{
		DefaultConfig,
		{
			MemoryKB:    1 << 15, // 32MB
			Times:       3,
			Parallelism: 2,
			SaltLength:  16,
			KeyLength:   32,
		},
		{
			MemoryKB:    1 << 16,
			Times:       2, // fewer iters
			Parallelism: 2,
			SaltLength:  16,
			KeyLength:   32,
		},
		{
			MemoryKB:    1 << 16,
			Times:       3,
			Parallelism: 1, // fewer threads
			SaltLength:  16,
			KeyLength:   32,
		},
		{
			MemoryKB:    1 << 16,
			Times:       3,
			Parallelism: 2,
			SaltLength:  32, // longer salt
			KeyLength:   32,
		},
	}
	type args struct {
		password []byte
		cfg      *Config
	}
	tests := []struct {
		name       string
		args       args
		wantGenErr bool
		wantCmpErr bool
	}{
		{
			name:       "basic password with default config",
			args:       args{[]byte("123456"), configs[0]},
			wantGenErr: false,
			wantCmpErr: false,
		},
		{
			name:       "basic password with nil config",
			args:       args{[]byte("123456"), nil},
			wantGenErr: false,
			wantCmpErr: false,
		},
		{
			name:       "empty password with default config",
			args:       args{[]byte(""), configs[0]},
			wantGenErr: false,
			wantCmpErr: false,
		},
		{
			name:       "nil password with default config",
			args:       args{nil, configs[0]},
			wantGenErr: false,
			wantCmpErr: false,
		},
		{
			name:       "basic password with cfg1 - lower memory",
			args:       args{[]byte("123456"), configs[1]},
			wantGenErr: false,
			wantCmpErr: false,
		},
		{
			name:       "basic password with cfg2 - fewer iterations",
			args:       args{[]byte("123456"), configs[2]},
			wantGenErr: false,
			wantCmpErr: false,
		},
		{
			name:       "basic password with cfg3 - fewer threads",
			args:       args{[]byte("123456"), configs[3]},
			wantGenErr: false,
			wantCmpErr: false,
		},
		{
			name:       "basic password with cfg4 - longer salt",
			args:       args{[]byte("123456"), configs[4]},
			wantGenErr: false,
			wantCmpErr: false,
		},
	}

	for i := 0; i < len(tests); i++ {
		tt := tests[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := GenerateFromPassword(tt.args.password, tt.args.cfg)
			if (err != nil) != tt.wantGenErr {
				t.Errorf("GenerateFromPassword() error = %v, wantGenErr %v", err, tt.wantGenErr)
				return
			}
			err = CompareHashAndPassword(got, tt.args.password)
			if (err != nil) != tt.wantCmpErr {
				t.Errorf("CompareHashAndPassword() error = %v, wantCmpErr %v", err, tt.wantCmpErr)
				return
			}
		})
	}
}

func TestUniqueness(t *testing.T) {

	type args struct {
		password []byte
	}
	tests := []struct {
		name       string
		args       args
		wantGenErr bool
		wantCmpErr bool
	}{
		{
			name:       "hashes unique even for same plain pwd",
			args:       args{[]byte("123456")},
			wantGenErr: false,
			wantCmpErr: false,
		},
		{
			name:       "hashes unique even for same empty pwd",
			args:       args{[]byte("")},
			wantGenErr: false,
			wantCmpErr: false,
		},
		{
			name:       "hashes unique even for same nil pwd",
			args:       args{nil},
			wantGenErr: false,
			wantCmpErr: false,
		},
	}

	for i := 0; i < len(tests); i++ {
		tt := tests[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got1, err := GenerateFromPassword(tt.args.password, nil)
			if (err != nil) != tt.wantGenErr {
				t.Errorf("GenerateFromPassword() error = %v, wantGenErr %v", err, tt.wantGenErr)
				return
			}
			got2, err := GenerateFromPassword(tt.args.password, nil)
			if (err != nil) != tt.wantGenErr {
				t.Errorf("GenerateFromPassword() error = %v, wantGenErr %v", err, tt.wantGenErr)
				return
			}

			if string(got1) == string(got2) {
				t.Errorf("passwords NOT unique")
				return
			}
		})
	}
}

func ExampleHash() {
	pwd := "secret"
	hash, err := Hash(pwd)
	if err != nil {
		fmt.Print(err)
	}
	fmt.Println(hash)
}

func ExampleVerify() {
	pwd := "secret"
	hash, err := Hash(pwd)
	if err != nil {
		fmt.Print(err)
	}
	if Verify(hash, pwd) {
		fmt.Println("the password is good")
	}
}

func ExampleGenerateFromPassword() {
	pwd := []byte("secret")
	hash, err := GenerateFromPassword(pwd, DefaultConfig)
	if err != nil {
		fmt.Print(err)
	}
	fmt.Println(string(hash))
}

func ExampleCompareHashAndPassword() {
	pwd := []byte("secret")
	hash, err := GenerateFromPassword(pwd, DefaultConfig)
	if err != nil {
		fmt.Print(err)
	}
	if CompareHashAndPassword(hash, pwd) == nil {
		fmt.Println("the password is good")
	}
	// Output: the password is good
}
