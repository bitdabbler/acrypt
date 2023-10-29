# Acrypt

## Overview

Secure password hashing using the Argon2id hashing algorithm.

## Usage

### Simple API

The simplest API accepts password inputs directly as strings.

#### Hashing a password

```go
import (
    // ...
    github.com/bitdabbler/acrypt
)
```
```go
pwd := "secret"
hash, err := acrypt.Hash(pwd)
if err != nil {
    log.Print(err)
}
fmt.Println(hash)
```

#### Verifying a password

```go
pwd := "secret"
hash, err := acrypt.Hash(pwd)
if err != nil {
    log.Print(err)
}
if acrypt.Verify(hash, pwd) {
    log.Println("the password is good")
}
```

### (Also simple) Bcrypt-like API

The other API expects passwords to be passed as byte slices, and uses naming similar that used in the Go Bcrypt package.

ref: https://pkg.go.dev/golang.org/x/crypto/bcrypt

#### Hashing a password

```go
pwd := []byte("secret")
hash, err := acrypt.GenerateFromPassword(pwd, DefaultConfig)
if err != nil {
    log.Print(err)
}
fmt.Println(hash)
```

#### Verifying a password

```go
pwd := []byte("secret")
hash, err := acrypt.GenerateFromPassword(pwd, DefaultConfig)
if err != nil {
    log.Print(err)
}
if acrypt.CompareHashAndPassword(hash, pwd) == nil {
    log.Println("the password is good")
}
```
