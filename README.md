# Acrypt

## Overview

Secure password hashing using the Argon2id hashing algorithm. There is a simple API that works with strings, but also an API similar to that of the popular Bcrypt library.

## Usage

### Simple API

#### Hashing a password

```go
pwd := "secret"
hash, err := Hash(pwd)
if err != nil {
    log.Print(err)
}
fmt.Println(hash)
```

#### Verifying a password

```
pwd := "secret"
hash, err := Hash(pwd)
if err != nil {
    log.Print(err)
}
if Verify(hash, pwd) {
    log.Println("the password is good")
}
```

### Bcrypt-like API

#### Hashing a password

```go
pwd := []byte("secret")
hash, err := GenerateFromPassword(pwd, DefaultConfig)
if err != nil {
    log.Print(err)
}
fmt.Println(hash)
```

#### Verifying a password

```go
pwd := []byte("secret")
hash, err := GenerateFromPassword(pwd, DefaultConfig)
if err != nil {
    log.Print(err)
}
if CompareHashAndPassword(hash, pwd) == nil {
    log.Println("the password is good")
}
```
