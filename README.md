# Hash

Hash algorithms in Golang

[![PkgGoDev](https://pkg.go.dev/badge/github.com/JuneKimDev/hash)](https://pkg.go.dev/github.com/JuneKimDev/hash)
[![Go Report Card](https://goreportcard.com/badge/github.com/JuneKimDev/hash)](https://goreportcard.com/report/github.com/JuneKimDev/hash)
![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/JuneKimDev/hash)
![GitHub](https://img.shields.io/github/license/JuneKimDev/hash)

---

## Getting Started

### Installing

go get it (pun intended :smile_cat:)

```shell
go get github.com/JuneKimDev/hash
```

## Usage

```golang
package main

import (
  "log"

  "github.com/JuneKimDev/hash"
)


func main() {
  // Got password over https
  // Hash it to store
  hashedPassword, err := Run(password)
  if err != nil {
    log.Println(err)
  }

  // Got password over https &
  // Got store password from DB
  // Verify it
  match, err := Verify(password, hashedPassword)
  if err != nil {
    log.Println(err)
  }

  // Hashing a file with sha1 algorithm
  filename := "HASH_ME.txt"
  if hashedFile, err := RunFile(filename); err != nil {
    log.Println(err)
  }
  // Use hashedFile to evaluate equality of two files
  // like what GIT does...

  // Lightweight but risky hashing
  // SHA1 algorithm is not considered as a secure algorithm at this moment of time
  // But there are many use cases SHA1 algorithm can be useful

  // RunSha1 can take more than one string; order matters
  hash1 := RunSha1(input1, input2)
  hash2 := RunSha1(input3, input4)
  if hash1 == hash2 {
    log.Println("Same inputs")
  }
}
```
