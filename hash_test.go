package hash

import (
	"io/ioutil"
	"log"
	"os"
	"testing"
)

func TestVerifyTrue(t *testing.T) {
	password := "strongP@S$w0rd"
	hashedPassword, err := Run(password)
	if err != nil {
		log.Fatal(err)
	}
	match, err := Verify(password, hashedPassword)
	if err != nil {
		log.Fatal(err)
	}
	if !match {
		t.Errorf("Failed to verify the password, got: %v, want: %v.", match, true)
	}
}

func TestVerifyFalse(t *testing.T) {
	password := "strongP@S$w0rd"
	hashedPassword, err := Run(password)
	if err != nil {
		log.Fatal(err)
	}
	match, err := Verify(password+"1", hashedPassword)
	if err != nil {
		log.Fatal(err)
	}
	if match {
		t.Errorf("Failed to verify the password, got: %v, want: %v.", match, false)
	}
}

func TestRunFile(t *testing.T) {
	filename := "hashFileTest.txt"
	// create a file to test
	text := `Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.
Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.
Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.`
	if err := ioutil.WriteFile(filename, []byte(text), 0644); err != nil {
		log.Println("Failed to create a text file for the test")
	}

	if _, err := RunFile(filename); err != nil {
		t.Errorf("Failed to hash a file: %v", err)
	}

	defer os.Remove(filename)
}

func TestRunSha1(t *testing.T) {
	s1 := "test1"
	s11 := "test1"
	s2 := "test2"
	r1 := RunSha1(s1)
	r11 := RunSha1(s11)
	r2 := RunSha1(s2)
	if r1 != r11 {
		t.Errorf("Two hashes with the same string do not match: 1-%v, 2-%v", r1, r2)
	}
	if r1 == r2 {
		t.Errorf("Two hashes with the different string are same: 1-%v, 2-%v", r1, r2)
	}
}

func TestRunSha1Sum(t *testing.T) {
	s1 := "test1"
	s2 := "test2"
	s3 := "test3"
	r1 := RunSha1(s1, s2)
	r2 := RunSha1(s1, s3)
	r3 := RunSha1(s2, s3)
	r11 := RunSha1(s2, s1)
	if r1 == r2 {
		t.Errorf("Two hashes with the different string are same:\n1-%v, 2-%v", r1, r2)
	}
	if r1 == r3 {
		t.Errorf("Two hashes with the different string are same:\n1-%v, 2-%v", r1, r2)
	}
	if r2 == r3 {
		t.Errorf("Two hashes with the different string are same:\n1-%v, 2-%v", r1, r2)
	}
	if r1 == r11 {
		t.Errorf("Two hashes with the different order of string are same:\n1-%v, 2-%v", r1, r2)
	}
}
