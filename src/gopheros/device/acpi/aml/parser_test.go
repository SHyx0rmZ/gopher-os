package aml

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/davecgh/go-spew/spew"
)

func TestParser(t *testing.T) {
	f, err := os.Open(pkgDir() + "/example.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	amlStream, err := ioutil.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}

	rootNs, err := Parse(amlStream, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}

	spew.Config.DisablePointerAddresses = true
	spew.Dump(rootNs)
}

func pkgDir() string {
	_, f, _, _ := runtime.Caller(1)
	return filepath.Dir(f)
}
