// Code generated by go-bindata. DO NOT EDIT.
// sources:
// ebpf/bin/probe.o

package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes []byte
	info  fileInfoEx
}

type fileInfoEx interface {
	os.FileInfo
	MD5Checksum() string
}

type bindataFileInfo struct {
	name        string
	size        int64
	mode        os.FileMode
	modTime     time.Time
	md5checksum string
}

func (fi bindataFileInfo) Name() string {
	return fi.name
}
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}
func (fi bindataFileInfo) MD5Checksum() string {
	return fi.md5checksum
}
func (fi bindataFileInfo) IsDir() bool {
	return false
}
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _bindataProbeo = []byte(
	"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x94\x55\xbf\x6b\x14\x4f\x14\xff\xec\x5d\x7e\xdc\xf7\xbe\xc1\x44\xab\xb8" +
		"\xa4\x58\x84\x40\xd2\x6c\x12\x09\x92\xc2\x22\x04\x12\x9b\x14\x22\x51\xec\x96\xcd\x65\x42\x96\xbd\xdd\x3d\x76\x27" +
		"\x21\xf1\x04\xb5\xb0\xd0\x52\xd0\x56\xad\x2c\xb5\x3b\x0b\xc1\x7f\xc0\x22\x65\xc0\x26\x65\xc0\x26\x82\xa0\x85\x64" +
		"\xe5\xcd\xcd\xe4\xe6\xe6\x6e\xbd\xf8\x60\x6f\xde\xfb\xcc\x7c\xde\xcf\xd9\xbd\x47\xab\xeb\x6b\x25\xcb\x82\x12\x0b" +
		"\x3f\xd1\xb1\x3a\x72\x32\xd4\xd1\x97\xe5\xef\x38\x2c\x4c\x5a\x40\x23\x09\x62\x42\xf8\x6c\x15\x4d\xfb\x34\x27\x9d" +
		"\xf0\xed\xcc\xd9\x21\x3d\x49\x42\xa7\x69\x9f\x9c\xe3\x51\xb8\x15\x90\x9e\x3a\x33\x7b\x4d\xfb\x58\xe0\x9f\xdf\xb6" +
		"\x7d\x8f\x5a\xc0\x71\x9e\xe7\xad\x12\x30\x09\xe0\x29\x80\x11\x00\x2d\x19\xfb\xa5\x5c\x5b\x16\x10\x57\x81\xd0\xfe" +
		"\x9d\x2b\x3b\x89\xa2\xa4\x66\xff\x3a\x8f\xb3\xcb\x83\x88\x74\x96\x79\x35\x95\x57\x4b\x16\x97\xd9\x67\x3d\x71\x4f" +
		"\x65\xdc\xf1\x41\x71\xf9\x6c\xb5\xa6\xd5\xb9\x93\x24\x21\xe9\x4e\x23\x09\xf4\x3a\xb3\x83\xac\x46\xba\x5f\xaf\x3b" +
		"\xaa\x4e\xc2\x53\xc6\x77\x45\xfd\xb1\x33\xd3\xb4\x8f\x7a\xfb\xe2\x73\xa7\x69\x1f\x1a\xf9\xfe\xe8\xc9\xf7\x50\xe6" +
		"\x3b\xfd\x97\x7c\xc9\x27\xf5\x99\x66\x41\x73\xa0\x59\xd1\x9c\xa0\xef\xfb\xdc\xa1\x9c\x28\x1f\xca\x99\xf2\xed\x3a" +
		"\x4c\x8d\xa4\x26\x52\x83\xe3\x2a\x6e\xdd\x5e\xc7\x59\x9e\xe7\xaf\xbf\x59\x62\x46\xba\x88\x74\xf5\x8d\x21\xed\xa9" +
		"\x00\x98\x68\xc3\x13\xea\xfc\x83\x3b\xa8\x3c\xfc\xdf\x1a\x43\x7b\xde\xba\xbf\x7d\x4d\x9f\x02\xb0\x58\xb0\xa7\xf6" +
		"\x37\x34\xfb\x03\x2e\x26\x6f\x44\x6a\xdf\xf3\x7e\x7b\x65\x94\xfb\x72\xca\x18\x2a\xc0\x87\x7b\xb0\x67\x00\x2e\x8b" +
		"\xc2\xdb\xa2\x98\x8f\x05\xfe\x5f\x0f\x7e\x0f\xc0\x15\xcd\xbf\xaa\x73\x51\xe0\xe5\x1e\xfc\x9a\xc0\x3b\x71\x55\xdd" +
		"\x53\x72\xa5\x79\x94\x00\x2c\x69\x36\x79\xb9\xaf\xd9\x22\x9a\xcb\xd9\x3e\x87\xbb\xb2\xb1\xe6\x92\x12\xa6\x8c\x37" +
		"\xd2\x64\x93\xcd\xc9\x1b\xd2\x46\x92\x4d\xe6\xed\xc6\xf5\x20\x0e\x09\x11\x07\xbc\xbd\xed\xcc\x13\x87\x24\x30\x67" +
		"\x02\x5e\xd7\xfd\x51\xa7\xba\x41\x6f\x8f\xa5\x59\x40\x4a\x3d\xa8\xb1\x38\x63\x70\x53\x56\x77\xd9\x8e\xb7\x9d\xfa" +
		"\x11\x43\xe4\x07\xb1\x5b\x83\x9b\xf1\x94\xfb\x9b\x70\xb3\x83\x48\xac\x2b\x1b\x6b\x70\xd3\x64\xcb\xe7\x3e\xed\x2d" +
		"\xb8\x0b\x37\x0c\xbb\xef\xa8\xfe\x59\xde\xc9\xbe\x99\x52\x91\xa3\xfa\x6a\xe0\xe6\x37\xd4\x92\xcf\x88\x81\x2f\x17" +
		"\xc4\x33\x6f\xd8\xea\x00\xbe\xf9\x3e\x54\x0c\x3b\x2c\xe0\x7f\xbc\x20\x7f\xa2\x80\x3f\x2f\x0b\x35\xdf\x37\x93\xff" +
		"\x49\xf2\xaf\x1b\xf8\xb1\xe4\xaf\xf6\x89\x07\xad\x8f\x5f\x0a\xf8\xd3\xa5\xf6\x3a\x6e\xe0\x96\xb1\x3e\xd7\xee\xbe" +
		"\x2e\x8b\x92\x6f\xf6\xdb\x9c\xdf\x93\x02\xfe\x52\x01\xdf\xb4\x5b\x7d\x7c\x92\xdc\x94\xfc\xab\x03\xe2\x8f\x16\xf0" +
		"\xef\x4a\xbe\x33\x80\xff\x4a\xfb\x16\xe8\xb2\x2f\x81\x86\x81\x9b\xf3\x7b\x01\x68\x5f\xab\x8e\x1c\xc9\x86\xcc\x4b" +
		"\xfb\x12\x80\x31\x8d\xaf\xe6\xf8\xbe\x4f\x6c\x92\x13\x09\x9e\x6a\x79\x0f\x6b\x7c\xf5\x7f\xf0\x27\x00\x00\xff\xff" +
		"\x66\x31\x61\xca\xa8\x08\x00\x00")

func bindataProbeoBytes() ([]byte, error) {
	return bindataRead(
		_bindataProbeo,
		"/probe.o",
	)
}

func bindataProbeo() (*asset, error) {
	bytes, err := bindataProbeoBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{
		name:        "/probe.o",
		size:        2216,
		md5checksum: "",
		mode:        os.FileMode(420),
		modTime:     time.Unix(1594312574, 0),
	}

	a := &asset{bytes: bytes, info: info}

	return a, nil
}

//
// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
//
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrNotExist}
}

//
// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
// nolint: deadcode
//
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

//
// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or could not be loaded.
//
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrNotExist}
}

//
// AssetNames returns the names of the assets.
// nolint: deadcode
//
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

//
// _bindata is a table, holding each asset generator, mapped to its name.
//
var _bindata = map[string]func() (*asset, error){
	"/probe.o": bindataProbeo,
}

//
// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
//
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, &os.PathError{
					Op:   "open",
					Path: name,
					Err:  os.ErrNotExist,
				}
			}
		}
	}
	if node.Func != nil {
		return nil, &os.PathError{
			Op:   "open",
			Path: name,
			Err:  os.ErrNotExist,
		}
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}

var _bintree = &bintree{Func: nil, Children: map[string]*bintree{
	"": {Func: nil, Children: map[string]*bintree{
		"probe.o": {Func: bindataProbeo, Children: map[string]*bintree{}},
	}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	return os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}
