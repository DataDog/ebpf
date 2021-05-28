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
	"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x8c\x54\x31\x8b\x13\x41\x14\xfe\x26\x89\xb9\xe8\x9d\x10\xad\xce\x90\x22" +
		"\xa5\x16\xce\xdd\x59\x58\x1f\x07\xc6\xe6\x0a\xd1\x94\xca\xba\xee\x8d\xb8\x98\x6c\x64\x67\x10\x73\x11\x04\x41\x10" +
		"\x1b\x6d\xac\x4f\x7f\x45\x4a\xff\x82\x3f\xe1\x4a\x41\x8b\x08\x82\x56\xae\xcc\xdc\x9b\x64\x78\xd9\x25\x3e\x98\xcc" +
		"\xcc\x37\xf3\xbd\xf7\xbd\x2f\xc3\xbe\xba\x75\xd8\xaf\x09\x01\x1f\x02\xbf\xb1\xdc\x2d\xe3\x53\x6d\xb9\xde\xa7\xdf" +
		"\x2d\x08\xcc\x04\x60\xae\x5d\x40\xd2\xf9\x53\x58\x74\x5b\x00\x79\x9c\x28\xbb\x7e\x36\x4e\xb3\x69\x67\xbe\xc0\x55" +
		"\x66\x1c\x9e\xf7\xae\x9a\x69\xe7\xdb\x02\x1f\x3d\x3d\x4a\x1d\x1e\x9b\xde\xb4\x73\xea\xf0\x2f\x9f\xcf\x6a\x6d\x08" +
		"\xe0\xb4\x28\x8a\x59\x0d\xe8\x02\x78\x03\xa0\x09\x60\x46\x5a\x3e\x32\x9d\x36\x97\xcd\x63\x6b\xd9\x3a\x56\x8b\xd5" +
		"\x61\x35\xde\xbe\x73\x88\xbf\x45\x51\x9c\x7c\x17\xd8\x66\x3c\xd7\x73\x78\xd0\x08\x46\x0b\x40\xfb\x0c\x6e\xfb\xfb" +
		"\xc7\x77\xd1\x7a\xb9\x29\xb6\x6c\x0f\x34\x7c\xbc\x2d\xf1\x8f\x87\x76\xa9\x7f\x16\x65\x67\x75\xd4\x57\xb0\xfb\x00" +
		"\x2e\xe1\xdc\x62\xdf\xa0\xf9\x9e\xc3\x9b\x2b\xb8\xd5\x79\x39\xc8\xe3\x35\x75\x83\x7e\xdd\x5f\x2a\x8d\x7a\x61\x20" +
		"\x0f\x06\x7d\x69\x17\x4b\xc3\x22\x3d\xd1\x91\xb3\x31\x22\x53\x83\xc3\x1d\x3d\xd1\x49\x3c\x1c\xea\x9d\xd5\x5b\xd1" +
		"\x73\x95\xeb\x74\x9c\x21\x1a\xa6\x89\xca\xb4\x82\xcc\xd5\x50\xaa\x27\xd1\xe3\x3c\x1e\x29\x8c\xe2\x34\x93\x09\xa4" +
		"\x36\xb9\x89\x1f\x41\xea\xc9\xc8\xcd\x07\x83\x3e\x64\x3e\x3e\x8a\x4d\x6c\xcf\xf6\xe4\xde\xcd\xff\x30\x72\x4d\x1c" +
		"\x3b\x3f\x4b\x82\xde\xf3\x09\x83\xf9\xdb\x17\x34\x9a\x0c\xdf\xaf\xa8\xd7\x60\xfb\xeb\x6b\xf8\xfc\xad\xb4\xd8\xfe" +
		"\x3d\xf1\x6f\x30\xfc\x2b\xcd\x5d\x86\xb7\x59\x1f\x0f\x68\xcd\x3d\xf8\x51\xa1\x97\xf7\x3f\xa8\xe0\xcf\x2b\xf8\x7c" +
		"\xff\xae\x24\xa7\x8d\x5f\x34\x5f\x59\x53\x7f\xa3\x82\x7f\x91\xc0\xde\x1a\x7e\x1a\xbe\xf5\x20\x76\xe9\xe2\x2e\xc3" +
		"\xb9\xff\xf6\x83\x75\xbe\xa4\xfe\x9c\xf8\xde\xef\x4d\xba\xe7\xf9\x1e\x7f\x5d\x52\xdb\xc6\x43\xe2\x7f\x08\x74\xd7" +
		"\x03\xbe\xff\x9e\xfc\x0b\x00\x00\xff\xff\x83\x97\x90\xc4\xa0\x05\x00\x00")

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
		size:        1440,
		md5checksum: "",
		mode:        os.FileMode(420),
		modTime:     time.Unix(1594295152, 0),
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
