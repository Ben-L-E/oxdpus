// Code generated by go-bindata. (@generated) DO NOT EDIT.

// Package gen generated by go-bindata.// sources:
// pkg/xdp/prog/obj/.gitkeep
// pkg/xdp/prog/obj/xdp.o
package gen

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
		return nil, fmt.Errorf("read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

// Name return file name
func (fi bindataFileInfo) Name() string {
	return fi.name
}

// Size return file size
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}

// Mode return file mode
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}

// ModTime return file modify time
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}

// IsDir return file whether a directory
func (fi bindataFileInfo) IsDir() bool {
	return fi.mode&os.ModeDir != 0
}

// Sys return file is sys mode
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _Gitkeep = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x01\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00")

func GitkeepBytes() ([]byte, error) {
	return bindataRead(
		_Gitkeep,
		".gitkeep",
	)
}

func Gitkeep() (*asset, error) {
	bytes, err := GitkeepBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: ".gitkeep", size: 0, mode: os.FileMode(420), modTime: time.Unix(1597452100, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _xdpO = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xec\x9c\x5b\x68\x5c\x55\x17\xc7\xf7\xcc\xa4\x49\xda\xb4\xc9\x34\x97\xaf\x69\x7a\xc9\xb4\x69\x93\x5e\x93\x99\x33\x49\x93\xef\xfb\x8a\xa4\x17\x7b\x91\x88\x83\x34\x5a\x45\xc9\xa5\x4d\x9b\xd0\x69\x9d\x36\x51\x62\x15\x9a\x3e\x58\x8b\x54\x0c\x05\x21\x20\x96\xa0\x3e\x54\x11\x1d\x41\xac\x88\x92\xd0\x17\x8b\x78\x29\xe2\x43\x51\x2a\x01\x41\x14\x8a\x46\x11\x0c\x52\x1d\x59\xeb\x9c\x71\x76\xd7\xda\xdb\xee\xed\xab\x7b\x41\x7b\xba\x7e\xf9\xff\xf7\xcc\xf9\xef\x93\x75\x4e\x52\x92\x53\x77\x76\xed\x0a\x87\x42\x22\x5f\x21\xf1\xab\x28\x74\x85\x1a\xdc\x5d\xf8\x77\x67\xf0\x77\x9b\x08\x89\x4b\xc5\x3e\xeb\xab\x2c\xf2\x8f\x8b\xfd\x7e\xaa\xca\x3f\x96\x44\x84\x28\x17\x42\x6c\x6e\x68\xc6\x65\x8f\x57\x2f\x44\x7e\xbc\x6a\x11\x1e\x0f\x47\x84\x28\x15\x42\xdc\xb3\xc3\xd7\xd7\x44\xc2\xe2\xec\x45\x21\x2e\x15\xf9\xbe\xee\x48\xb1\x38\x4d\xd6\xab\x14\xe2\xaf\xd7\xdd\xdc\xd0\x80\xeb\x82\x1e\xf8\x50\x55\x14\x39\x7c\x3c\x2c\x84\xb8\x3f\x22\x44\x2e\x07\xeb\xae\x0c\x9d\xb9\x2e\x44\xc5\x36\xfe\xfe\xaa\x6f\x59\x6f\x69\xc8\x3f\x0f\xff\x7d\x1e\xa8\xbb\x99\x43\xfd\x4b\x81\x3e\x2c\xc4\xcd\x5c\x2e\x57\x4b\x42\x7a\x0a\xb3\xf3\xd7\x81\x63\xb7\x88\x86\x6c\x7c\xdd\x62\x81\xa5\xbe\xc8\x52\xff\x87\xb0\xd3\xcf\x59\xea\x7f\xb6\xd4\xdf\xb0\xd4\x7f\x6b\xa9\x9f\xb1\xd4\x7f\x69\xa9\xff\xc2\x52\xff\xa9\xa5\xfe\x8a\xa5\xfe\xb2\xa5\xfe\x7d\x4b\xfd\x3b\x96\xfa\xac\xa5\xfe\x35\x4b\xfd\x2b\x96\xfa\x0b\x96\xfa\x09\x4b\xfd\x79\x4b\xfd\x39\x4b\xfd\x19\x4b\xfd\x98\xa5\xfe\xa4\xa5\x7e\xc4\x52\x7f\xcc\x52\x3f\x68\xa9\xef\xb7\xd4\x3f\x64\xa9\xbf\xcf\x52\x9f\xb2\xd4\xdf\x65\xa9\xdf\x69\xa9\xbf\xc3\x52\xdf\x61\xa9\xf7\x2c\xf5\x9b\x2c\xf5\x8d\x96\xfa\x98\xa5\xbe\xce\x52\x5f\x6d\xa9\x2f\xb7\xd4\x97\x5a\xe9\xf3\xcf\x3b\x35\xc1\xd3\x5b\xfe\x39\x64\xaa\xd7\xd7\x3d\x1f\xe8\x81\x15\x05\x7f\x44\xa0\x05\xdf\xe1\xf4\x23\xfd\x7d\xe9\x61\xf1\x6f\x2d\x39\x97\x5c\xce\x67\x2e\x17\x97\x8b\xae\x5c\x2e\xea\x72\xb9\xa8\xcb\xe5\xa2\x2e\x97\x8b\xba\x5c\x2e\xea\x72\xb9\xa8\xcb\xe5\xa2\x2e\x97\x8b\xba\x5c\x2e\xea\x72\xb9\xa8\xcb\xe5\xa2\x2e\x97\x8b\xba\x5c\x2e\xea\x72\xb9\xa8\xcb\xe5\xa2\x2e\x97\x8b\xba\x5c\x2e\xea\x72\xb9\xa8\xcb\xe5\xa2\x2e\x97\x8b\xba\x5c\x2e\xea\x72\xb9\xa8\xcb\xe5\xa2\x2e\x97\x8b\xba\x5c\x2e\xea\x72\xb9\xa8\xcb\xe5\xa2\x2e\x97\x8b\xba\x5c\x2e\xea\x72\xb9\xa8\xcb\xe5\xa2\x2e\x97\x8b\xba\x5c\x2e\xea\x72\xb9\xa8\xcb\xe5\xa2\x2e\x97\x8b\xba\x5c\x2e\xea\x72\xb9\xa8\xcb\xe5\xa2\x2e\x97\x8b\xba\x5c\x2e\xea\x72\xb9\xa8\xcb\xe5\xa2\xae\x9d\x8f\xf6\xa5\x63\x77\xef\xdd\xd7\xb2\x3b\xd5\xf5\x77\xba\x65\x10\x96\x88\x04\x3f\xd5\x55\xa8\x83\x21\x9f\x4f\x10\x3e\x15\xf0\xc9\xf9\xb7\xf2\x15\x42\x88\xa8\x48\xb2\xf5\xa7\xc2\xc0\xe7\x31\xbe\x2b\x02\xbc\x9c\xf1\x30\xf2\x0a\xc6\xdf\xc0\x75\xa2\x8c\x3f\x88\x7c\x31\xe3\xb9\x10\xf0\x4a\xc6\x5f\x46\x5e\xc5\xf8\x1e\xe4\xd5\x8c\xff\x82\xe7\x55\xc3\xf8\x5b\xc8\xff\xc3\xf8\x31\xe4\x4b\x18\x3f\x82\xef\xb3\x98\xf1\x36\x3c\xdf\x5a\xc6\x7f\x42\xfd\x52\xc6\x5f\x44\x5e\xc7\xf8\x5e\xe4\xcb\x18\xff\x01\xcf\x6b\x39\xe3\xe7\x91\xaf\x60\xbc\x1d\xf9\x4a\xc6\xbf\xc1\xf3\xaa\x67\x7c\x12\x79\x8c\xf1\x87\x91\xaf\x62\x3c\x8a\xef\xb3\x84\xf1\x35\x98\xc3\x6a\xc6\x67\x50\xdf\xc0\xf8\x39\xe4\x6b\x18\xef\x40\xbe\x96\xf1\xeb\x78\x5e\x8d\x8c\x9f\x46\xde\xc4\x78\x23\xf2\x75\x8c\x7f\x8e\xe7\xb5\x9e\xf1\xe7\x90\x6f\x60\xbc\x0b\xf9\x46\xc6\xdf\xc6\xf5\x4b\x19\xaf\xc2\x1c\x36\x31\xfe\x19\x9e\xd7\x66\xc6\x9f\x40\xde\xcc\x78\x13\xf2\x16\xc6\x3f\xc6\xd7\x8d\x33\x9e\x41\x9e\x60\xbc\x06\xb9\xc7\xf8\x03\xc8\xe7\x33\x3e\x0f\xf9\x02\xc6\x2f\x63\x0e\x65\x8c\x9f\x42\xbe\x90\xf1\xad\xc8\x17\x31\x5e\x81\x3c\xc2\xf8\x5c\x70\x84\xf1\x04\xd3\x26\x1e\x2a\xf4\x30\x35\x7a\xa5\x1e\x3e\x4b\xc6\xa5\x1e\xae\x8a\x69\xa9\x87\x34\x67\xa5\x1e\x52\x8c\x85\x0b\x3d\xa4\x97\x92\x7a\x48\x6d\x4c\xea\x21\xad\xac\xd4\x17\x07\xd7\x71\xbe\x87\xab\x3f\x1a\x29\xf4\x70\x15\x74\x4a\x3d\xa4\x9a\x91\x7a\x48\x73\x52\xea\x21\xc5\xab\x52\x8f\xe9\x15\x15\x7a\x48\x2d\x2e\xf5\x30\x65\x7b\xa5\x1e\x32\x1c\x97\x7a\x98\x9e\xd3\x52\x0f\x53\x73\x56\xea\x61\x5a\xc6\xe6\x15\x7a\x98\x92\x29\xa9\x87\xe9\x38\x26\xf5\x30\x15\xb3\x52\x0f\xd3\x70\x46\xea\x61\xda\x45\x8b\x0b\x3d\x4c\xb9\x4e\xa9\x87\xe9\x96\x91\x7a\x98\x5e\x93\x52\x0f\x53\xeb\xaa\xd4\xe3\xb4\x2a\x29\xf4\x30\xa5\xe2\x52\x0f\xd3\xa9\x57\xea\x61\x2a\x8d\x4b\x3d\x4c\x9d\x69\xa9\x87\x69\x33\x2b\xf5\x30\x65\x62\xa5\x85\x1e\xa6\x4b\x4a\xea\x61\x7a\x8c\x49\x3d\x4c\x8d\xac\xd4\xc3\xb4\x98\x91\x7a\x98\x12\xd1\xf9\x85\x1e\xa6\x43\xa7\xd4\xc3\x67\x7f\x46\xea\xf1\xb3\xbe\x79\x64\x60\x74\x44\x34\x9f\x18\x48\x8f\x1e\xcc\xb4\x8c\x1e\xcc\xf4\x0c\x65\x7a\x0e\x0d\xa5\x47\x06\x4e\x88\x9e\x9e\xf4\xd0\x81\x81\x63\xc3\x03\xa2\x79\x78\xe4\xc4\x48\x5f\xbf\x68\x1e\x7e\xfc\x28\x1c\x8f\xf6\x65\x86\x5b\xfa\xd3\x7d\x07\x8e\xa4\x87\x86\x47\xfe\x4b\xfa\x24\x05\x1e\x05\x09\x0a\x3a\xe8\x12\x14\x78\x14\x24\x28\x68\xa7\x4b\x50\xe0\x51\x90\xa0\x60\x0b\xe9\x5b\x29\x48\x52\xe0\x51\x90\xa0\xa0\x4d\x74\x6d\xdf\x1e\xef\x69\xa3\x4b\x53\x90\xa4\xc0\xa3\x20\xc1\xd6\x08\x96\x6e\xa5\x9c\x82\x24\x05\x1e\x05\x09\x66\xf1\xd7\x4e\xd2\xa5\x29\x48\x52\xe0\x51\x90\x60\x0a\xba\x26\x05\x49\x0a\x3c\x0a\x12\x0c\xd0\x35\x29\x48\x52\xe0\x51\x90\x60\x6b\xc4\xe9\x1a\x14\x78\x14\x24\xf8\x1d\xf0\x9f\x55\x13\x3e\x0d\xf3\x8a\xfa\xbf\x06\x40\xdc\x4b\x3e\x48\x7e\x4c\x1c\xfb\xfc\x3d\x42\xae\x4e\xcd\xeb\x15\x91\xbe\xec\x36\xfe\x2c\xb9\x45\xd3\x27\x8e\x92\xe0\x7e\x43\x2b\x1e\xfc\x3e\x9e\xfc\x7d\xab\x35\x38\xcf\xbc\x3f\xff\x24\xfe\x5e\xd8\x7f\x7d\x9a\xc1\x6c\xb0\x28\xfd\xb9\x78\xfa\xfe\x0f\x69\xfc\xa5\x65\x66\xfe\x32\x8d\x3f\xb6\xd0\xcc\xff\x66\x48\xed\xef\x58\x64\xe6\xdf\xa7\xf1\xa7\xca\xcd\xfc\x42\xe3\x1f\xac\x30\xf3\x7f\x20\xd4\xfe\xb1\xa8\x99\xff\xa4\xc6\x3f\xb1\xd8\xcc\xdf\xae\xf1\x67\x2b\xcd\xfc\xdb\x22\x6a\xff\x95\x2a\x33\xff\xef\x9a\xfd\x9f\xa9\x36\xf3\xbf\xaa\xf1\xcf\xd5\x98\xf9\xbb\x35\xfe\xe8\x12\x33\xff\x6f\x9a\xfd\x5f\x57\x6b\xe6\xbf\xa0\xf1\x77\x2e\x35\xf3\xef\xd0\xf8\xf7\xd7\x99\xf9\x7f\xd4\xec\x7f\x66\x99\x99\xff\x75\x8d\xff\xec\x72\x33\xff\x90\xc6\x3f\xb9\xc2\xcc\x1f\xd7\x5c\x7f\xef\xae\x34\xf3\xdf\xd0\xec\xff\xd5\x7a\x33\xff\x84\xc6\xff\x5d\xcc\xcc\xbf\x53\xe3\xcf\x7f\x29\x7d\x3b\xff\xf7\x9a\xfd\xaf\x6d\x30\xf3\x3f\xab\xf1\xc7\xd7\x98\xf9\x3d\x8d\x7f\xcf\x5a\x33\xff\xd7\x9a\xfd\xef\x6d\x34\xf3\xbf\xa0\xf1\x8f\x36\x99\xf9\xf7\x6b\xfc\xe3\xeb\xcc\xfc\xf5\x9a\xeb\xef\xe2\x7a\x33\xff\x57\x9a\xfd\x9f\xde\x60\xe6\x7f\x5a\xe3\xbf\xb6\xd1\xcc\x9f\xd4\xdd\xff\x37\x99\xf9\xaf\x69\xf6\xbf\xb4\xd9\xcc\xff\xa4\xc6\x1f\x6b\x31\xf3\xaf\xd2\xdd\xff\xe3\x66\xfe\x4f\x34\xfb\x9f\x4a\x98\xf9\x9f\xd1\xf8\x07\x3d\x33\xff\x6e\xdd\xfd\x3f\x69\xe6\x2f\xd7\x5c\x7f\x13\xad\x66\xfe\x8f\x34\xfb\x9f\x6d\x33\xf3\x3f\xa6\xf1\x5f\xd9\x62\xe6\x5f\xad\xbb\xff\xb7\x9b\xf9\x3f\xd4\xec\xff\x5c\x87\x99\xff\x88\xc6\x1f\xfd\x9f\x99\x3f\xaa\xbb\xff\xff\xdf\xcc\x5f\xaf\xd9\xff\xce\xad\xfe\x91\x7e\x07\x8d\x7e\xfd\xd1\x12\xfc\x7f\x09\xad\x54\xe0\x9f\x91\xbe\x0f\x54\x24\x3d\xff\xe7\xbf\x63\xfd\x67\x00\x00\x00\xff\xff\x2b\x4e\x45\x35\xa8\x54\x00\x00")

func xdpOBytes() ([]byte, error) {
	return bindataRead(
		_xdpO,
		"xdp.o",
	)
}

func xdpO() (*asset, error) {
	bytes, err := xdpOBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "xdp.o", size: 21672, mode: os.FileMode(420), modTime: time.Unix(1597452333, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[canonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[canonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	".gitkeep": Gitkeep,
	"xdp.o":    xdpO,
}

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
// AssetDir("foo.txt") and AssetDir("nonexistent") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		canonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(canonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
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

var _bintree = &bintree{nil, map[string]*bintree{
	".gitkeep": &bintree{Gitkeep, map[string]*bintree{}},
	"xdp.o":    &bintree{xdpO, map[string]*bintree{}},
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
	err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
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
	canonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(canonicalName, "/")...)...)
}
