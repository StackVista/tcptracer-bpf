// Code generated by go-bindata.
// sources:
// ../dist/tcptracer-ebpf.o
// DO NOT EDIT!

package tracer

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
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
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
func (fi bindataFileInfo) IsDir() bool {
	return false
}
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _tcptracerEbpfO = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xc4\x5c\x7f\x6c\x5c\x57\x56\xbe\x6f\xc6\x93\x19\xbb\xcd\xda\xa4\x9d\xc6\x19\x58\xe4\xa5\xd0\x9a\x81\x76\x3d\x8e\x93\x78\x4d\x97\xf5\x66\xb7\xdb\xc1\xaa\xf0\xa8\x8a\xa9\x15\xb5\x8c\x67\xa7\x93\xda\x99\x6c\x32\x19\x4f\x6a\xbf\xce\x0a\x22\x96\x94\x60\xad\x56\x4e\xb7\x20\x53\x65\x91\xc7\x71\xa8\x81\x42\x2d\x2d\x90\xfc\x01\x1a\xb3\x2a\xc2\x42\x2b\xb0\x50\x84\x8c\x64\x90\x05\xd1\xca\xac\x2a\x14\x50\x15\x79\xab\x8a\x41\x73\xcf\xf7\xe6\xbd\x7b\xde\x7d\x6f\xc6\x49\x76\x77\xa4\xf4\xf4\x9e\x7b\xcf\x39\xf7\xc7\xb9\xe7\x7e\xe7\xbe\x9b\xfc\xe6\xb3\xcf\x7f\x29\x60\x18\xc2\xfa\x19\xf8\xc3\x7f\x37\x3f\x6f\xff\xff\x30\xfe\xfb\x93\xc2\x10\xd5\xc7\x88\x77\x49\x08\xf1\x09\x21\x44\xb9\xe3\x4e\xad\x5e\x36\x33\x05\xc9\x2f\xc7\x76\x65\xb9\xba\x44\xed\xc2\x01\x21\xee\xd4\x6a\xb5\xea\x35\x94\x83\x42\xec\xd6\x6a\xb5\x6e\x66\xf4\x46\x9b\xad\x37\x50\x2f\x83\xff\x7b\xa0\xe6\xc1\x14\xb3\x9b\x94\x76\x6e\x40\x4f\x39\x36\xec\xb2\x9b\xd4\xd8\xb9\x84\xf1\x46\xc5\x41\x59\x63\xee\x23\x7e\x2b\x72\x41\x21\xc4\xab\x61\x21\x7a\x84\x10\x33\xa0\x63\xe1\x4f\x18\x5c\x7e\xd8\xc7\x6e\x35\x4c\xe5\x68\x38\x4c\xf6\xcf\xa3\x6c\x84\xa8\xbc\xc4\xc7\xd5\x47\xf3\x3b\x8d\x76\xc1\x71\xd9\x8f\xb1\x60\x4d\xea\x33\xcf\x47\xa8\xff\x8f\x50\xfd\x7b\x8f\x13\xed\x0e\x08\x51\xab\xd5\x6a\x96\xfd\xa7\x1e\xff\x01\xcd\x73\x3b\xf4\xbe\xbd\x53\x23\xba\x0d\xba\x09\xba\x01\xba\x0e\xba\x06\x7a\x13\x74\x15\x74\x05\x74\x11\x74\x01\x74\x1e\xf4\x32\xe8\x45\xd0\x59\xd0\x02\xe8\x24\x8d\x33\x40\xeb\x5d\x8e\x53\xb9\x1c\xa3\x7a\xf3\x7c\x17\xc6\x4f\x72\x66\xb1\x9b\xca\xf1\x5e\x6a\x17\xbf\x08\x7e\x0f\xf8\x3d\xe0\x93\x5d\xb3\xd0\x4b\xfc\x0e\xea\x8f\x79\xa1\x8f\xca\x27\xa9\x9f\x66\x69\x90\xfc\x6a\x96\xbc\xbb\x3c\x87\xf1\x8c\xd0\x78\xcc\xd9\x24\xd5\x17\x53\xd0\x8f\xf1\xcf\xad\x2a\xf3\x92\x29\x96\x64\x7d\x36\xbe\x85\xfe\xcc\xa2\x4c\xf3\x5a\xfd\x79\x9a\xef\x99\x76\xf2\x97\xfc\xdb\xb7\x25\x7f\x26\x20\x44\xbd\x47\xf9\xf8\xf7\xa0\xa7\x00\x39\x5a\x87\xa9\xe2\x45\x59\xce\xc7\x77\x50\xff\x8a\x2c\xbf\x1a\x20\x3d\x19\x73\x42\x96\x47\xdf\x24\xfd\x19\x73\x92\xe8\xf4\x19\x6a\x17\xa4\x76\xa3\xdf\xc4\x7a\x0f\x61\x5d\xe3\xb4\xae\x39\x23\x2b\xe7\x3d\x6a\xfc\x06\xfc\xef\x2d\xda\x17\x86\x21\xf9\x21\xf1\x6d\xe1\xf4\xc3\x7c\xec\x05\x29\xd7\xf9\x06\x95\xab\x15\xa2\x75\x2f\x7e\xa1\x56\xab\x59\xeb\x58\xcd\x12\xbf\xee\xef\xf5\x2d\x3d\x55\x21\xb9\x7c\x8c\xc6\x11\x12\x8b\x34\xce\xd8\x60\xcd\xe9\xdf\xd9\xd8\x38\xe8\xc7\x68\x7f\x02\xf4\x2e\xda\x4d\xa2\x7e\x17\xfe\x41\xfe\x60\xd9\xeb\x7c\xc4\xdd\xaf\x71\xf4\xab\xcd\xd1\x1f\xf3\x7c\x4f\x53\xb9\x8f\xb5\x72\xbd\x4d\xe5\x4e\x38\xe6\xc1\x96\xeb\x6b\x2a\x77\x57\x2b\x47\xfe\xd9\xf9\x98\xbb\xfd\x24\xda\x47\x34\xf3\x6d\x9e\x27\x7f\x36\xaf\xd1\x7c\xe9\xec\xed\x6a\xc6\x97\x59\xc6\xfc\x8f\xd0\x7a\x64\xae\xd1\x3a\x64\x87\x06\xc8\x1f\x97\xb0\x1e\x71\x5a\xb7\xa9\xca\x5d\xac\xcf\x10\xb5\xbf\x4e\xeb\x92\x3d\xf9\x8c\xa4\xd1\xb6\xbc\xe2\x87\x33\xa0\xd1\x20\xf9\xe9\x8b\x32\x3e\x09\x11\x0d\x9c\xa2\xb2\x81\xb2\x41\x7e\x6e\x56\x92\xca\xba\xdb\xf1\x70\x56\x89\x13\xce\x71\x15\x30\xae\x2e\x8c\xab\x8b\xc5\xe5\x3e\x76\x0e\x4d\x6a\xe2\x74\x48\xbc\x20\x69\xd4\x78\x52\xc6\xd9\xa8\xf1\x59\x39\x3f\xf5\x7d\x11\x92\xf5\x14\x0f\xac\xfe\x64\xe1\xa7\x65\xf8\x6f\xe7\x97\xbc\xfd\xd0\x7f\xbd\xc6\x3d\xd7\xeb\x84\x66\xbd\x5e\x15\x98\x57\xd0\xfa\x38\xfe\xd7\x11\xef\x5f\xee\x4a\x34\xfa\x69\xc8\xfe\xad\x61\xff\xf5\xb1\xfe\xd3\x3a\x9b\x15\x8a\xab\x3a\x7f\x73\xee\x07\xde\xff\x4c\x05\x7e\x12\xdb\x82\xfe\x9f\x55\xf4\x5b\xfb\xb7\x73\x9f\x5b\xef\x5d\xdf\xb8\x61\xf9\xd7\x6d\xe8\x3d\xc4\xfa\x8d\x38\x50\xe9\xf1\xec\xf7\xae\x6f\xbf\xe1\xaf\xb1\x6d\xe8\xdf\xcf\xfa\x7d\x8a\xf4\xfe\x9a\x5b\xef\x29\xdf\x7e\x9f\x42\xbf\xbf\x07\xbd\x01\x59\x9f\xa9\x9c\x80\xbd\x4d\x17\x4e\x69\xc5\x2f\x9b\xe1\xa3\x1f\x1b\x2e\xeb\x7e\xb0\xb8\xac\x0a\x3f\x89\xee\x23\xbc\xd2\x2a\x2e\x33\x4f\x09\x57\xfb\xd6\x70\xd8\x07\x34\x8e\x06\x0e\xfb\x3e\x95\x11\x7f\x6e\x04\x30\x8e\x38\xe6\xb3\x88\x76\x81\x97\x08\x87\x05\x6e\x13\x0e\x2b\x02\x87\x01\x7f\xbd\x87\x7d\xdc\x6d\x30\x1c\xf6\xc8\xbf\x0b\x75\x7e\x70\x2e\xc7\x80\xb7\xb0\x4f\xcb\x31\xe0\x8d\x18\xf0\x46\x0c\xf8\x24\x06\xbc\x15\x03\xde\x8a\x01\x6f\xc5\x80\xb7\x62\xc0\x5b\x2c\x4e\x5a\x71\xb4\x1c\x9b\x50\xe2\x55\x39\x96\xa2\x71\x06\x81\xc3\x86\x52\xc0\x09\xe3\x18\x2f\xe1\x30\x73\x1a\xf8\x6b\x08\x7a\xe2\x13\xc0\xa5\x74\x9e\x9a\x25\xe0\xad\x11\xd8\x1d\x02\x8e\x9b\xee\x43\xfd\x20\xea\xd1\xcf\x21\xe0\xb7\x69\xc4\xbf\x52\x12\xf5\x18\xd7\x10\x70\xdb\x34\xf0\xd7\xd0\xa2\x32\x0f\x99\x12\x70\xd7\xc8\xfb\xc0\x73\xc0\x5d\x23\x34\x8f\xd5\x67\x69\x7e\x67\x42\xc0\x5d\x27\xbf\x4b\xb8\xab\x0d\xb8\x6b\xe4\x1f\xa1\x07\xb8\x6b\x84\xe6\x7d\xaa\x04\xdc\x35\xb2\x81\x7a\xe0\xa9\x36\xe0\xae\x0b\x74\x7e\x8d\x9e\xc0\xfa\x8d\xdc\x44\x3b\xc2\x63\x99\x0b\xc0\x69\xb0\x3b\x8a\x7e\x94\x4f\x5a\xeb\x08\xfc\x1a\xa3\xb8\x35\x16\xb8\x2a\xea\x2e\x5f\x7d\x87\xda\x85\xc3\x42\xac\xd6\x6a\xb5\xce\xa3\x54\x76\xc6\x9d\x1e\xc7\xf9\xe6\x3a\x47\x10\xbf\xcb\x07\x23\xf0\x5f\xe0\xe1\x83\xd0\xe3\xb3\xef\x53\xda\x73\xf0\x77\x68\x1c\x11\x9c\x33\xa0\x63\x91\x37\x98\xff\xb6\xe6\x5f\xd6\x78\xcb\xb1\x3b\xa0\xc8\x3f\x10\x7f\xf3\xb1\x8f\x40\x77\xc1\xdf\x54\xf0\xa0\x79\x9e\xfc\x80\xe3\xa8\x7a\xff\xbb\x3c\xe6\x29\xa2\x9c\xb3\xde\xf2\xdd\x4c\xfe\xce\x1e\xe4\x9d\x72\x3b\x7b\xb4\x1b\x61\xf2\xdb\x5a\xf9\xe6\xb8\xf3\xa3\x7b\xc4\x9d\xbb\x7b\xc4\x9d\x9b\x2d\xe1\x98\x4d\x4f\x1c\xa3\xc5\xd5\x7f\x0c\xbf\x78\x9b\xfc\xc4\x5c\x81\x7f\xcc\x21\xfe\xbc\x03\x3f\x79\x1d\xf1\xe6\x8f\x90\xaf\x9e\x9e\x04\x2e\x85\xdf\xc4\x0b\xc0\xa5\xbb\xf0\xa3\x22\xc3\xb1\x25\x8a\x0b\x5f\xa3\xfe\x58\x79\x51\x34\xf8\x8b\xca\x3c\x8d\x36\xf2\x6c\x4a\xdc\x6c\x9c\xfa\x24\x95\x1b\x38\xf5\xe7\x64\x99\xe7\xe9\x7c\x7f\xdb\x38\xb6\xc7\x85\x57\x7b\x35\x78\x75\xac\x3d\x24\xeb\xf9\xbe\xa3\xfd\x69\x9f\x23\x9f\xec\xa6\x83\x72\x2c\xfc\x30\xb5\xdf\x87\xf6\xfb\xf4\xed\x5f\x7e\x8c\x0e\x3c\x67\x1c\x48\xb1\x38\xd0\xa3\x8d\x03\xfb\xee\x49\x6e\xaf\x78\xa5\x4e\x23\x12\x3f\x0c\x33\xfc\x40\xfe\x64\xbe\x4a\x71\xd7\x9c\x2c\xb8\xfa\xb3\xe9\x77\xce\xe3\xbe\x23\xda\xfe\x9c\x6c\xe1\xbe\xbf\xf9\xa2\xbc\x0d\x33\xaf\x50\xbb\x31\xe3\xb8\x11\x54\xec\x27\xe1\x4f\xab\x7b\xc2\x31\x51\xe0\x3e\x13\xf5\x51\x63\xbf\x78\x30\x7a\x83\x58\x17\xc1\xf4\x5f\x92\x35\x21\x11\xa7\x7b\x24\x83\xce\x53\xcb\xdf\x75\xfb\x71\x55\xb3\xff\xa7\x2a\xd4\x9f\x31\xe3\xfb\xb5\x80\x82\xb7\x55\xdc\x91\x45\xbf\xb3\x88\xe7\xf9\x46\x1c\xff\xb8\xe6\x1c\x5f\x16\x71\xde\xbc\xd2\xdd\x72\x7f\x94\xf8\x70\xa5\xa7\xa9\xdc\x1d\xad\x5c\x6f\x53\xb9\x6d\x5d\xfc\xbb\xd2\xd7\x54\xee\x63\xad\x1c\xe2\x66\xb7\xbb\x7d\xd2\x19\x37\xbf\x66\xaf\x27\xc9\x59\x71\x33\xe9\x19\x37\x77\xb4\xf9\x3a\xe6\x1f\x78\x29\x73\xed\x0e\xe2\xdc\x55\xc4\x45\xac\x47\x7c\x11\x71\xd1\xba\x57\x59\xa2\xf6\xd7\x69\x5d\xb2\x27\x97\x25\x8d\xb6\xfd\xa7\xb4\xe7\xce\xd7\xb7\x25\xdf\x8e\x83\x84\x5f\xed\x38\xb8\x45\xfd\x75\xf8\xef\x82\xaf\xff\xfe\x8b\x2c\xdb\xfb\x40\x8f\x77\x75\x7e\x21\xcf\xe9\xa0\x3a\x7f\x97\xb0\x17\xac\xbc\xc3\xbc\x46\xf1\x83\x8f\xc3\xc2\xb5\x56\x3e\x6c\xdd\x37\x65\x2a\x7f\x01\x3f\x7d\x09\x65\xcb\xbf\x0b\x28\x5f\x45\xb9\x84\x32\xcd\x67\xf5\x00\xf5\x63\x0b\xf1\x3b\x1f\x27\xdc\x3b\x63\x50\x79\x0b\x34\x1f\x7b\x1d\x72\xcb\xd0\xf3\x55\x9c\x0b\x6b\x0a\x6e\x32\x2b\x37\x15\xfc\x54\x5d\xc6\xf8\xdb\xc8\x7f\xaa\x19\x2a\x77\x07\xd4\x79\xbd\x11\x12\x62\x10\xf3\x70\xa8\x85\x75\x08\x89\xeb\xe4\x6f\xf7\x1d\x1f\xbe\x25\x3a\xee\x29\x8f\x49\xb2\xfc\x45\xc5\x83\x6e\x1c\xb8\xad\xe2\xc0\x2b\x29\x6d\xbf\x75\x38\x30\xa9\xc3\x53\x3e\xf2\x1c\x07\x2e\xec\x41\xbe\x29\x7e\xf4\xb1\xcb\x71\xa0\x16\x47\xb6\x10\xcf\xb4\x38\xb0\x85\x78\xa6\xc5\x81\x3e\xf1\x6c\xbb\xa5\x78\xb6\xbd\x37\x1c\xd8\xc0\x49\xe4\x27\xe6\x75\xf8\xc7\x49\xf2\x9f\xd1\xa8\x80\x5e\xf8\xcb\x10\xf9\x97\xb9\x0c\x7c\x88\xbc\xcf\xc6\x83\x1b\x0c\x0f\xfe\x33\xed\xc3\x45\xe0\xc1\x8e\x5b\x14\xf7\x42\x5f\x94\x7a\x47\x07\x48\x7f\xb4\xed\xb8\xa4\x76\xbc\xa3\xf1\xd8\xf1\xee\x97\x69\x3c\x8e\x7d\xb6\xea\x1b\xef\x68\x1e\xed\x7d\xa2\xcf\xe3\x75\x7e\xf7\xc3\x89\x77\x57\x95\x78\x67\x62\x3f\x9b\x4b\xd8\xa7\x71\xf5\xde\xc0\x8a\x53\xe6\x12\xf6\x75\x5c\xbd\x67\x30\x2b\x1b\x1e\xf1\x90\xf2\x77\x8a\x57\x36\x0e\xad\x3e\x4a\x34\x4d\xd7\x84\x32\x1f\x97\xf1\x12\x34\x3f\xf2\x66\x23\x8e\xf6\xc8\x7e\xbe\x05\x3b\x2b\x2c\x5e\x2e\xde\x73\xbc\x4c\x79\xc4\x4b\xaf\x75\x0c\xfa\xe0\x57\x8e\x53\xed\x7b\xb0\xc1\x46\x59\xee\x13\x4a\xcb\x85\x39\xb5\x47\xfc\xda\xb8\xa7\x2a\x29\xdf\x0b\xc7\x8c\xa2\xc4\xa9\xe5\xd3\x94\x77\x54\xf1\x5d\xe6\x06\xec\x94\xe7\x68\xbd\xb2\x73\xe4\xe7\x56\x5e\x57\x45\xde\xa3\xdb\x97\xeb\xda\xfc\xd3\xda\xcf\xeb\x9e\xfb\xf9\x96\x66\x3f\x97\xe7\xc8\x2f\xf3\x73\x8b\x2e\x7c\xeb\x77\x2f\xd7\x1c\x37\x43\x6f\x6c\xaf\x7a\xbd\x70\xf3\x0b\xc0\xcd\x49\x15\x37\xfb\xcc\xd3\xa2\xf6\x5c\x5c\xf4\xc0\xcd\xea\x7e\xcf\xe2\xbe\xce\x1b\x37\x0f\xab\xb8\xd9\xfa\xce\xe5\xd3\x9f\x79\xbf\xef\x5c\x3e\x72\x5a\xdc\x6c\xdd\x37\xf8\xc8\x69\x71\xb3\x75\xdf\xe0\x23\xa7\xc5\xcd\xd6\x7d\xc3\x21\x77\xfb\x61\xe7\x39\xf3\x4d\x7b\x3d\x55\xbf\x1c\xde\x23\x6e\xc6\xfc\xe3\x3b\xaf\x8d\x9b\x97\x19\x6e\x5e\x61\xb8\xf9\x4f\x18\x6e\x7e\x17\xb8\x99\x36\xa8\x1b\x37\x53\x02\x6c\x9f\x23\xe4\xd7\xd6\x39\x32\x66\xdc\xa2\xfe\x3a\xfc\xb7\xee\x57\x21\xf1\xf7\xe2\xc1\xf8\xe1\x7f\x33\x7c\xd6\xea\xbd\xf2\x30\xe8\xfc\xbd\xe1\x33\xeb\xbe\x8b\xf5\x5b\x87\xcf\x86\xfd\xee\xcb\x34\xf2\x1c\x9f\xcd\xef\x41\xbe\xe5\xfb\x3d\x8d\xdd\x96\xf0\x59\x0b\xfb\xc6\xf7\x9e\xce\x47\xce\xf7\x9e\x4e\xb3\x6f\xb6\x5b\xda\x37\x7b\xc4\x67\xcb\xf0\x0b\xeb\x7d\xc4\x35\xf8\xc7\xd0\x0a\xf0\x01\xfc\x24\x0e\x3c\x51\xd9\x51\xfc\x6d\x6a\x11\x7e\xd3\x81\x7b\x76\x7c\x2f\xce\x9f\xfc\x0e\xed\xab\x77\x80\xcb\x5e\xa7\xfb\xfc\xea\x31\xea\xcf\xe8\x73\x44\xa3\x61\xba\xff\xa9\xe2\x3e\x7b\xf4\x49\x8b\x9f\x93\xf4\x45\xa0\x8c\xa8\xa0\x8b\xbc\x17\x43\x28\x87\x08\x08\x58\x71\x7f\xac\x0d\xf7\x6b\x6c\xbf\x76\xcb\xed\xea\xb8\x5f\xfb\x02\xee\xd7\x02\xb8\x07\x07\x1e\xb1\x70\x09\xc7\x35\x2f\x7f\xea\xb7\x1a\xf3\x1c\x72\xdc\x63\xf1\x7b\xb9\xf2\x69\xfb\xfb\x58\x50\xee\x1b\xdc\x7b\x56\x06\x19\xee\x39\xd1\x68\x27\x34\xf7\xea\x99\xca\xbb\xd8\x77\x93\x28\xff\x35\xca\x67\x14\xdc\xe6\xc6\x65\x84\xeb\xba\xc3\x6a\xff\xad\x76\x69\x7c\xdf\x9a\x41\x7b\x5b\xae\xc8\xfa\x57\x72\xe1\xd6\x71\xcd\x7d\xa6\x59\x41\x1e\xbd\x04\x3c\x89\x77\x09\x55\xe0\xed\x19\x7c\x57\xa9\xd2\x36\x70\x7d\xd7\xae\x02\xf7\x47\x05\xce\x41\xab\xdc\x46\x00\xac\x4a\x9f\xa7\x1a\xeb\x6f\xb7\x3f\xa0\xd4\xa7\x0b\x42\x95\x97\x28\x4d\xc5\x8d\xf5\x78\x64\x56\xfa\x1c\xb8\xd5\xfe\x59\xf7\xc3\x3c\xdf\xb6\xc6\xe7\x39\xae\x03\xaa\xdd\xec\x90\x75\xfe\x10\xae\xdd\x0a\x61\x7e\xf1\x2e\xc9\x7b\xfe\xdf\x66\xf3\x7f\xd5\x85\x7f\xe6\x7d\xf0\x6b\x48\xe0\x9e\x9b\x9d\x37\xde\xed\x9f\x68\x94\x7f\x34\xfe\xbc\xc8\xfc\x79\x59\xf1\xe7\x0c\xf0\xbf\x97\x3f\xbb\xef\x5d\x8a\x6c\x9f\xb4\xe6\xaf\xf7\xeb\x0f\x3c\x4f\xf8\x51\xcd\x9f\x95\x0f\x99\x4b\x38\xcf\xe3\x05\x96\x2f\xf1\x3c\x4f\xfd\x4e\xec\x1d\x2f\x2e\x3b\xc6\xef\x88\x17\x38\x37\xd2\xf8\xde\x3d\x83\xf3\x7d\x0b\x34\x3f\x34\xc7\xfa\xff\xf5\x1f\xda\xfc\xa7\xe4\x1c\xff\x93\x32\x1f\xf6\x77\x7b\xbc\x13\x39\xa4\xbe\x53\xb0\xde\x19\xf0\xfc\x2c\xda\x3e\xe0\x7a\xcf\xa9\x7b\x17\xe1\xce\xcf\x9e\x62\xf9\xd9\x2f\x50\x7e\x36\x87\x3c\x1c\xfa\xf3\x73\x78\xd7\x32\xf7\x21\xf0\x52\xf3\xf3\xff\xc3\x3d\xe0\x86\x30\xbe\xe3\x37\x7b\x5f\x56\x9e\x03\x8e\x9d\xc3\xbb\x86\x16\xf2\x43\x3d\xee\xb1\xf0\xc4\x8e\x27\x9e\xd0\xe5\x19\xe5\xb9\x05\xcc\xc3\x84\x2b\x8e\xf9\xdf\x1f\x37\xcb\x0f\xa1\x37\xb6\x57\xbd\x5e\xf9\xe1\x28\xe2\xe1\xff\x80\xdf\x1c\x97\x4f\xd4\xc7\x1b\xc1\x77\x2f\x17\x3e\x9f\x00\x3e\xff\xaf\x5a\x40\x89\x0f\x78\x97\x5a\x21\x7f\xe1\x78\xc3\xfe\x8e\x8e\x38\x89\xf7\xaa\x76\x9e\x89\x7c\x3f\xf6\x3e\xe8\x1a\xa8\x85\x0b\x6e\x82\x5a\xf7\xdd\xd6\xf7\x9b\x77\x11\x27\x91\x07\xc5\xf0\x4e\x02\xf1\x29\x7b\xfa\x5d\xf8\x47\xf3\x3c\x74\xcd\x27\x0f\xd5\xe1\xd4\xf7\x9d\xef\xb3\x18\x4e\xb5\xdf\x7f\xe1\x5e\xaf\x42\xfb\xc5\x8e\xef\xff\xe0\x8a\x27\xab\x5a\xfc\xa1\xc6\x35\xeb\xfd\xec\x0c\x68\x34\xf0\x57\x92\xef\x8c\x2f\xf5\x29\x7d\xea\x00\xbd\x7f\xcd\x54\xd6\x15\x79\x3b\x9f\x7b\x4f\xe8\xd6\x89\xe2\x8e\x21\x9e\x3a\xf0\xa7\x34\x5e\x47\x3c\x5b\x90\xf1\x6c\x5c\x1b\xcf\xcc\x6b\x88\x13\x38\x4f\x42\x62\xe9\x01\xfb\xdb\x1f\xc8\x7c\xf0\xc1\xf9\x9b\x95\xf7\x6d\x81\x5a\xef\x35\x6e\x81\x6e\x28\xfe\xf4\xe0\xfc\xf3\xb6\x87\x7f\x36\xcf\xfb\x36\xee\x33\xef\xdb\xdc\xa3\x3c\xcf\x77\xd7\x7c\xe4\xad\xfd\x11\x6e\x77\xe7\xb9\xeb\x3e\xf9\x9c\xbd\x4f\xb6\x3d\xf6\xc9\x7f\xb4\xb8\x4f\xd6\x81\x0f\x68\x5d\xc6\x02\xf8\xee\x8f\xf1\x34\xcf\x97\xda\xe1\xc7\xf8\x5e\xbf\x4c\xeb\x3f\xd6\x46\x0f\x99\xaa\x47\xa0\x07\xef\xa2\xac\x77\x59\x14\x55\x1c\x79\x54\xa8\xaf\x31\x3e\xf2\x53\xbc\xfb\x78\x07\xfe\xf8\xba\xfd\x1e\x38\xe0\xf8\x4e\x97\x3d\x5d\x62\xf8\x48\xc5\x37\x99\x8a\xe5\x87\x97\x51\xb6\xfc\xf6\xeb\x28\x5b\xf7\x70\xf3\x0a\x9e\xcc\xc7\xde\x64\xfe\xf7\x96\x6b\x3e\x67\xb5\xf3\x79\xb9\x49\xdc\xa1\x04\xd6\x1d\x77\xe8\x62\x3c\x53\x99\xf7\x88\x3b\x14\x4f\xbd\xe3\xce\x4f\xd1\x7c\x3b\xe2\xce\x84\x4f\xdc\xa9\xe2\xbd\x8b\x1d\x77\x68\xc1\x47\x3f\x45\xfc\xa8\x41\x1d\x18\xfd\x02\xca\xc1\x2e\xe1\x9c\x2f\x77\xff\x1e\x6e\xd2\xbf\x88\xab\x7f\xad\xc6\xc5\x94\x0f\xce\x6e\x73\xfc\x11\x6d\xde\x3c\x03\x78\x2f\xd2\x02\xaf\xcb\xf2\x4f\x07\xaf\x57\xc3\xab\xcb\x5d\x76\xfc\x3d\xaa\xe7\x52\xcf\x8b\xff\x73\xbc\xf9\xd4\xfd\x0a\x12\x6e\x84\x44\x61\x9f\xca\xdf\x0e\x10\x3f\x15\x56\xf9\x5f\x05\x3f\x12\x51\xf9\x9f\x03\x7f\x36\xa8\xf2\x3f\x30\x88\xbf\xca\xf4\xdc\x02\x7f\x92\xe9\xf9\x1b\xf0\xe7\x59\x7f\x26\xd0\xcf\x35\xd6\xbe\x0f\xfc\x0d\xc6\x17\x16\x9f\xf5\xe7\xbb\xd0\x2f\xda\x55\xfe\x75\xf0\xbb\x18\x7f\x51\xca\xb7\x8b\x6d\xa6\xe7\xb6\x41\xfc\x8b\x6c\x5c\x7f\x09\x3e\x1f\xef\x3c\xf4\xec\x30\xfe\xdf\xa1\x7d\x37\xeb\xff\x1f\x82\xdf\xcb\xf8\xdd\x52\xcf\x43\xf8\x4a\x60\xff\x36\x03\xc4\x1f\x67\xfc\x12\xf8\x17\x43\x2a\xbf\x17\x7a\x56\x3a\x54\xfe\x2e\xda\xaf\x32\xfe\x18\xf8\xbb\x2a\x5b\x0c\x82\x3f\xc1\xec\x2e\x48\xfd\xfb\x45\xb2\x4d\xe5\x4f\x82\xbf\xc0\xf4\x0f\x83\xbf\xc3\xf8\x5d\xe0\xaf\x31\xfd\x1b\x01\xe2\x6f\x30\xfe\x19\xf0\x27\x98\xdd\xcb\xd0\x73\x93\xe9\x1f\xb7\xf8\x6c\x5d\xee\x40\x0f\x5f\xaf\x57\xc0\xe7\xeb\x75\x11\x7a\x06\x99\xfe\x14\xf8\xbd\x0f\xab\xfc\x1e\xf0\xbb\x18\x7f\xc7\xd2\xcf\xf8\x7f\x0b\x7e\x81\x8d\xf7\x57\xc1\xdf\x64\xfc\x41\xa9\xbf\x53\x24\x59\x1c\x8b\x80\x3f\xce\xf8\xeb\x01\xe2\x6f\xb0\x79\xdb\x32\x88\xcf\xfd\xfc\xcf\xc0\x5f\x67\xfc\x97\xa0\x27\xc9\xf6\xd1\x2c\xec\x6e\x33\x7e\x12\xfc\x1d\xc6\x7f\x0e\x7a\x76\xd9\xb8\x12\xe0\x4f\xb0\xfe\x5f\x92\xe7\x64\xb7\xe0\xbf\x27\x24\xff\x90\x8b\xff\x2d\x79\x4e\x3e\xe2\xe2\xef\x97\xfc\x47\x5d\xfc\x5f\x97\x7a\xf6\xbb\xf8\x9f\x96\xfc\x87\x5c\xfc\xef\xc8\xb8\x1d\x74\xf1\x4f\x4a\x7e\xd8\xc5\x0f\x4b\x7e\xa7\x8b\xbf\x22\xf9\x21\x17\x7f\x58\xf2\xdb\x5d\xfc\xdf\x95\xfd\xff\x09\x17\xff\x07\xb2\x9f\x07\x5c\xfc\xa8\xe4\x1f\x74\xf1\xbf\x2d\xf5\x44\x5d\xfc\xc7\x25\xff\x31\x17\x3f\x09\x5a\x5f\xae\x3a\xd2\x1a\x64\xe5\x02\x2b\xaf\x3a\xca\x9f\xaf\xef\xc3\x7d\x76\xf9\x78\x7d\xff\x45\xd4\x7a\xa7\xfe\x63\x4c\xff\x31\xa6\xbf\x5e\x5e\x64\xfa\xd7\x83\x6a\x79\x23\xac\xda\x8b\x38\xec\xd5\x21\x46\x8a\xcb\xb3\x72\x8f\xa1\x96\xb7\x83\xaa\xbe\xc1\x90\x5d\xfe\x5c\x3d\xee\x85\xd4\xfa\x0d\x66\x6f\xb2\xc3\x2e\xd7\xd7\x76\xa1\xc3\xbf\x3f\xc3\xcc\xfe\x02\xef\x4f\xbb\x6a\xdf\xa9\xaf\x6e\x7f\x9d\xe9\xbf\xf3\x90\xda\xbe\xb0\x5f\xed\xcf\x38\x9f\x0f\x66\xaf\x27\xa0\x96\x57\xda\x54\x7d\x3d\xac\x3f\x6b\xed\xaa\x7e\xf1\x74\x29\x37\x5b\x12\xf9\x62\xae\x54\x28\x9e\xfb\x72\x2e\x9d\x9e\x3a\x9b\x2b\xa5\xb3\xd3\xf9\x74\x26\x9b\xcd\x15\x4a\xe2\xe9\x62\xee\x4c\xa3\xfa\xd3\xbc\xd6\x21\x58\xca\x16\xd2\xaf\x1d\x4d\x67\xcf\x9d\x3d\x9b\xcb\x96\x44\x5e\xcf\x56\xd5\xe9\x2a\xb5\x35\xdc\xce\x80\xde\xce\x80\x9f\x9d\x01\x4f\x3b\x76\xcd\x57\x32\x85\xe9\x3a\xaf\x54\xcc\x64\x73\xc5\xf4\x74\x29\x53\xba\x30\x2d\xd2\xaf\xe5\x8a\xd3\x53\xe7\xce\x2a\xc6\xa6\x73\x25\x59\x9f\xe3\xea\xec\x0a\x67\xf3\xec\x99\x73\xd3\xae\xa6\xc4\x4c\x9f\x99\xca\xe6\xce\xd6\x6b\xa7\x4b\xc5\x52\xe6\xcb\xe2\xe9\x69\xf3\x2b\x75\xfa\xfc\xf1\xe3\x87\xd3\x9f\xa9\x93\x44\xba\x5f\xd2\xa3\xe9\xc4\x67\x88\x9d\x00\xdf\x2a\x0f\xa2\x19\x68\x62\x10\xcd\x8f\xa1\xf9\x31\xf0\x8f\x35\xc6\x98\xce\xbd\x96\x3b\x5b\x4a\x4f\x15\x5e\x3b\x4a\x3c\x4c\xc2\xf4\xb9\x6c\xde\xc1\x2d\x5d\x28\x9c\xc9\x15\xa6\x5e\x21\x96\x54\x2a\xc9\x00\x91\x44\x3a\x01\xee\x91\x3a\x39\x42\x64\x80\xc8\xd1\x74\x3f\xb8\x16\x4d\xa0\x9a\x68\xa2\x4e\xdd\xfd\x19\xd0\xf6\x67\xc0\xdd\x9f\x01\x52\x3a\x80\xb1\xa2\x48\x74\x00\x34\xd1\xe0\x1f\x3e\x8c\xbe\x1c\xa6\x7a\xa2\x09\xd0\xa3\xe9\x04\xea\x13\xa8\xb7\xca\x87\xfb\xd1\xbe\x1f\xed\xfb\xd1\xbe\x1f\xed\x51\x3e\x9c\x40\x7b\xd0\xfe\x04\xda\xa3\x9c\x40\x99\xe8\xd1\xf4\xe1\x3e\xb4\x07\xed\xef\xa3\xb5\xea\x47\x39\x81\x72\xa2\x4f\xdc\xef\xef\x1b\xf8\xbe\xc0\x7f\x5d\xf4\x9c\x4d\xac\xb0\x4a\x76\xfc\x37\xfe\x9d\x08\x96\x1e\xe0\xdf\x86\x70\xff\x18\x9c\x11\x1f\x35\x91\x9f\x65\x7c\x9e\x56\xdc\x15\xae\xd4\x41\xfe\x36\x7e\x89\x28\x3e\xf3\x89\x18\x52\x10\x4b\xde\xe2\xff\x9b\x87\xfd\x9b\xa0\x3d\xed\xfe\xf6\xff\xd5\xc3\xfe\x36\xec\xa7\x1c\xf6\x43\x1a\xfb\x6f\x7a\xd8\xdf\x84\xd2\x66\xe3\xff\x86\x87\xfd\xbe\x67\x54\x3b\x31\x60\x1a\x6e\xff\x82\x87\xfd\x14\xce\xa3\xc1\x88\xbf\xfd\xf3\x1e\xf6\x87\x61\x7f\xc2\x61\xbf\x5d\x63\xff\x57\x0c\xbd\xfd\xcb\x80\x46\x6b\x1d\xfe\xf6\x9f\x35\xf4\xf6\x17\x61\x7f\xde\x61\xff\x21\x8d\xfd\x92\x87\xfd\xe4\x27\x89\x2e\xec\xf7\xb7\x5f\xf0\xb0\xdf\xf7\x59\xa2\x17\x1d\xf6\xf7\x6b\xec\x3f\xe1\x31\xff\xdb\x71\xa2\xbb\x4d\xfc\xef\x67\x3c\xe6\x7f\x15\xf6\x9d\xf3\xdf\xa9\xb1\xff\xdb\x01\xb2\xcf\x63\xc0\x26\xbe\x57\x73\xe4\xcd\xf7\xef\x87\x86\x5e\xfe\x83\x16\xe5\x17\x3c\xec\x8b\x23\xad\xc9\x47\x3c\xe4\x1f\x6d\x51\xfe\xcf\x3d\xe4\x7b\x5b\x94\xff\x69\x0f\xf9\x67\x5a\x94\xef\xf2\x98\xbf\x54\x8b\xf2\x6f\x78\xc8\xbf\x72\x44\xdf\x9e\xc7\xef\x27\x3d\xe4\x27\x3d\xe4\x79\xf9\xf7\x71\xdf\xca\x7f\x05\xc8\x4f\x38\xf2\x88\x01\x87\xff\x59\x99\xe1\xff\x07\x00\x00\xff\xff\xf7\x13\xcc\x25\x78\x48\x00\x00")

func tcptracerEbpfOBytes() ([]byte, error) {
	return bindataRead(
		_tcptracerEbpfO,
		"tcptracer-ebpf.o",
	)
}

func tcptracerEbpfO() (*asset, error) {
	bytes, err := tcptracerEbpfOBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "tcptracer-ebpf.o", size: 18552, mode: os.FileMode(420), modTime: time.Unix(1, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
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
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
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
	"tcptracer-ebpf.o": tcptracerEbpfO,
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
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
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
	"tcptracer-ebpf.o": &bintree{tcptracerEbpfO, map[string]*bintree{}},
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
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}
