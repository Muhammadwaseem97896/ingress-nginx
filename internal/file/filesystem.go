package file

import (
	"os"
	"path/filepath"

	"github.com/golang/glog"

	"k8s.io/kubernetes/pkg/util/filesystem"
)

// Filesystem is an interface that we can use to mock various filesystem operations
type Filesystem interface {
	filesystem.Filesystem
}

// NewLocalFS implements Filesystem using same-named functions from "os" and "io/ioutil".
func NewLocalFS() (Filesystem, error) {
	fs := filesystem.DefaultFs{}

	err := initialize(false, fs)
	if err != nil {
		return nil, err
	}

	return fs, nil
}

// NewFakeFS creates an in-memory filesytem with all the required
// paths used by the ingress controller.
// This allows running test without polluting the local machine.
func NewFakeFS() (Filesystem, error) {
	fs := filesystem.NewFakeFs()

	err := initialize(true, fs)
	if err != nil {
		return nil, err
	}

	return fs, nil
}

// initialize creates the required directory structure and when
// runs as virtual filesystem it copies the local files to it
func initialize(isVirtual bool, fs Filesystem) error {
	for _, directory := range directories {
		err := fs.MkdirAll(directory, 0655)
		if err != nil {
			return err
		}
	}

	if !isVirtual {
		return nil
	}

	for _, file := range files {
		f, err := fs.Create(file)
		if err != nil {
			return err
		}

		_, err = f.Write([]byte(""))
		if err != nil {
			return err
		}

		err = f.Close()
		if err != nil {
			return err
		}
	}

	err := fs.MkdirAll("/proc", 0655)
	if err != nil {
		return err
	}

	glog.Info("Restoring generated (go-bindata) assets in virtual filesystem...")
	for _, assetName := range AssetNames() {
		err := restoreAsset("/", assetName, fs)
		if err != nil {
			return err
		}
	}

	return nil
}

// restoreAsset restores an asset under the given directory
func restoreAsset(dir, name string, fs Filesystem) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = fs.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}

	f, err := fs.Create(_filePath(dir, name))
	if err != nil {
		return err
	}

	_, err = f.Write(data)
	if err != nil {
		return err
	}

	err = f.Close()
	if err != nil {
		return err
	}

	//Missing info.Mode()

	err = fs.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

// restoreAssets restores an asset under the given directory recursively
func restoreAssets(dir, name string, fs Filesystem) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return restoreAsset(dir, name, fs)
	}
	// Dir
	for _, child := range children {
		err = restoreAssets(dir, filepath.Join(name, child), fs)
		if err != nil {
			return err
		}
	}
	return nil
}
