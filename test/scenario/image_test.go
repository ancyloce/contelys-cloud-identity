//go:build scenario

package scenario

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"path"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/moby/moby/client"
)

// The image holds Identity's binary and nothing else, no shell and no certificate bundle, and runs
// it under a numeric user that is not root (Identity ADR 0009).
func TestTheImageHoldsIdentityAloneUnderAUserThatIsNotRoot(t *testing.T) {
	docker, err := client.New(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatal(err)
	}
	defer docker.Close()
	ctx := context.Background()

	inspected, err := docker.ImageInspect(ctx, image)
	if err != nil {
		t.Fatal(err)
	}
	user, _, _ := strings.Cut(inspected.Config.User, ":")
	if uid, err := strconv.Atoi(user); err != nil || uid == 0 {
		t.Errorf("the image runs as user %q, want a numeric user that is not root", inspected.Config.User)
	}

	saved, err := docker.ImageSave(ctx, []string{image})
	if err != nil {
		t.Fatal(err)
	}
	defer saved.Close()
	if files := imageFiles(t, saved); !slices.Equal(files, []string{"identity"}) {
		t.Errorf("the image holds %v, want identity alone", files)
	}
}

// imageFiles lists every file of every layer of the image that saved holds, as docker save writes
// it, without the directories.
func imageFiles(t *testing.T, saved io.Reader) []string {
	t.Helper()
	entries := map[string][]byte{}
	archive := tar.NewReader(saved)
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(archive)
		if err != nil {
			t.Fatal(err)
		}
		entries[header.Name] = content
	}
	var manifest []struct {
		Layers []string `json:"Layers"`
	}
	if err := json.Unmarshal(entries["manifest.json"], &manifest); err != nil || len(manifest) != 1 {
		t.Fatalf("the saved image's manifest.json: %v, %d images", err, len(manifest))
	}
	var files []string
	for _, name := range manifest[0].Layers {
		layer, ok := entries[name]
		if !ok {
			t.Fatalf("the saved image lacks its layer %s", name)
		}
		var reader io.Reader = bytes.NewReader(layer)
		if bytes.HasPrefix(layer, []byte{0x1f, 0x8b}) {
			unzipped, err := gzip.NewReader(reader)
			if err != nil {
				t.Fatal(err)
			}
			reader = unzipped
		}
		contents := tar.NewReader(reader)
		for {
			header, err := contents.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("layer %s: %v", name, err)
			}
			if header.Typeflag != tar.TypeDir {
				files = append(files, path.Clean(strings.TrimPrefix(header.Name, "/")))
			}
		}
	}
	slices.Sort(files)
	return files
}
