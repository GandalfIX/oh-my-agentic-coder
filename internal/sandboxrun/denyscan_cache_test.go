package sandboxrun

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// cacheTree builds a fixed shape the tests below reason about:
// root/{sub1,sub2}/{deep,a}/file and root/sub1/deep/.env. Four
// directories: root, sub1, sub2 and one deep per sub.
func cacheTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, sub := range []string{"sub1", "sub2"} {
		for _, leaf := range []string{"deep", "a"} {
			p := filepath.Join(root, sub, leaf)
			if err := os.MkdirAll(p, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(p, "file"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(root, "sub1", "deep", ".env"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func cacheWalk(t *testing.T, root string, cache *denyScanCache) []string {
	t.Helper()
	got, hitCap := walkOneDenyRoot(root, []string{".env"}, map[string]bool{}, make(chan struct{}, denyScanConcurrency), cache)
	slices.Sort(got)
	if hitCap {
		t.Fatalf("unexpected cap hit walking %s", root)
	}
	return got
}

// TestDenyScanCacheFirstPassMatchesSequential asserts the seeded pass
// (cache attached but empty) finds what the uncached walk finds.
func TestDenyScanCacheFirstPassMatchesSequential(t *testing.T) {
	root := cacheTree(t)
	got := cacheWalk(t, root, newDenyScanCache())
	want := []string{filepath.Join(root, "sub1", "deep", ".env")}
	if !slices.Equal(got, want) {
		t.Fatalf("cached first pass got %v, want %v", got, want)
	}
}

// TestDenyScanCacheSkipsUnchangedDirs asserts the second pass reads
// nothing: every directory is lstat'd (the traversal must still reach
// them), no directory is re-read, and no match is reported again.
func TestDenyScanCacheSkipsUnchangedDirs(t *testing.T) {
	root := cacheTree(t)
	cache := newDenyScanCache()
	rc := cache.state(root)

	if got := cacheWalk(t, root, cache); len(got) != 1 {
		t.Fatalf("first pass got %v", got)
	}
	readsAfterFirst := rc.readdirs.Load()
	if readsAfterFirst != 7 {
		t.Fatalf("first pass: %d readdirs, want 7 (root, sub1, sub2, deep+a per sub)", readsAfterFirst)
	}

	got := cacheWalk(t, root, cache)
	if len(got) != 0 {
		t.Fatalf("unchanged pass reported new matches: %v", got)
	}
	if rc.readdirs.Load() != readsAfterFirst {
		t.Errorf("unchanged pass re-read directories (%d -> %d readdirs)", readsAfterFirst, rc.readdirs.Load())
	}
	if rc.skips.Load() != 7 {
		t.Errorf("unchanged pass skipped %d directories, want 7", rc.skips.Load())
	}
	if lstats := rc.lstats.Load(); lstats != 14 {
		t.Errorf("two passes issued %d lstats, want 14 (every directory every pass)", lstats)
	}
}

// TestDenyScanCacheFindsNewMatchOnlyInChangedDirs creates a protected
// file in a deep untouched directory: only the ancestors on the way
// down changed, and exactly that subtree is re-read and matched.
func TestDenyScanCacheFindsNewMatchOnlyInChangedDirs(t *testing.T) {
	root := cacheTree(t)
	cache := newDenyScanCache()
	if got := cacheWalk(t, root, cache); len(got) != 1 {
		t.Fatalf("first pass got %v", got)
	}
	readsAfterFirst := cache.state(root).readdirs.Load()

	// root untouched, root/sub1 gains a new directory, root/sub2 untouched.
	if err := os.Mkdir(filepath.Join(root, "sub1", "newdir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub1", "newdir", ".env"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	got := cacheWalk(t, root, cache)
	want := filepath.Join(root, "sub1", "newdir", ".env")
	if len(got) != 1 || got[0] != want {
		t.Fatalf("incremental pass got %v, want [%s]", got, want)
	}
	reads := cache.state(root).readdirs.Load()
	if reads-readsAfterFirst != 2 { // sub1 and sub1/newdir
		t.Errorf("incremental pass re-read %d directories, want 2", reads-readsAfterFirst)
	}
}

// TestDenyScanCacheReconcilesRemovedDirs removes a subtree, then
// recreates it with a match: the cache must not serve the stale state
// of the removed directories.
func TestDenyScanCacheReconcilesRemovedDirs(t *testing.T) {
	root := cacheTree(t)
	cache := newDenyScanCache()
	if got := cacheWalk(t, root, cache); len(got) != 1 {
		t.Fatalf("first pass got %v", got)
	}

	if err := os.RemoveAll(filepath.Join(root, "sub1")); err != nil {
		t.Fatal(err)
	}
	if got := cacheWalk(t, root, cache); len(got) != 0 {
		t.Fatalf("pass after removal reported %v", got)
	}

	if err := os.MkdirAll(filepath.Join(root, "sub1", "deep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub1", "deep", ".env"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	got := cacheWalk(t, root, cache)
	want := filepath.Join(root, "sub1", "deep", ".env")
	if len(got) != 1 || got[0] != want {
		t.Fatalf("pass after recreation got %v, want [%s]", got, want)
	}
}

// TestDenyScanCacheFileRootSkipsReaddirs covers a granted file used as
// a scan root (e.g. ~/.gitconfig): the first pass attempts the read,
// later passes retire it with one lstat — even after the file is
// rewritten.
func TestDenyScanCacheFileRootSkipsReaddirs(t *testing.T) {
	file := filepath.Join(t.TempDir(), "dotfile")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cache := newDenyScanCache()
	rc := cache.state(file)

	if got := cacheWalk(t, file, cache); len(got) != 0 {
		t.Fatalf("file root reported %v", got)
	}
	if rc.readdirs.Load() != 1 {
		t.Fatalf("first pass: %d readdirs, want 1", rc.readdirs.Load())
	}

	if err := os.WriteFile(file, []byte("rewritten"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := cacheWalk(t, file, cache); len(got) != 0 {
		t.Fatalf("file root reported %v after rewrite", got)
	}
	if rc.readdirs.Load() != 1 {
		t.Errorf("file root was re-read after rewrite (%d readdirs)", rc.readdirs.Load())
	}
	if rc.skips.Load() != 1 {
		t.Errorf("file root skips = %d, want 1", rc.skips.Load())
	}
}

// TestDenyScanCacheChargesCapAcrossPasses grows a tree past a lowered
// cap between passes; the incremental pass must still sum the whole
// tree (cached counts for unchanged directories, fresh counts for
// changed ones) and report the cap like a full recount would.
func TestDenyScanCacheChargesCapAcrossPasses(t *testing.T) {
	setDenyScanLimit(t, 40)
	setDenyByName(t, true)
	root := t.TempDir()
	big := filepath.Join(root, "big")
	if err := os.Mkdir(big, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := range 10 {
		if err := os.WriteFile(filepath.Join(big, "n"), []byte{byte(i)}, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cache := newDenyScanCache()
	if got, hitCap := walkOneDenyRoot(root, []string{".env"}, map[string]bool{}, make(chan struct{}, denyScanConcurrency), cache); hitCap || len(got) != 0 {
		t.Fatalf("first pass: matches %v, cap %v", got, hitCap)
	}

	// Grow past the cap inside the one directory the second pass
	// re-reads; root itself is unchanged and skipped from reading.
	for i := range 50 {
		if err := os.WriteFile(filepath.Join(big, fmt.Sprintf("m%02d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, hitCap := walkOneDenyRoot(root, []string{".env"}, map[string]bool{}, make(chan struct{}, denyScanConcurrency), cache); !hitCap {
		t.Fatal("incremental pass must report the cap after the tree outgrew it")
	}
}
