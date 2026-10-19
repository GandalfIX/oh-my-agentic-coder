package sandboxrun

import (
	"sync"
	"sync/atomic"
)

// dirFingerprint identifies a directory's metadata state: the (sec,
// nsec) pairs of its mtime and ctime. mtime changes whenever the entry
// set changes (create, unlink, rename all update it), so an unchanged
// mtime proves the entry set is unchanged. ctime also catches changes
// that leave mtime alone, such as a chmod that makes a previously
// unreadable folder readable.
type dirFingerprint struct {
	mtimeSec, mtimeNsec int64
	ctimeSec, ctimeNsec int64
}

func (f dirFingerprint) equal(o dirFingerprint) bool {
	return f.mtimeSec == o.mtimeSec && f.mtimeNsec == o.mtimeNsec &&
		f.ctimeSec == o.ctimeSec && f.ctimeNsec == o.ctimeNsec
}

// denyScanCache remembers what the last walk of each scan root saw in
// every directory: its fingerprint, entry count and the subdirectories
// the walk descended into. The mid-session protected-file watch passes
// one cache to every periodic re-walk, so a pass can skip re-reading
// any directory whose fingerprint is unchanged. An unchanged directory
// cannot have gained or lost entries, so the cached subdirectory list
// keeps the traversal going and no new matches can hide inside it; a
// changed directory is read again like on the first pass.
//
// Why it exists: without the cache, every watch tick re-opened and
// re-read every directory of every granted root. Large grants are
// common — tool-chain and package-cache trees like ~/.cache/uv or an
// npm content store hold tens of thousands of directories — and on
// macOS every open()/readdir of a home-relative path pays a Seatbelt
// policy evaluation (`sandcastle_match_any_home_directory`). The
// full re-walk therefore burned multiple CPU cores permanently while
// the session sat idle. With the cache an idle pass costs one lstat
// per directory instead of open+readdir, and only directories that
// actually changed are read again.
//
// State is kept per scan root (the granted spelling), because two
// granted roots may overlap and each root's walk must count its own
// entries toward the shared scan cap. All methods are safe for the
// walk's concurrent per-root workers.
type denyScanCache struct {
	mu    sync.Mutex
	roots map[string]*denyScanRootState
}

// denyScanRootState is one root's cached walk state. The lstats,
// readdirs and skips counters are diagnostics: tests use them to assert
// unchanged directories are skipped; nothing else reads them.
type denyScanRootState struct {
	mu       sync.Mutex
	dirs     map[string]*denyScanDirState
	lstats   atomic.Int64
	readdirs atomic.Int64
	skips    atomic.Int64
}

// denyScanDirState is what the last pass saw in one directory. count is
// the number of readdir entries (what the walk charges against the
// scan cap); subdirs are the resolved paths the walk descended into,
// after the same pruning the walk applies — protected, skip-listed and
// glob-matched folders are not descended, so they are not listed.
type denyScanDirState struct {
	isDir   bool
	fp      dirFingerprint
	count   int64
	subdirs []string
}

func newDenyScanCache() *denyScanCache {
	return &denyScanCache{roots: map[string]*denyScanRootState{}}
}

// state returns the per-root cache entry, creating it on first use.
func (c *denyScanCache) state(root string) *denyScanRootState {
	c.mu.Lock()
	defer c.mu.Unlock()
	rc, ok := c.roots[root]
	if !ok {
		rc = &denyScanRootState{dirs: map[string]*denyScanDirState{}}
		c.roots[root] = rc
	}
	return rc
}

// unchanged reports the cached state of dir when the walk can skip
// re-reading it. A non-directory (a granted file used as a scan root)
// never yields entries to match, so once known it is skipped for good;
// a directory is skipped only while its fingerprint is unchanged.
func (r *denyScanRootState) unchanged(dir string, fp dirFingerprint, isDir bool) (*denyScanDirState, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.dirs[dir]
	if !ok || e.isDir != isDir {
		return nil, false
	}
	if !isDir || e.fp.equal(fp) {
		return e, true
	}
	return nil, false
}

// record stores one directory's fresh read and reconciles the subtree:
// cached subdirectories that no longer appear in subdirs were removed
// or renamed, so their cached state is dropped. A later pass then reads
// such a path from scratch should it reappear.
func (r *denyScanRootState) record(dir string, fp dirFingerprint, isDir bool, count int64, subdirs []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.dirs[dir]; ok {
		seen := make(map[string]bool, len(subdirs))
		for _, s := range subdirs {
			seen[s] = true
		}
		for _, s := range old.subdirs {
			if !seen[s] {
				r.forgetLocked(s)
			}
		}
	}
	r.dirs[dir] = &denyScanDirState{isDir: isDir, fp: fp, count: count, subdirs: subdirs}
}

// forget drops dir and everything below it from the cache, e.g. after
// an lstat failed between discovery and read.
func (r *denyScanRootState) forget(dir string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.forgetLocked(dir)
}

func (r *denyScanRootState) forgetLocked(dir string) {
	e, ok := r.dirs[dir]
	if !ok {
		return
	}
	delete(r.dirs, dir)
	for _, s := range e.subdirs {
		r.forgetLocked(s)
	}
}
