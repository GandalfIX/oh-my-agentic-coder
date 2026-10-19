//go:build darwin

package sandboxrun

import (
	"os"
	"syscall"
)

// fingerprintOf extracts a directory's mtime and ctime. ctime comes
// from the raw stat: metadata-only changes (chmod) must also
// invalidate the cache, and os.FileInfo does not expose it.
func fingerprintOf(info os.FileInfo) dirFingerprint {
	mt := info.ModTime()
	fp := dirFingerprint{mtimeSec: mt.Unix(), mtimeNsec: int64(mt.Nanosecond())}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		fp.ctimeSec, fp.ctimeNsec = int64(st.Ctimespec.Sec), int64(st.Ctimespec.Nsec)
	} else {
		fp.ctimeSec, fp.ctimeNsec = fp.mtimeSec, fp.mtimeNsec
	}
	return fp
}
