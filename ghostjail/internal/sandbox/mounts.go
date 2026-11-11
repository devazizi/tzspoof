package sandbox

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/sabz/ghostjail/internal/config"
)

// scratch is a private tmpfs that is never attached to the tree. It holds
// replacement files that are then cloned over their targets. Files are
// never unlinked: mounting over an unlinked file fails with ENOENT, which
// would break nested sessions.
type scratch struct{ fd int }

func newScratch() (*scratch, error) {
	fs, err := unix.Fsopen("tmpfs", unix.FSOPEN_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("fsopen tmpfs: %w", err)
	}
	defer unix.Close(fs)
	if err := unix.FsconfigCreate(fs); err != nil {
		return nil, fmt.Errorf("fsconfig create: %w", err)
	}
	mnt, err := unix.Fsmount(fs, unix.FSMOUNT_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("fsmount: %w", err)
	}
	return &scratch{fd: mnt}, nil
}

func (s *scratch) Close() { unix.Close(s.fd) }

func (s *scratch) WriteFile(name, content string, mode uint32) error {
	fd, err := unix.Openat(s.fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, mode)
	if err != nil {
		return fmt.Errorf("create scratch %s: %w", name, err)
	}
	defer unix.Close(fd)
	if _, err := unix.Write(fd, []byte(content)); err != nil {
		return fmt.Errorf("write scratch %s: %w", name, err)
	}
	return nil
}

func (s *scratch) Symlink(name, target string) error {
	if err := unix.Symlinkat(target, s.fd, name); err != nil {
		return fmt.Errorf("symlink scratch %s: %w", name, err)
	}
	return nil
}

// mountOver clones dirfd/path as a detached mount and attaches it at
// target without following a symlink at target (legacy mount(2) always
// follows, which overlays the file a symlinked /etc/localtime points to).
func mountOver(dirfd int, path string, nofollowSrc bool, target string) error {
	flags := uint(unix.OPEN_TREE_CLONE | unix.OPEN_TREE_CLOEXEC)
	if nofollowSrc {
		flags |= unix.AT_SYMLINK_NOFOLLOW
	}
	src, err := unix.OpenTree(dirfd, path, flags)
	if err != nil {
		return fmt.Errorf("open_tree %s: %w", path, err)
	}
	defer unix.Close(src)
	if err := unix.MoveMount(src, "", unix.AT_FDCWD, target, unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		return fmt.Errorf("move_mount onto %s: %w", target, err)
	}
	return nil
}

// replaceFile mounts scratch/name over target if target exists.
// Returns (false, nil) when target does not exist.
func (s *scratch) replaceFile(name, target string) (bool, error) {
	if _, err := os.Lstat(target); err != nil {
		return false, nil
	}
	return true, mountOver(s.fd, name, false, target)
}

type clonedBind struct {
	fd     int
	target string
	isDir  bool
}

// cloneBinds takes detached copies of each bind source (made read-only for
// --ro) while the sources are still visible.
func cloneBinds(binds []config.Bind) ([]clonedBind, error) {
	var out []clonedBind
	for _, b := range binds {
		st, err := os.Stat(b.Path)
		if err != nil {
			return nil, fmt.Errorf("bind %s: %w", b.Path, err)
		}
		fd, err := unix.OpenTree(unix.AT_FDCWD, b.Path,
			unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_RECURSIVE)
		if err != nil {
			return nil, fmt.Errorf("clone %s: %w", b.Path, err)
		}
		if !b.Writable {
			attr := unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY}
			if err := unix.MountSetattr(fd, "", unix.AT_EMPTY_PATH|unix.AT_RECURSIVE, &attr); err != nil {
				unix.Close(fd)
				return nil, fmt.Errorf("make %s read-only: %w", b.Path, err)
			}
		}
		out = append(out, clonedBind{fd: fd, target: b.Path, isDir: st.IsDir()})
	}
	return out, nil
}

// attachBinds attaches the clones at their original paths, creating the
// mount point when a mask (e.g. --tmp-home) removed it.
func attachBinds(binds []clonedBind) error {
	for _, b := range binds {
		if _, err := os.Lstat(b.target); err != nil {
			if err := os.MkdirAll(filepath.Dir(b.target), 0o700); err != nil {
				return fmt.Errorf("bind %s: %w", b.target, err)
			}
			if b.isDir {
				err = os.Mkdir(b.target, 0o700)
			} else {
				err = os.WriteFile(b.target, nil, 0o600)
			}
			if err != nil {
				return fmt.Errorf("bind %s: create mount point: %w", b.target, err)
			}
		}
		if err := unix.MoveMount(b.fd, "", unix.AT_FDCWD, b.target, unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
			return fmt.Errorf("bind %s: %w", b.target, err)
		}
	}
	return nil
}

// mountTmpfs mounts a fresh tmpfs on dir.
func mountTmpfs(dir, mode string) error {
	if err := unix.Mount("tmpfs", dir, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode="+mode); err != nil {
		return fmt.Errorf("mount tmpfs on %s: %w", dir, err)
	}
	return nil
}
