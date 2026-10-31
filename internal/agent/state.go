package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/theo-mazars/best-before/internal/protocol"
)

// state lives in the agent's state directory, readable by the agent only.
type state struct {
	dir string
}

func (s state) keyPath() string { return filepath.Join(s.dir, "agent.key") }
func (s state) seqPath() string { return filepath.Join(s.dir, "sequence") }

func (s state) enrolled() bool {
	_, err := os.Stat(s.keyPath())
	return err == nil
}

func (s state) loadKey() (*protocol.AgentKey, error) {
	info, err := os.Stat(s.keyPath())
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by other users; run: chmod 600 %s", s.keyPath(), s.keyPath())
	}
	data, err := os.ReadFile(s.keyPath())
	if err != nil {
		return nil, err
	}
	return protocol.ParseAgentKey(data)
}

// saveKey replaces the key and resets the sequence, as for a new agent.
func (s state) saveKey(k *protocol.AgentKey) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	data, err := k.MarshalBinary()
	if err != nil {
		return err
	}
	if err := writeFileAtomic(s.keyPath(), data, 0o600); err != nil {
		return err
	}
	if err := os.Remove(s.seqPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// nextSequence returns the next sequence number, recorded on disk before it
// is used, so that a crash can never lead to a number being sent twice.
func (s state) nextSequence() (uint64, error) {
	var last uint64
	data, err := os.ReadFile(s.seqPath())
	switch {
	case err == nil:
		if last, err = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err != nil {
			return 0, fmt.Errorf("%s is damaged: %w", s.seqPath(), err)
		}
	case !errors.Is(err, os.ErrNotExist):
		return 0, err
	}
	next := last + 1
	if err := writeFileAtomic(s.seqPath(), []byte(strconv.FormatUint(next, 10)+"\n"), 0o600); err != nil {
		return 0, err
	}
	return next, nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := matchDirOwner(tmp); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// matchDirOwner gives a file the owner of its directory. Enrolment runs as
// root, but the agent's service runs as its own user, which owns the state
// directory once the service has started.
func matchDirOwner(path string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	return os.Lchown(path, int(st.Uid), int(st.Gid))
}
