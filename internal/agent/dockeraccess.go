package agent

import (
	"fmt"
	"os"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/theo-mazars/best-before/internal/agent/docker"
)

// ServiceUser is the user the agent's service runs as.
const ServiceUser = "bestbefore-agent"

// socketGroup returns the group that may open a Docker socket, and whether
// ServiceUser is in it. user is nil when ServiceUser does not exist, as on a
// machine where the package is not installed.
func socketGroup(path string) (group *user.Group, member bool, u *user.User, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, false, nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, false, nil, fmt.Errorf("%s: cannot read its owner", path)
	}
	gid := strconv.FormatUint(uint64(st.Gid), 10)
	group, err = user.LookupGroupId(gid)
	if err != nil {
		group = &user.Group{Gid: gid, Name: gid}
	}
	u, err = user.Lookup(ServiceUser)
	if err != nil {
		return group, false, nil, nil
	}
	ids, _ := u.GroupIds()
	return group, u.Gid == gid || slices.Contains(ids, gid), u, nil
}

// socketPath returns the socket a docker setting reads, if any.
func socketPath(setting string) (string, bool) {
	if setting == DockerAuto {
		setting = docker.DefaultHost
	}
	path, ok := strings.CutPrefix(setting, "unix://")
	return path, ok
}

// DockerAccessNote says what the owner must do, if anything, for the agent's
// service to read Docker with the new setting, or to stop being able to read
// the socket of the previous one. The agent never changes groups itself:
// giving a user a Docker socket is the owner's decision, made visibly.
func DockerAccessNote(previous, setting string) string {
	if setting == DockerOff || strings.HasPrefix(setting, "tcp://") {
		// The previous socket's group is no longer needed.
		path, ok := socketPath(previous)
		if !ok {
			path = strings.TrimPrefix(docker.DefaultHost, "unix://")
		}
		group, member, u, err := socketGroup(path)
		if err != nil || u == nil || !member || u.Gid == group.Gid {
			return ""
		}
		return fmt.Sprintf(`%s is still in the %s group, which gives it the Docker socket. Remove it with:
  sudo gpasswd -d %s %s
`, ServiceUser, group.Name, ServiceUser, group.Name)
	}

	path, ok := socketPath(setting)
	if !ok {
		return ""
	}
	group, member, u, err := socketGroup(path)
	switch {
	case err != nil && setting == DockerAuto:
		return ""
	case err != nil:
		return fmt.Sprintf("%s cannot be read yet (%v): Docker is reported unavailable until it can.\n", path, err)
	case u == nil || member:
		return ""
	case group.Gid == "0":
		return fmt.Sprintf(`Only root can open %s: the agent's service cannot read it, and should not be
given the root group. Use a socket proxy instead (see docs/agent.md).
`, path)
	case setting == DockerAuto:
		// auto never asks for the socket, but uses it if it was given.
		return ""
	}
	return fmt.Sprintf(`The agent's service runs as %s, which cannot open %s yet.
Members of its group, %s, can; that access is equivalent to root, although the
agent only ever sends its five read requests. To allow it:
  sudo usermod -aG %s %s
It applies from the next report. To take it back:
  sudo gpasswd -d %s %s
`, ServiceUser, path, group.Name, group.Name, ServiceUser, ServiceUser, group.Name)
}
