// Package docker reads running containers and their images from the Docker
// Engine API.
//
// It only ever reads: the client exposes no method but GET, its transport
// refuses any other method and any path outside the five read endpoints the
// agent uses (the same list as the socket proxy in packaging/socket-proxy),
// and getonly_test.go fails the build if this package mentions another HTTP
// method.
//
// This does not make access to the Docker socket safe. Whoever can reach the
// socket is effectively root on the host, whatever this code does with it;
// see docs/agent.md for the choice between a socket proxy and the socket.
package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// DefaultHost is used when neither a flag nor DOCKER_HOST is set.
const DefaultHost = "unix:///var/run/docker.sock"

// presenceMarkers are files whose existence shows that Docker is installed:
// the default socket, or the daemon from Docker's packages, Ubuntu's
// docker.io package, a manual install or the snap.
var presenceMarkers = []string{
	"/var/run/docker.sock",
	"/usr/bin/dockerd",
	"/usr/sbin/dockerd",
	"/usr/local/bin/dockerd",
	"/snap/docker",
}

// Present reports whether Docker is installed on this server. A missing
// socket alone does not mean "no Docker": the daemon may be installed but not
// running, and that must be reported rather than ignored.
func Present() bool {
	return anyExists(presenceMarkers)
}

func anyExists(paths []string) bool {
	for _, p := range paths {
		if _, err := os.Lstat(p); err == nil {
			return true
		}
	}
	return false
}

// maxResponseBytes bounds every API response.
const maxResponseBytes = 32 << 20

// errNotFound is returned for 404 responses, e.g. a container that stopped
// between listing and inspecting it.
var errNotFound = errors.New("not found")

// Client talks to the Docker Engine API with GET requests only.
type Client struct {
	http   *http.Client
	stream *http.Client
	base   string
}

// NewClient accepts "unix:///path/to/docker.sock" or "tcp://host:port"
// (plain HTTP, as served by a socket proxy).
func NewClient(host string) (*Client, error) {
	u, err := url.Parse(host)
	if err != nil {
		return nil, fmt.Errorf("invalid Docker host %q: %w", host, err)
	}

	transport := &http.Transport{
		Proxy:                 nil,
		ResponseHeaderTimeout: 30 * time.Second,
		DisableCompression:    true,
	}
	var base string
	switch u.Scheme {
	case "unix":
		socket := u.Path
		var d net.Dialer
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.DialContext(ctx, "unix", socket)
		}
		base = "http://docker"
	case "tcp":
		base = "http://" + u.Host
	default:
		return nil, fmt.Errorf("unsupported Docker host %q: use unix:// or tcp://", host)
	}

	return &Client{
		http: &http.Client{
			Transport: getOnly{transport},
			Timeout:   time.Minute,
		},
		// Image exports can take minutes; their callers set a deadline.
		stream: &http.Client{Transport: getOnly{transport}},
		base:   base,
	}, nil
}

// open starts a GET request whose body is streamed to the caller, who must
// close it.
func (c *Client) open(ctx context.Context, path string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.stream.Do(req)
	if err != nil {
		return nil, err
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		resp.Body.Close()
		return nil, errNotFound
	case resp.StatusCode != http.StatusOK:
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s: %s", path, resp.Status, strings.TrimSpace(string(msg)))
	}
	return resp.Body, nil
}

// get fetches an API path and decodes the JSON response into out.
func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body := io.LimitReader(resp.Body, maxResponseBytes)
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return errNotFound
	case resp.StatusCode != http.StatusOK:
		msg, _ := io.ReadAll(io.LimitReader(body, 1024))
		return fmt.Errorf("GET %s: %s: %s", path, resp.Status, strings.TrimSpace(string(msg)))
	}
	if err := json.NewDecoder(body).Decode(out); err != nil {
		return fmt.Errorf("GET %s: decoding response: %w", path, err)
	}
	return nil
}

// allowedPaths are the only requests the agent makes, by the IDs Docker
// returns: its version, the running containers, and each one's details and
// image. Some GET endpoints are not reads (attaching to a container over a
// WebSocket) or read too much (logs, files from containers), so GET alone is
// not enough when the agent is given the socket itself. The socket proxy's
// compose.yaml allows the same list; getonly_test.go keeps them in step.
const allowedPaths = `/version|/containers/json|/containers/[0-9a-f]{64}/json|/images/sha256:[0-9a-f]{64}/(json|get)`

var allowedPath = regexp.MustCompile(`^(` + allowedPaths + `)$`)

// getOnly refuses every request that is not a GET of an allowed path, with no
// query, as a last line of defence.
type getOnly struct{ next http.RoundTripper }

func (g getOnly) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet {
		return nil, fmt.Errorf("refusing %s %s: the agent only reads from Docker", req.Method, req.URL.Path)
	}
	if path := req.URL.EscapedPath(); !allowedPath.MatchString(path) || req.URL.RawQuery != "" {
		return nil, fmt.Errorf("refusing GET %s: not one of the read requests the agent makes", req.URL.RequestURI())
	}
	return g.next.RoundTrip(req)
}
