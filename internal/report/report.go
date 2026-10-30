// Package report defines the JSON report an agent sends to the dashboard.
// It is shared by both binaries so that they always agree on the schema.
//
// Any change to the shape of these types must bump SchemaVersion.
package report

import "time"

// SchemaVersion is the version of the report format defined in this package.
const SchemaVersion = 1

// Report is one collection run on one server.
type Report struct {
	SchemaVersion int       `json:"schema_version"`
	AgentVersion  string    `json:"agent_version"`
	GeneratedAt   time.Time `json:"generated_at"`
	Host          Host      `json:"host"`
	// Docker is omitted on servers without Docker, which are common and
	// nothing to report on.
	Docker *Docker `json:"docker,omitempty"`
}

// Host describes the server itself.
type Host struct {
	Hostname       string `json:"hostname"`
	OS             OS     `json:"os"`
	Kernel         string `json:"kernel"`
	UptimeSeconds  int64  `json:"uptime_seconds"`
	RebootRequired bool   `json:"reboot_required"`
	// RebootRequiredPackages lists the packages that asked for the reboot,
	// when the system records them.
	RebootRequiredPackages []string `json:"reboot_required_packages"`
	APT                    APT      `json:"apt"`
	// Errors lists anything that could not be collected. An empty list
	// means every host field above is complete.
	Errors []string `json:"errors"`
}

// OS is taken from /etc/os-release.
type OS struct {
	ID        string `json:"id"`         // e.g. "ubuntu"
	Name      string `json:"name"`       // e.g. "Ubuntu 24.04.3 LTS"
	VersionID string `json:"version_id"` // e.g. "24.04"
	Codename  string `json:"codename"`   // e.g. "noble"
}

// APT holds package information from dpkg and apt.
type APT struct {
	// ListsPublishedAt is when the archive published the newest package
	// index on this server (apt keeps the archive's timestamp on the files it
	// downloads). Upgradable is only as fresh as these lists, and the agent
	// never refreshes them itself. Ubuntu's -security pocket publishes several
	// times a day, so a value more than a couple of days old means
	// apt-get update is not running or failing. Nil if the lists were never
	// downloaded.
	ListsPublishedAt *time.Time          `json:"lists_published_at"`
	Installed        []InstalledPackage  `json:"installed"`
	Upgradable       []UpgradablePackage `json:"upgradable"`
}

// InstalledPackage is one installed binary package.
type InstalledPackage struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	// Source and SourceVersion identify the source package, which is what
	// Ubuntu security notices refer to.
	Source        string `json:"source"`
	SourceVersion string `json:"source_version"`
}

// UpgradablePackage is an installed package with a newer candidate.
type UpgradablePackage struct {
	Name             string `json:"name"`
	Architecture     string `json:"architecture"`
	CurrentVersion   string `json:"current_version"`
	CandidateVersion string `json:"candidate_version"`
	// Origins are the archives offering the candidate, e.g.
	// "Ubuntu:24.04/noble-security".
	Origins []string `json:"origins"`
	// Security is true when any origin is a -security pocket.
	Security bool `json:"security"`
}

// Docker describes the running containers and the images they use.
type Docker struct {
	// Available is false when Docker is installed but its API could not be
	// read; Error then says why. The dashboard must treat this as a problem,
	// never as "nothing running".
	Available     bool        `json:"available"`
	Error         string      `json:"error,omitempty"`
	EngineVersion string      `json:"engine_version,omitempty"`
	Containers    []Container `json:"containers"`
	Images        []Image     `json:"images"`
}

// Container is one running container.
type Container struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Image is the image reference as written when the container was
	// created, e.g. "mysql:8.0.36".
	Image          string    `json:"image"`
	ImageID        string    `json:"image_id"`
	CreatedAt      time.Time `json:"created_at"`
	ComposeProject string    `json:"compose_project,omitempty"`
	ComposeService string    `json:"compose_service,omitempty"`
}

// Image is one distinct image used by at least one running container.
type Image struct {
	ID string `json:"id"`
	// RepoDigests are the registry digests of the image, e.g.
	// "mysql@sha256:…". Empty for images built locally and never pushed.
	RepoDigests  []string  `json:"repo_digests"`
	RepoTags     []string  `json:"repo_tags"`
	CreatedAt    time.Time `json:"created_at"`
	OS           string    `json:"os"`
	Architecture string    `json:"architecture"`
}
