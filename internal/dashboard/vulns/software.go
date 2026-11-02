package vulns

import (
	"regexp"

	"github.com/theo-mazars/best-before/internal/report"
)

// software is something images install without their package manager and
// announce in a *_VERSION environment variable, matched by CPE (the naming
// scheme of the NVD) rather than through a distribution's security data.
type software struct {
	variable string   // e.g. NODE_VERSION
	name     string   // shown in the dashboard
	cpes     []string // vendor:product pairs in the NVD's naming
}

// knownSoftware lists the variables official images set. Each CPE was checked
// against the Grype database. Variables not listed here are ignored.
var knownSoftware = []software{
	{"NODE_VERSION", "node", []string{"nodejs:node.js"}},
	{"PYTHON_VERSION", "python", []string{"python:python"}},
	{"PHP_VERSION", "php", []string{"php:php"}},
	{"RUBY_VERSION", "ruby", []string{"ruby-lang:ruby"}},
	// Checked against Go's own vulnerability data rather than by CPE.
	{"GOLANG_VERSION", "go", nil},
	{"JAVA_VERSION", "java", []string{"oracle:openjdk"}},
	{"REDIS_VERSION", "redis", []string{"redis:redis"}},
	{"PG_VERSION", "postgresql", []string{"postgresql:postgresql"}},
	{"MYSQL_VERSION", "mysql", []string{"oracle:mysql"}},
	{"MARIADB_VERSION", "mariadb", []string{"mariadb:mariadb"}},
	{"MONGO_VERSION", "mongodb", []string{"mongodb:mongodb"}},
	{"NGINX_VERSION", "nginx", []string{"f5:nginx", "nginx:nginx"}},
	{"HTTPD_VERSION", "httpd", []string{"apache:http_server"}},
	{"HAPROXY_VERSION", "haproxy", []string{"haproxy:haproxy"}},
	{"CADDY_VERSION", "caddy", []string{"caddyserver:caddy"}},
	{"TOMCAT_VERSION", "tomcat", []string{"apache:tomcat"}},
	{"RABBITMQ_VERSION", "rabbitmq", []string{"vmware:rabbitmq", "pivotal_software:rabbitmq"}},
	{"MEMCACHED_VERSION", "memcached", []string{"memcached:memcached"}},
}

var softwareByVariable = func() map[string]software {
	m := map[string]software{}
	for _, s := range knownSoftware {
		m[s.variable] = s
	}
	return m
}()

// SoftwareName returns the name of the software a *_VERSION variable
// announces, if it is one the dashboard checks.
func SoftwareName(variable string) (string, bool) {
	s, ok := softwareByVariable[variable]
	return s.name, ok
}

// Software sorts the *_VERSION variables the dashboard recognises into
// those it matches, e.g. "node 22.11.0", and those whose value is not a
// precise enough version to match, e.g. "redis 7".
func Software(vars []report.VersionVariable) (checked, imprecise []string) {
	for _, v := range vars {
		s, ok := softwareByVariable[v.Name]
		if !ok {
			continue
		}
		if _, ok := softwareVersion(v.Value); ok {
			checked = append(checked, s.name+" "+v.Value)
		} else {
			imprecise = append(imprecise, s.name+" "+v.Value)
		}
	}
	return checked, imprecise
}

var dottedVersion = regexp.MustCompile(`\d+(?:\.\d+)+`)

// softwareVersion extracts the upstream version from the forms images use:
// "22.11.0", "v2.11.7", "jdk-21.0.13+9", "9.7.0-1.el9",
// "1:11.4.2+maria~ubu2404". A value without a dotted version, such as "8",
// cannot be matched precisely and is skipped.
func softwareVersion(value string) (string, bool) {
	v := dottedVersion.FindString(value)
	return v, v != ""
}
