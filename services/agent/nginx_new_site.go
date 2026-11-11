package main

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func newNginxSite(p HostWafPlan) ([]byte, error) {
	if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$`).MatchString(p.Hostname) || p.ListenPort < 1 || p.ListenPort > 65535 || strings.ContainsAny(p.Upstream, "\"'\\$;{}\r\n\t ") {
		return nil, errors.New("invalid new nginx hostname, port or upstream")
	}
	origin, err := url.Parse(p.Upstream)
	if err != nil || origin.Scheme != "http" || origin.Hostname() == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || origin.Path != "" {
		return nil, errors.New("new nginx site requires exact HTTP business origin")
	}
	entry, err := url.Parse(p.EntryURL)
	if err != nil || entry.Hostname() != "127.0.0.1" || entry.User != nil || entry.Path != "/" || entry.RawQuery != "" || entry.Fragment != "" {
		return nil, errors.New("invalid new nginx entry")
	}
	port := entry.Port()
	if port == "" {
		if entry.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	if port != fmt.Sprint(p.ListenPort) {
		return nil, errors.New("nginx listen port differs from explicit entry")
	}
	tls := ""
	listen := fmt.Sprint(p.ListenPort)
	if entry.Scheme == "https" {
		for _, path := range []string{p.CertificateFile, p.CertificateKeyFile} {
			if !regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`).MatchString(path) || filepath.Clean(path) != path {
				return nil, errors.New("HTTPS requires explicit certificate and key file paths")
			}
		}
		listen += " ssl"
		tls = fmt.Sprintf("    ssl_certificate %s;\n    ssl_certificate_key %s;\n    ssl_protocols TLSv1.2 TLSv1.3;\n", p.CertificateFile, p.CertificateKeyFile)
	} else if entry.Scheme != "http" || p.CertificateFile != "" || p.CertificateKeyFile != "" {
		return nil, errors.New("certificate fields and entry scheme differ")
	}
	return []byte(fmt.Sprintf("server {\n    listen %s;\n    server_name %s;\n%s    location / {\n        proxy_pass %s;\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto $scheme;\n    }\n}\n", listen, p.Hostname, tls, p.Upstream)), nil
}

// Publish a fully written new vhost without ever replacing an existing path.
func createNewNginxFile(path string, body []byte) (created bool, resultErr error) {
	if err := safePath(filepath.Dir(path), filepath.Dir(path)); err != nil {
		return false, err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".selfguard-new-nginx-*")
	if err != nil {
		return false, err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0644); err == nil {
		_, err = f.Write(body)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return false, err
	}
	if err = os.Link(name, path); err != nil {
		return false, err
	}
	if err = os.Remove(name); err != nil {
		return true, err
	}
	return true, syncParent(path)
}
func applyNewNginxTransaction(path, state string, after []byte, verify func() error, run func(...string) error, review ...func() error) (resultErr error) {
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return errors.New("new nginx configuration already exists or cannot be checked")
	}
	if err := run("-t"); err != nil {
		return errors.New("existing nginx configuration is invalid; unchanged")
	}
	if err := os.Mkdir(state, 0700); err != nil {
		return err
	}
	tx := nginxTransaction{Path: path, BeforeSHA256: contentDigest(nil), AfterSHA256: contentDigest(after), BeforeAbsent: true, Mode: 0644, Status: "PREPARED"}
	if err := writePrivate(filepath.Join(state, "original.json"), []byte(nil)); err != nil {
		return err
	}
	if err := writePrivate(filepath.Join(state, "journal.json"), tx); err != nil {
		return err
	}
	for _, check := range review {
		if err := check(); err != nil {
			return err
		}
	}
	published := false
	defer func() {
		if resultErr != nil && published {
			resultErr = errors.Join(resultErr, rollbackNginxTransaction(state, run))
		}
	}()
	published, resultErr = createNewNginxFile(path, after)
	if resultErr != nil {
		return resultErr
	}
	if err := run("-t"); err != nil {
		return err
	}
	if err := run("-s", "reload"); err != nil {
		return err
	}
	if err := verify(); err != nil {
		return err
	}
	tx.Status = "VERIFIED"
	return writePrivate(filepath.Join(state, "journal.json"), tx)
}
