package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"
)

func fetchHostWafImageArchive(a *Agent, p HostWafPlan, out io.Writer) error {
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(p.ImageArchiveSHA256) || p.ImageArchiveBytes < 1 || p.ImageArchiveBytes > 64<<20 {
		return errors.New("invalid managed image archive bounds")
	}
	origin, err := url.Parse(a.Config.Server)
	if err != nil || !validPlatformPath(origin) || origin.User != nil || origin.Host == "" || (origin.Scheme != "https" && !(origin.Scheme == "http" && a.Config.AllowHTTP)) {
		return errors.New("trusted platform transport required for image download")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	target := strings.TrimSuffix(a.Config.Server, "/") + "/api/agent/host-waf/image?sha256=" + p.ImageArchiveSHA256
	request, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+a.Identity.Token)
	client := *a.Client
	client.Timeout = 3 * time.Minute
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return errors.New("managed WAF image download failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.ContentLength >= 0 && response.ContentLength != p.ImageArchiveBytes {
		return errors.New("managed WAF image response or length differs from approved plan")
	}
	digest := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, digest), io.LimitReader(response.Body, p.ImageArchiveBytes+1))
	if err != nil || n != p.ImageArchiveBytes || hex.EncodeToString(digest.Sum(nil)) != p.ImageArchiveSHA256 {
		return errors.New("managed WAF image archive size or SHA256 mismatch")
	}
	return nil
}
func ensureHostWafImage(a *Agent, p HostWafPlan) error {
	image, err := hostTool("docker", "image", "inspect", "--format", "{{.Os}}|{{.Architecture}}", p.Image)
	if err == nil {
		if image != "linux|"+runtime.GOARCH {
			return errors.New("WAF image architecture differs from this host")
		}
		return nil
	}
	if !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(p.Image) {
		return errors.New("managed image delivery requires a fixed local image ID; preload registry digests explicitly")
	}
	root := "/var/lib/selfguard-host-waf"
	if err = os.MkdirAll(root, 0700); err != nil {
		return err
	}
	if err = executorTrustedDirectory(root, true); err != nil {
		return err
	}
	file, err := os.CreateTemp(root, ".image-*.tar")
	if err != nil {
		return err
	}
	path := file.Name()
	defer os.Remove(path)
	err = fetchHostWafImageArchive(a, p, file)
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return err
	}
	if _, err = hostTool("docker", "load", "--input", path); err != nil {
		return err
	}
	image, err = hostTool("docker", "image", "inspect", "--format", "{{.Os}}|{{.Architecture}}", p.Image)
	if err != nil || image != "linux|"+runtime.GOARCH {
		return errors.New("delivered archive did not contain the exact approved WAF image and architecture")
	}
	return nil
}
