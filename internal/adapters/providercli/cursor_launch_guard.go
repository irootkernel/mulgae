package providercli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/irootkernel/mulgae/internal/ports"
)

func cursorRejectContainedLaunch(source string, places ...string) error {
	for _, place := range places {
		if place == "" {
			continue
		}
		if cursorPathContains(source, place) || cursorPathContains(place, source) {
			return fmt.Errorf("cursor launch: source and launch root contain one another")
		}
	}
	return nil
}

func cursorPathContains(parent, child string) bool {
	parent = filepath.Clean(parent)
	child = filepath.Clean(child)
	if parent == child {
		return true
	}
	if parent == "/" {
		return strings.HasPrefix(child, "/")
	}
	return strings.HasPrefix(child, parent+"/")
}

func cursorBoundaryCredentials(existing []ports.AnchoredRoot, namespaceAuth string, extras []string) ([]ports.AnchoredRoot, error) {
	roots := append([]ports.AnchoredRoot(nil), existing...)
	auth, err := ports.NewAnchoredRoot(namespaceAuth)
	if err != nil {
		return nil, err
	}
	roots = append(roots, auth)
	for _, candidate := range extras {
		root, ok, err := cursorExistingDirectory(candidate)
		if err != nil {
			return nil, err
		}
		if ok {
			roots = append(roots, root)
		}
	}
	seen := map[string]struct{}{}
	unique := make([]ports.AnchoredRoot, 0, len(roots))
	for _, root := range roots {
		if _, ok := seen[root.String()]; ok {
			continue
		}
		seen[root.String()] = struct{}{}
		unique = append(unique, root)
	}
	return unique, nil
}

func cursorQualificationExtras(runtimeHome, projectRoot, fixture string, configured []string) ([]string, error) {
	if err := cursorRejectRuntimeHomeExposure(runtimeHome, projectRoot); err != nil {
		return nil, err
	}
	extras := make([]string, 0, len(configured)+6)
	if runtimeHome != "" {
		for _, relative := range []string{".codex", ".grok", ".zcode", ".cursor", filepath.Join(".config", "cursor")} {
			extras = append(extras, filepath.Join(runtimeHome, relative))
		}
	}
	for _, configuredRoot := range configured {
		if configuredRoot == "" {
			continue
		}
		if err := cursorRejectRuntimeHomeExposure(runtimeHome, configuredRoot); err != nil {
			return nil, err
		}
		extras = append(extras, configuredRoot)
	}
	if projectRoot == "" {
		return extras, nil
	}
	if cursorPathContains(projectRoot, fixture) || cursorPathContains(fixture, projectRoot) {
		return nil, fmt.Errorf("cursor qualification: project overlaps the permitted source")
	}
	return append(extras, projectRoot), nil
}

func cursorRejectRuntimeHomeExposure(runtimeHome string, roots ...string) error {
	if runtimeHome == "" {
		return nil
	}
	for _, root := range roots {
		if root == "" {
			continue
		}
		if cursorPathContains(root, runtimeHome) {
			return &cursorBoundaryError{msg: "cursor boundary: credential root contains the runtime home"}
		}
	}
	return nil
}

type cursorBoundaryError struct {
	msg string
}

func (err *cursorBoundaryError) Error() string {
	return err.msg
}

func cursorExistingDirectory(path string) (ports.AnchoredRoot, bool, error) {
	if path == "" {
		return ports.AnchoredRoot{}, false, nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ports.AnchoredRoot{}, false, nil
		}
		return ports.AnchoredRoot{}, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			if os.IsNotExist(err) {
				return ports.AnchoredRoot{}, false, nil
			}
			return ports.AnchoredRoot{}, false, err
		}
		path = resolved
		info, err = os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				return ports.AnchoredRoot{}, false, nil
			}
			return ports.AnchoredRoot{}, false, err
		}
	}
	if !info.IsDir() {
		return ports.AnchoredRoot{}, false, nil
	}
	root, err := ports.NewAnchoredRoot(path)
	if err != nil {
		return ports.AnchoredRoot{}, false, err
	}
	return root, true, nil
}
