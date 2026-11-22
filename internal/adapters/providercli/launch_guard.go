package providercli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/irootkernel/mulgae/internal/ports"
)

func rejectContainedLaunch(source string, places ...string) error {
	for _, place := range places {
		if place == "" {
			continue
		}
		if pathContains(source, place) || pathContains(place, source) {
			return fmt.Errorf("launch boundary: source and launch root contain one another")
		}
	}
	return nil
}

func pathContains(parent, child string) bool {
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

func boundaryCredentials(existing []ports.AnchoredRoot, namespaceAuth string, extras []string) ([]ports.AnchoredRoot, error) {
	roots := append([]ports.AnchoredRoot(nil), existing...)
	auth, err := ports.NewAnchoredRoot(namespaceAuth)
	if err != nil {
		return nil, err
	}
	roots = append(roots, auth)
	for _, candidate := range extras {
		root, ok, err := existingDirectory(candidate)
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

func rejectRuntimeHomeExposure(runtimeHome string, roots ...string) error {
	if runtimeHome == "" {
		return nil
	}
	for _, root := range roots {
		if root == "" {
			continue
		}
		if pathContains(root, runtimeHome) {
			return &launchBoundaryError{msg: "launch boundary: credential root contains the runtime home"}
		}
	}
	return nil
}

type launchBoundaryError struct {
	msg string
}

func (err *launchBoundaryError) Error() string {
	return err.msg
}

func existingDirectory(path string) (ports.AnchoredRoot, bool, error) {
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
