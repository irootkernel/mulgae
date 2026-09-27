package app

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// NewProjectBinding hashes private local identity. Only its returned digest may
// cross a public boundary; callers observe canonical paths through descriptors.
func NewProjectBinding(root, gitDirectory, commonDirectory ports.AnchoredRoot, rootIdentity, gitIdentity, commonIdentity ports.ProjectDirectoryIdentity) (domain.ProjectBinding, error) {
	if !root.Valid() || !gitDirectory.Valid() || !commonDirectory.Valid() || !utf8.ValidString(root.String()) || !utf8.ValidString(gitDirectory.String()) || !utf8.ValidString(commonDirectory.String()) {
		return domain.ProjectBinding{}, fmt.Errorf("project binding: invalid anchors")
	}
	for _, identity := range []ports.ProjectDirectoryIdentity{rootIdentity, gitIdentity, commonIdentity} {
		if identity.Device == 0 || identity.Inode == 0 || identity.BirthSeconds < 0 || identity.BirthNanoseconds < 0 || identity.BirthNanoseconds >= 1_000_000_000 {
			return domain.ProjectBinding{}, fmt.Errorf("project binding: invalid descriptor identity")
		}
	}
	data, err := json.Marshal(struct {
		Root            string                         `json:"root"`
		GitDirectory    string                         `json:"git_directory"`
		CommonDirectory string                         `json:"common_directory"`
		RootIdentity    ports.ProjectDirectoryIdentity `json:"root_identity"`
		GitIdentity     ports.ProjectDirectoryIdentity `json:"git_identity"`
		CommonIdentity  ports.ProjectDirectoryIdentity `json:"common_identity"`
	}{root.String(), gitDirectory.String(), commonDirectory.String(), rootIdentity, gitIdentity, commonIdentity})
	if err != nil {
		return domain.ProjectBinding{}, err
	}
	return domain.ParseProjectBinding(fmt.Sprintf("sha256:%x", sha256.Sum256(append([]byte("mulgae-project-binding.v1\x00"), data...))))
}
