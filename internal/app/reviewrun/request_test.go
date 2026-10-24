package reviewrun

import (
	"errors"
	"reflect"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestReviewRequestAdmissionCompatibility(t *testing.T) {
	target, err := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	if err != nil {
		t.Fatal(err)
	}
	defaults, err := ports.NewArtistReviewInputs("docs/default.md", []string{"design/**/*.png"})
	if err != nil {
		t.Fatal(err)
	}
	enabled := map[domain.Role]bool{domain.RoleLogic: true, domain.RoleArtist: true}
	for _, test := range []struct {
		name      string
		roles     []string
		explicit  bool
		brief     string
		globs     []string
		want      []string
		wantBrief string
		automatic bool
		failure   error
	}{
		{"default", []string{"logic", "security"}, false, "", nil, []string{"logic", "artist"}, "docs/default.md", true, nil},
		{"explicit", []string{"logic"}, true, "", nil, []string{"logic"}, "", false, nil},
		{"artist override", []string{"artist"}, true, "docs/custom.md", []string{"ui/**/*.webp"}, []string{"artist"}, "docs/custom.md", false, nil},
		{"disabled", []string{"testing"}, true, "", nil, nil, "", false, ErrRoleNotEnabled},
		{"inputs without artist", []string{"logic"}, true, "docs/custom.md", nil, nil, "", false, ErrArtistRoleRequired},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := NewRequest(RequestInput{Target: target, Roles: test.roles, RolesExplicit: test.explicit, ArtistBriefPath: test.brief, HasArtistBrief: test.brief != "", ArtistDesignGlobs: test.globs})
			for range 2 {
				admitted, err := ResolveRequest(request, enabled, defaults, true)
				if test.failure != nil {
					if !errors.Is(err, test.failure) {
						t.Fatalf("err=%v want=%v", err, test.failure)
					}
					return
				}
				resolved := admitted.Request()
				brief, present := resolved.ArtistBrief()
				if err != nil || !reflect.DeepEqual(resolved.Roles(), test.want) || resolved.RequestedRolesExplicit() != test.explicit || resolved.ArtistAutomatic() != test.automatic || brief != test.wantBrief || present != (test.wantBrief != "") {
					t.Fatalf("resolved=%+v err=%v", resolved, err)
				}
				if test.name == "artist override" && !reflect.DeepEqual(resolved.ArtistDesignSpecs(), []string{"ui/**/*.webp"}) {
					t.Fatal("request design override lost")
				}
				request = resolved
			}
		})
	}
	if _, err := ResolveRequest(NewRequest(RequestInput{Target: target, Roles: []string{"artist"}, RolesExplicit: true}), enabled, ports.ArtistReviewInputs{}, false); !errors.Is(err, ErrArtistInputsRequired) {
		t.Fatalf("missing artist defaults: %v", err)
	}
	roles := []string{"logic"}
	globs := []string{"design/**/*.png"}
	session, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	request := NewRequest(RequestInput{Target: target, Roles: roles, ArtistDesignGlobs: globs, SessionID: &session, Objective: "focus", HasObjective: true})
	roles[0] = "testing"
	globs[0] = "changed.png"
	session = domain.SessionID{}
	returnedRoles := request.Roles()
	returnedRoles[0] = "security"
	returnedGlobs := request.ArtistDesignSpecs()
	returnedGlobs[0] = "changed.webp"
	if !reflect.DeepEqual(request.Roles(), []string{"logic"}) || !reflect.DeepEqual(request.ArtistDesignSpecs(), []string{"design/**/*.png"}) {
		t.Fatal("request retained mutable caller storage")
	}
	if id, present := request.SessionID(); !present || id != "s_019f596a-cf80-7c67-b265-f37053d51ccf" {
		t.Fatal("session pointer changed request identity")
	}
	if value, present := request.Objective(); !present || value != "focus" {
		t.Fatal("objective presence changed")
	}
}
