package config_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	appconfig "github.com/irootkernel/mulgae/internal/app/config"
	"github.com/irootkernel/mulgae/internal/ports"
)

type confirmationSource struct {
	ports.ConfigSource
	trace  *[]string
	calls  int
	failAt int
	cause  error
}

func (source *confirmationSource) Revalidate() error {
	*source.trace = append(*source.trace, "source")
	source.calls++
	if source.calls == source.failAt {
		return source.cause
	}
	return nil
}

type confirmationAttestor struct {
	ports.ConfigLocalityAttestor
	trace    *[]string
	cause    error
	ctx      context.Context
	request  ports.ConfigLocalityRequest
	expected ports.ConfigLocalityContext
}

func (attestor confirmationAttestor) Revalidate(ctx context.Context, request ports.ConfigLocalityRequest, expected ports.ConfigLocalityContext) error {
	if ctx != attestor.ctx || !reflect.DeepEqual(request, attestor.request) || !reflect.DeepEqual(expected, attestor.expected) {
		panic("confirmation changed arguments")
	}
	*attestor.trace = append(*attestor.trace, "attestor")
	return attestor.cause
}
func TestLocalityAdmissionSequence(t *testing.T) {
	for _, test := range []struct {
		name          string
		failAt        int
		attestorFails bool
		want          []string
	}{
		{name: "success", want: []string{"source", "attestor", "source"}},
		{name: "first source failure", failAt: 1, want: []string{"source"}},
		{name: "attestor failure", attestorFails: true, want: []string{"source", "attestor"}},
		{name: "final source failure", failAt: 2, want: []string{"source", "attestor", "source"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, cause := range []error{errors.New("identity changed"), context.Canceled, context.DeadlineExceeded} {
				var trace []string
				source := &confirmationSource{trace: &trace, failAt: test.failAt, cause: cause}
				ctx := context.WithValue(context.Background(), struct{}{}, "confirmation context")
				attestor := confirmationAttestor{trace: &trace, ctx: ctx}
				if test.attestorFails {
					attestor.cause = cause
				}
				got := appconfig.ConfirmLocality(ctx, source, attestor, attestor.request, attestor.expected)
				if test.failAt != 0 || test.attestorFails {
					if got != cause {
						t.Fatalf("cause identity lost: got %v want %v", got, cause)
					}
				} else if got != nil {
					t.Fatal(got)
				}
				if !reflect.DeepEqual(trace, test.want) {
					t.Fatalf("trace=%v want=%v", trace, test.want)
				}
			}
		})
	}
}
func TestNativeAccountAdmissionCompatibility(t *testing.T) {
	lookupFailure := errors.New("lookup failed")
	for _, test := range []struct {
		name, home, uid string
		available       bool
		euid            int
		lookupErr       error
		want            string
	}{
		{name: "matching", home: "/Users/example", uid: "501", available: true, euid: 501},
		{name: "leading zeros preserved", home: "/Users/example", uid: "0501", available: true, euid: 501},
		{name: "zero uid", home: "/Users/example", uid: "0", available: true, euid: 0},
		{name: "lookup failure", lookupErr: lookupFailure, want: "native user account is unavailable"},
		{name: "account absent", want: "native user account is unavailable"},
		{name: "home absent", available: true, uid: "501", euid: 501, want: "native user account is unavailable"},
		{name: "negative effective uid", home: "/Users/example", available: true, uid: "501", euid: -1, want: "native user account is unavailable"},
		{name: "invalid uid", home: "/Users/example", available: true, uid: "invalid", euid: 501, want: "configured native account does not match the effective user"},
		{name: "overflow uid", home: "/Users/example", available: true, uid: "4294967296", euid: 501, want: "configured native account does not match the effective user"},
		{name: "uid mismatch", home: "/Users/example", available: true, uid: "502", euid: 501, want: "configured native account does not match the effective user"},
		{name: "home mismatch", home: "/Users/other", available: true, uid: "501", euid: 501, want: "configured native account does not match the effective user"},
	} {
		t.Run(test.name, func(t *testing.T) {
			home, uid, err := appconfig.AdmitConfiguredNativeAccount("/Users/example", appconfig.AccountObservation{Available: test.available, Home: test.home, UID: test.uid, EffectiveUID: test.euid, Err: test.lookupErr})
			if test.want != "" {
				if err == nil || err.Error() != test.want || home != "" || uid != 0 {
					t.Fatalf("rejection=%q/%d/%v", home, uid, err)
				}
				return
			}
			if err != nil || home != test.home || uid != uint32(test.euid) {
				t.Fatalf("admission=%q/%d/%v", home, uid, err)
			}
		})
	}
}

func TestNativeHomeAuthorityComparison(t *testing.T) {
	authority := func(path string, device, inode uint64, uid uint32) ports.NativeHomeLaunchAuthority {
		t.Helper()
		value, err := ports.NewNativeHomeLaunchAuthority(path, device, inode, uid)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := authority("/synthetic/home", 1, 2, 501)
	for _, test := range []struct {
		name  string
		after ports.NativeHomeLaunchAuthority
		want  bool
	}{
		{"same", authority("/synthetic/home", 1, 2, 501), true},
		{"path", authority("/synthetic/other", 1, 2, 501), false},
		{"device", authority("/synthetic/home", 3, 2, 501), false},
		{"inode", authority("/synthetic/home", 1, 3, 501), false},
		{"uid", authority("/synthetic/home", 1, 2, 502), false},
		{"unavailable", ports.NativeHomeLaunchAuthority{}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := appconfig.SameNativeHomeAuthority(before, test.after); got != test.want {
				t.Fatalf("same=%t want=%t", got, test.want)
			}
			if appconfig.SameNativeHomeAuthority(ports.NativeHomeLaunchAuthority{}, test.after) {
				t.Fatal("unavailable initial authority accepted")
			}
		})
	}
}
