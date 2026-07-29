package providercli

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/ports"
)

type kimiLoginRunner struct {
	request ports.ProcessRequest
}

func (runner *kimiLoginRunner) Run(_ context.Context, request ports.ProcessRequest) (ports.ProcessObservation, error) {
	runner.request = request
	receipt, err := ports.NewStdinWriteReceipt(0, 0, testStdinDigest(nil), true)
	if err != nil {
		return ports.ProcessObservation{}, err
	}
	code := 0
	return ports.NewProcessObservation(nil, nil, &code, ports.ProcessTerminationExited, receipt, time.Unix(1, 0).UTC(), time.Unix(2, 0).UTC())
}

type kimiLoginVerifier struct {
	calls int
}

func (verifier *kimiLoginVerifier) VerifyProviderSpawn(_ context.Context, definition RuntimeDefinition) error {
	verifier.calls++
	return nil
}

func TestKimiLoginAuthenticatorRunsNativeLoginWithClosedEnvironment(t *testing.T) {
	nativeHome := t.TempDir()
	dataHome := t.TempDir()
	runner := &kimiLoginRunner{}
	verifier := &kimiLoginVerifier{}
	authenticator, err := NewKimiLoginAuthenticator(runner, verifier, nativeHome, dataHome)
	if err != nil {
		t.Fatal(err)
	}
	definition := testProfile(t, FamilyKimi, "kimi-main", "kimi-lane", "1.1.4", "")
	if err := authenticator.LoginProvider(context.Background(), definition); err != nil {
		t.Fatal(err)
	}
	request := runner.request
	if verifier.calls != 1 || request.Executable() != definition.Executable() ||
		!reflect.DeepEqual(request.Argv(), []string{definition.Executable(), "login"}) ||
		request.WorkingDirectory() != nativeHome || request.Timeout() != kimiLoginTimeout ||
		request.ConcurrencyKey().String() != "kimi-login" {
		t.Fatalf("login request = %#v verifier calls=%d", request, verifier.calls)
	}
	wantEnvironment := map[string]string{
		"HOME": nativeHome, "KIMI_CODE_HOME": dataHome,
		"PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "PWD": nativeHome,
	}
	gotEnvironment := make(map[string]string)
	for _, variable := range request.Environment() {
		gotEnvironment[variable.Name()] = variable.Value()
	}
	if !reflect.DeepEqual(gotEnvironment, wantEnvironment) {
		t.Fatalf("login environment = %#v", gotEnvironment)
	}
}
