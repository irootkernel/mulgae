package report

import "testing"

func TestNewServiceRejectsNilAndTypedNilReader(t *testing.T) {
	var typedNil *reportReader
	for name, opener := range map[string]SnapshotOpener{
		"nil":       nil,
		"typed nil": typedNil,
	} {
		t.Run(name, func(t *testing.T) {
			if service, err := NewService(opener); err == nil || service != nil {
				t.Fatalf("NewService() = %#v, %v; want nil service and error", service, err)
			}
		})
	}
}
