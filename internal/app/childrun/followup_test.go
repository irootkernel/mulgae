package childrun

import (
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

func TestNewFollowupExecutorRejectsIncompleteAuthority(t *testing.T) {
	if executor, err := NewFollowupExecutor(nil, nil, nil, nil, nil, nil, ports.AnchoredRoot{}, FollowupExecutorConfig{}); executor != nil || err == nil {
		t.Fatal("NewFollowupExecutor accepted incomplete authority")
	}
}
