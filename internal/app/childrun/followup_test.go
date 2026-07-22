package childrun

import (
	"context"
	"strings"
	"testing"

	appfollowup "github.com/irootkernel/kkachi-agent-review/internal/app/followup"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

func TestNewFollowupExecutorRejectsIncompleteAuthority(t *testing.T) {
	if executor, err := NewFollowupExecutor(nil, nil, nil, nil, nil, nil, ports.AnchoredRoot{}, FollowupExecutorConfig{}); executor != nil || err == nil {
		t.Fatal("NewFollowupExecutor accepted incomplete authority")
	}
}

func TestExecuteFollowupRejectsSessionMismatchBeforeExecution(t *testing.T) {
	t.Parallel()

	sourceSessionID := childrunSessionID(t, "s_019f596a-cfb0-7c67-b265-f37053d51ccf")
	executionSessionID := childrunSessionID(t, "s_019f596a-cfb1-7c67-b265-f37053d51ccf")
	execution := appfollowup.Execution{
		SessionID: executionSessionID,
		Source: appfollowup.VerifiedSource{
			ProviderInstance: "fake.logic",
			SessionID:        sourceSessionID,
			RunID:            childrunRunID(t, "r_019f596a-cfb2-7c67-b265-f37053d51ccf"),
			ReviewID:         childrunReviewID(t, "019f596a-cfb3-7c67-b265-f37053d51ccf"),
			Finding:          appfollowup.SourceFinding{ID: "F001", Role: domain.RoleLogic},
		},
		Current: appfollowup.CurrentTarget{Identity: childrunTarget(t)},
	}

	_, err := (&FollowupExecutor{}).ExecuteFollowup(context.Background(), execution)
	if err == nil || !strings.Contains(err.Error(), "trusted execution identity is invalid") {
		t.Fatalf("ExecuteFollowup session-mismatch error = %v, want identity rejection", err)
	}
}
