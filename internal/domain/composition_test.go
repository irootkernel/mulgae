package domain

import "testing"

func TestCompositionFingerprintIsRoleOrderedAndExact(t *testing.T) {
	root, _ := ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	logicRun, _ := ParseRunID("r_019f596a-cfe5-7c9c-b82e-7149158243ba")
	securityRun, _ := ParseRunID("r_019f596a-cfe6-7c9c-b82e-7149158243ba")
	logicReview, _ := ParseReviewID("019f596a-d174-7321-b920-c2d312c82cc2")
	securityReview, _ := ParseReviewID("019f596a-d175-7321-b920-c2d312c82cc2")
	logicAttempt, _ := ParseAttemptID("a_019f596a-d048-79e7-b2b7-59822f012273")
	securityAttempt, _ := ParseAttemptID("a_019f596a-d049-79e7-b2b7-59822f012273")
	logic, _ := NewCompositionSource(RoleLogic, logicRun, logicReview, logicAttempt)
	security, _ := NewCompositionSource(RoleSecurity, securityRun, securityReview, securityAttempt)

	first, err := NewCompositionFingerprint(root, []CompositionSource{security, logic})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewCompositionFingerprint(root, []CompositionSource{logic, security})
	if err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatalf("fingerprint depends on caller order: %q != %q", first.String(), second.String())
	}
	if len(first.String()) != len("sha256:")+64 {
		t.Fatalf("fingerprint = %q", first.String())
	}
	if _, err := NewCompositionFingerprint(root, []CompositionSource{logic, logic}); err == nil {
		t.Fatal("duplicate role accepted")
	}
}

func TestCompositeContractEnums(t *testing.T) {
	if !RunTypeComposite.Valid() {
		t.Fatal("composite run type is invalid")
	}
	for _, state := range []CompositionState{CompositionCreated, CompositionRecovered, CompositionAlreadyCommitted, CompositionPublicationIncomplete, CompositionFailed} {
		if !state.Valid() {
			t.Fatalf("state %q is invalid", state)
		}
	}
	if got := len(CompositeReasonCodes()); got != 10 {
		t.Fatalf("reason code count = %d", got)
	}
}

func TestCompositionFingerprintRunIDIsStableAndDistinct(t *testing.T) {
	root, _ := ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	logicRun, _ := ParseRunID("r_019f596a-cfe5-7c9c-b82e-7149158243ba")
	securityRun, _ := ParseRunID("r_019f596a-cfe6-7c9c-b82e-7149158243ba")
	logicReview, _ := ParseReviewID("019f596a-d174-7321-b920-c2d312c82cc2")
	securityReview, _ := ParseReviewID("019f596a-d175-7321-b920-c2d312c82cc2")
	logicAttempt, _ := ParseAttemptID("a_019f596a-d048-79e7-b2b7-59822f012273")
	securityAttempt, _ := ParseAttemptID("a_019f596a-d049-79e7-b2b7-59822f012273")
	logic, _ := NewCompositionSource(RoleLogic, logicRun, logicReview, logicAttempt)
	security, _ := NewCompositionSource(RoleSecurity, securityRun, securityReview, securityAttempt)
	first, _ := NewCompositionFingerprint(root, []CompositionSource{logic})
	same, _ := NewCompositionFingerprint(root, []CompositionSource{logic})
	different, _ := NewCompositionFingerprint(root, []CompositionSource{logic, security})
	firstID, err := first.RunID()
	if err != nil {
		t.Fatal(err)
	}
	sameID, err := same.RunID()
	if err != nil {
		t.Fatal(err)
	}
	differentID, err := different.RunID()
	if err != nil {
		t.Fatal(err)
	}
	if firstID != sameID || firstID == differentID {
		t.Fatalf("derived IDs are not stable and distinct: %s %s %s", firstID, sameID, differentID)
	}
	if _, err := ParseRunID(firstID.String()); err != nil {
		t.Fatalf("derived ID is not canonical: %v", err)
	}
}
