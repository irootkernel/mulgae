package clean

import (
	"math"
	"sort"
	"time"
)

// Plan computes a dry-run plan from a fixed retention observation. It performs
// no I/O and never retains references to caller-owned slices.
func Plan(snapshot RetentionSnapshot) (CleanPlan, error) {
	snapshot = snapshot.Clone()
	if snapshot.Now.IsZero() {
		return CleanPlan{}, failure(FailureInvalidSnapshot, "now is required", nil)
	}
	if err := validateSnapshotIdentity(snapshot); err != nil {
		return CleanPlan{}, err
	}
	if snapshot.Policy.RetentionAgeSeconds < 0 || snapshot.Policy.MinAgeForSizeSeconds < 0 || snapshot.Policy.TargetBytes < 0 {
		return CleanPlan{}, failure(FailureInvalidSnapshot, "policy values must be non-negative", nil)
	}
	if snapshot.Policy.RetentionAgeSeconds > int64((1<<63-1)/int64(time.Second)) || snapshot.Policy.MinAgeForSizeSeconds > int64((1<<63-1)/int64(time.Second)) {
		return CleanPlan{}, failure(FailureInvalidSnapshot, "policy duration exceeds supported range", nil)
	}
	byID := make(map[string]RunObservation, len(snapshot.Runs))
	for _, run := range snapshot.Runs {
		if !canonicalRunID(run.RunID) || !canonicalSessionID(run.SessionID) {
			return CleanPlan{}, failure(FailureInvalidSnapshot, "run and session IDs must be canonical", nil)
		}
		if run.RegularFileBytes < 0 {
			return CleanPlan{}, failure(FailureInvalidSnapshot, "negative bytes for "+run.RunID, nil)
		}
		if run.kind() != RunKindPublication && run.kind() != RunKindDiagnosticOnly {
			return CleanPlan{}, failure(FailureInvalidSnapshot, "invalid run kind for "+run.RunID, nil)
		}
		if _, exists := byID[run.RunID]; exists {
			return CleanPlan{}, failure(FailureInvalidSnapshot, "duplicate run "+run.RunID, nil)
		}
		byID[run.RunID] = run
	}
	protected := map[string][]Reason{}
	seed := map[string]bool{}
	add := func(id string, reason Reason) {
		if _, ok := byID[id]; ok {
			protected[id] = addReason(protected[id], reason)
		}
	}
	for _, id := range snapshot.Policy.ExplicitKeepRunIDs {
		if !canonicalRunID(id) {
			return CleanPlan{}, failure(FailureInvalidSnapshot, "explicit keep run ID must be canonical", nil)
		}
		if _, ok := byID[id]; !ok {
			return CleanPlan{}, failure(FailureInvalidSnapshot, "explicit keep run is unknown", nil)
		}
		add(id, ReasonProtectedExplicit)
		seed[id] = true
	}
	for id, run := range byID {
		if run.Active {
			add(id, ReasonActive)
			seed[id] = true
		}
		if run.kind() == RunKindPublication && !run.Committed || run.kind() == RunKindDiagnosticOnly && run.DiagnosticProtected {
			add(id, ReasonUncommitted)
			seed[id] = true
		}
		if run.Corrupt {
			add(id, ReasonCorrupt)
			seed[id] = true
		}
	}
	newest := map[string]RunObservation{}
	for _, run := range byID {
		completed, ok := run.completion()
		if !ok {
			continue
		}
		old, exists := newest[run.SessionID]
		if !exists {
			newest[run.SessionID] = run
			continue
		}
		oldTime, _ := old.completion()
		if completed.After(oldTime) || (completed.Equal(oldTime) && run.RunID > old.RunID) {
			newest[run.SessionID] = run
		}
	}
	for _, run := range newest {
		add(run.RunID, ReasonNewestSession)
		seed[run.RunID] = true
	}

	sortEdges(snapshot.Edges)
	parentByChild := make(map[string]string, len(snapshot.Edges))
	for index := range snapshot.Edges {
		edge := &snapshot.Edges[index]
		if !canonicalRunID(edge.ParentRunID) || !canonicalRunID(edge.ChildRunID) || !canonicalSHA256(edge.SHA256) {
			return CleanPlan{}, failure(FailureInvalidGraph, "lineage edge identity or hash is invalid", nil)
		}
		if !canonicalEdgePath(edge.EdgePath) {
			return CleanPlan{}, failure(FailureInvalidPath, "unsafe lineage edge path", nil)
		}
		if !edge.Valid {
			continue
		}
		if edge.ParentRunID == edge.ChildRunID {
			edge.Valid = false
			continue
		}
		if parent, exists := parentByChild[edge.ChildRunID]; exists && parent != edge.ParentRunID {
			edge.Valid = false
			for prior := range snapshot.Edges {
				if snapshot.Edges[prior].ChildRunID == edge.ChildRunID {
					snapshot.Edges[prior].Valid = false
				}
			}
			continue
		}
		for ancestor := edge.ParentRunID; ancestor != ""; ancestor = parentByChild[ancestor] {
			if ancestor == edge.ChildRunID {
				edge.Valid = false
				break
			}
		}
		if edge.Valid {
			parentByChild[edge.ChildRunID] = edge.ParentRunID
		}
	}
	children := map[string][]LineageEdgeObservation{}
	undirected := map[string][]LineageEdgeObservation{}
	for _, edge := range snapshot.Edges {
		if !canonicalEdgePath(edge.EdgePath) {
			return CleanPlan{}, failure(FailureInvalidPath, "unsafe lineage edge path", nil)
		}
		_, parentOK := byID[edge.ParentRunID]
		_, childOK := byID[edge.ChildRunID]
		if !parentOK || !childOK {
			continue
		}
		undirected[edge.ParentRunID] = append(undirected[edge.ParentRunID], edge)
		undirected[edge.ChildRunID] = append(undirected[edge.ChildRunID], edge)
		if edge.Valid {
			children[edge.ChildRunID] = append(children[edge.ChildRunID], edge)
		}
	}
	protection := RetentionProtection{RetainedSeedRunIDs: sortedKeys(seed)}
	danglingRefs := []LineageEdgeRef{}
	for _, edge := range snapshot.Edges {
		_, parentOK := byID[edge.ParentRunID]
		_, childOK := byID[edge.ChildRunID]
		if !parentOK || !childOK {
			danglingRefs = appendEdgeRef(danglingRefs, edge.LineageEdgeRef)
		}
	}
	if len(danglingRefs) > 0 {
		ids := sortedKeysRuns(byID)
		for _, id := range ids {
			add(id, ReasonGraphAnomaly)
			seed[id] = true
		}
		protection.GraphAnomalyComponents = append(protection.GraphAnomalyComponents, GraphAnomalyComponent{
			AffectedRunIDs:  ids,
			LineageEdgeRefs: danglingRefs,
		})
	} else {
		seenComponents := map[string]bool{}
		for _, edge := range snapshot.Edges {
			_, parentOK := byID[edge.ParentRunID]
			_, childOK := byID[edge.ChildRunID]
			if edge.Valid && parentOK && childOK {
				continue
			}
			start := ""
			if parentOK {
				start = edge.ParentRunID
			} else if childOK {
				start = edge.ChildRunID
			}
			if start == "" {
				continue
			}
			if seenComponents[start] {
				for index := range protection.GraphAnomalyComponents {
					component := &protection.GraphAnomalyComponents[index]
					if containsString(component.AffectedRunIDs, start) {
						component.LineageEdgeRefs = appendEdgeRef(component.LineageEdgeRefs, edge.LineageEdgeRef)
						break
					}
				}
				continue
			}
			ids, refs := component(start, undirected)
			refs = appendEdgeRef(refs, edge.LineageEdgeRef)
			for _, id := range ids {
				add(id, ReasonGraphAnomaly)
				seed[id] = true
				seenComponents[id] = true
			}
			protection.GraphAnomalyComponents = append(protection.GraphAnomalyComponents, GraphAnomalyComponent{AffectedRunIDs: ids, LineageEdgeRefs: refs})
		}
	}
	// Follow valid child->parent edges from every retained seed. A path is
	// retained as evidence, independently for every descendant/ancestor pair.
	for _, descendant := range sortedKeys(seed) {
		type node struct {
			id   string
			path []LineageEdgeRef
		}
		queue := []node{{id: descendant}}
		visited := map[string]bool{descendant: true}
		for len(queue) > 0 {
			current := queue[0]
			queue = queue[1:]
			edges := append([]LineageEdgeObservation(nil), children[current.id]...)
			sortEdges(edges)
			for _, edge := range edges {
				parent := edge.ParentRunID
				path := append(append([]LineageEdgeRef(nil), current.path...), edge.LineageEdgeRef)
				if parent != descendant {
					add(parent, ReasonAncestor)
					protection.TransitiveAncestorProtection = append(protection.TransitiveAncestorProtection, AncestorProtection{AncestorRunID: parent, RetainedDescendantRunID: descendant, LineageEdgeRefs: path})
				}
				if !visited[parent] {
					visited[parent] = true
					queue = append(queue, node{id: parent, path: path})
				}
			}
		}
	}
	for id, run := range byID {
		if _, ok := run.completion(); !ok {
			add(id, ReasonMissingTime)
		}
	}
	protection.RetainedSeedRunIDs = sortedKeys(seed)
	sort.Slice(protection.TransitiveAncestorProtection, func(i, j int) bool {
		a, b := protection.TransitiveAncestorProtection[i], protection.TransitiveAncestorProtection[j]
		if a.RetainedDescendantRunID != b.RetainedDescendantRunID {
			return a.RetainedDescendantRunID < b.RetainedDescendantRunID
		}
		return a.AncestorRunID < b.AncestorRunID
	})
	sort.Slice(protection.GraphAnomalyComponents, func(i, j int) bool {
		a, b := protection.GraphAnomalyComponents[i].AffectedRunIDs, protection.GraphAnomalyComponents[j].AffectedRunIDs
		if len(a) == 0 || len(b) == 0 {
			return len(a) < len(b)
		}
		return a[0] < b[0]
	})

	now := snapshot.Now.UTC()
	retentionCutoff := now.Add(-time.Duration(snapshot.Policy.RetentionAgeSeconds) * time.Second)
	sizeCutoff := now.Add(-time.Duration(snapshot.Policy.MinAgeForSizeSeconds) * time.Second)
	if snapshot.ProtectedRegularFileBytes < 0 {
		return CleanPlan{}, failure(FailureInvalidSnapshot, "negative protected regular file bytes", nil)
	}
	initial := snapshot.ProtectedRegularFileBytes
	for _, run := range byID {
		if run.RegularFileBytes > math.MaxInt64-initial {
			return CleanPlan{}, failure(FailureInvalidSnapshot, "regular file byte total overflows int64", nil)
		}
		initial += run.RegularFileBytes
	}
	var ageCandidates, sizeCandidates []RunObservation
	for _, run := range byID {
		completed, ok := run.completion()
		if !ok || len(protected[run.RunID]) > 0 {
			continue
		}
		if completed.Before(retentionCutoff) {
			ageCandidates = append(ageCandidates, run)
			continue
		}
		if completed.After(sizeCutoff) {
			protected[run.RunID] = addReason(protected[run.RunID], ReasonYoung)
		} else {
			sizeCandidates = append(sizeCandidates, run)
		}
	}
	sortRuns(ageCandidates)
	sortRuns(sizeCandidates)
	ageSet := entries(ageCandidates, ReasonEligibleAge)
	ageBytes, ok := sum(ageCandidates)
	if !ok {
		return CleanPlan{}, failure(FailureInvalidSnapshot, "age byte total overflows int64", nil)
	}
	projected := initial - ageBytes
	var selectedSize []RunObservation
	for _, run := range sizeCandidates {
		if projected <= snapshot.Policy.TargetBytes {
			break
		}
		selectedSize = append(selectedSize, run)
		if run.RegularFileBytes > projected {
			return CleanPlan{}, failure(FailureInvalidSnapshot, "projected byte total underflows int64", nil)
		}
		projected -= run.RegularFileBytes
	}
	sizeBytes, ok := sum(selectedSize)
	if !ok {
		return CleanPlan{}, failure(FailureInvalidSnapshot, "size byte total overflows int64", nil)
	}
	selected := map[string]Reason{}
	for _, run := range ageCandidates {
		selected[run.RunID] = ReasonDeletedAge
	}
	for _, run := range selectedSize {
		selected[run.RunID] = ReasonDeletedSize
	}
	decisions := make([]RunDecision, 0, len(byID))
	for _, id := range sortedKeysRuns(byID) {
		reasons := append([]Reason(nil), protected[id]...)
		decision := "not_selected"
		if reason, ok := selected[id]; ok {
			if reason == ReasonDeletedAge {
				decision = "selected_age"
				reasons = addReason(reasons, ReasonEligibleAge)
				reasons = addReason(reasons, ReasonDeletedAge)
			} else {
				decision = "selected_size"
				reasons = addReason(reasons, ReasonEligibleSize)
				reasons = addReason(reasons, ReasonDeletedSize)
			}
		} else if len(reasons) > 0 {
			decision = "protected"
		} else if containsRun(ageCandidates, id) {
			decision = "eligible_age"
			reasons = []Reason{ReasonEligibleAge}
		} else if containsRun(sizeCandidates, id) {
			decision = "eligible_size"
			reasons = []Reason{ReasonEligibleSize}
		} else {
			reasons = []Reason{ReasonYoung}
		}
		decisions = append(decisions, RunDecision{RunID: id, Decision: decision, Reasons: sortReasons(reasons)})
	}
	outcomes := []Reason{}
	if projected > snapshot.Policy.TargetBytes {
		outcomes = []Reason{ReasonTargetProtected}
	}
	actions := actionsFor(ageCandidates, selectedSize)
	plannedBytes, ok := checkedAdd(ageBytes, sizeBytes)
	if !ok {
		return CleanPlan{}, failure(FailureInvalidSnapshot, "planned byte total overflows int64", nil)
	}
	plan := CleanPlan{SchemaVersion: SchemaVersion, Mode: "dry_run", Now: now.Format(time.RFC3339Nano), StoreEpoch: snapshot.StoreEpoch, InputPolicySHA256: snapshot.InputPolicySHA256, Policy: snapshot.Policy.clone(), RetentionProtection: protection, RunDecisions: decisions, DeleteSets: DeleteSets{AgeDeleteSet: ageSet, SizeDeleteSet: entries(selectedSize, ReasonEligibleSize)}, OrderedActions: actions, ByteAccounting: ByteAccounting{InitialRegularFileBytes: initial, AgeDeleteBytes: ageBytes, SizeDeleteBytes: sizeBytes, PlannedDeleteBytes: plannedBytes, ProjectedRegularFileBytes: projected, TargetBytes: snapshot.Policy.TargetBytes, TargetReached: projected <= snapshot.Policy.TargetBytes}, OutcomeReasons: outcomes}
	plan = plan.Clone()
	hash, err := PlanHash(plan)
	if err != nil {
		return CleanPlan{}, err
	}
	plan.PlanHash = hash
	return plan.Clone(), nil
}

func entries(runs []RunObservation, reason Reason) []DeleteSetEntry {
	result := make([]DeleteSetEntry, len(runs))
	for i, r := range runs {
		t, _ := r.completion()
		result[i] = DeleteSetEntry{RunID: r.RunID, CompletedAt: t.Format(time.RFC3339Nano), RegularFileBytes: r.RegularFileBytes, Reason: reason}
	}
	return result
}
func actionsFor(age, size []RunObservation) []OrderedAction {
	all := []struct {
		runs   []RunObservation
		phase  string
		reason Reason
	}{{age, "age", ReasonDeletedAge}, {size, "size", ReasonDeletedSize}}
	var result []OrderedAction
	n := 1
	for _, group := range all {
		for _, run := range group.runs {
			result = append(result, OrderedAction{n, group.phase, "tombstone", run.RunID, group.reason, 0}, OrderedAction{n + 1, group.phase, "delete", run.RunID, group.reason, run.RegularFileBytes})
			n += 2
		}
	}
	return result
}
func component(start string, graph map[string][]LineageEdgeObservation) ([]string, []LineageEdgeRef) {
	visited := map[string]bool{start: true}
	refs := map[string]LineageEdgeRef{}
	queue := []string{start}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for _, edge := range graph[id] {
			key := edgeKey(edge.LineageEdgeRef)
			refs[key] = edge.LineageEdgeRef
			next := edge.ParentRunID
			if next == id {
				next = edge.ChildRunID
			}
			if !visited[next] {
				visited[next] = true
				queue = append(queue, next)
			}
		}
	}
	ids := sortedKeys(visited)
	out := make([]LineageEdgeRef, 0, len(refs))
	for _, ref := range refs {
		out = append(out, ref)
	}
	sort.Slice(out, func(i, j int) bool { return edgeKey(out[i]) < edgeKey(out[j]) })
	return ids, out
}
func appendEdgeRef(refs []LineageEdgeRef, added LineageEdgeRef) []LineageEdgeRef {
	for _, ref := range refs {
		if edgeKey(ref) == edgeKey(added) {
			return refs
		}
	}
	refs = append(refs, added)
	sort.Slice(refs, func(i, j int) bool { return edgeKey(refs[i]) < edgeKey(refs[j]) })
	return refs
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
func edgeKey(e LineageEdgeRef) string {
	return e.ChildRunID + "\x00" + e.ParentRunID + "\x00" + e.EdgePath + "\x00" + e.SHA256
}
func sortEdges(es []LineageEdgeObservation) {
	sort.Slice(es, func(i, j int) bool { return edgeKey(es[i].LineageEdgeRef) < edgeKey(es[j].LineageEdgeRef) })
}
func sortRuns(r []RunObservation) {
	sort.Slice(r, func(i, j int) bool {
		a, _ := r[i].completion()
		b, _ := r[j].completion()
		return a.Before(b) || (a.Equal(b) && r[i].RunID < r[j].RunID)
	})
}
func sum(r []RunObservation) (int64, bool) {
	var n int64
	for _, v := range r {
		if v.RegularFileBytes > math.MaxInt64-n {
			return 0, false
		}
		n += v.RegularFileBytes
	}
	return n, true
}

func checkedAdd(left, right int64) (int64, bool) {
	if right > 0 && left > math.MaxInt64-right {
		return 0, false
	}
	return left + right, true
}
func containsRun(r []RunObservation, id string) bool {
	for _, v := range r {
		if v.RunID == id {
			return true
		}
	}
	return false
}
func canonicalEdgePath(path string) bool {
	if path == "" || len(path) > 4096 {
		return false
	}
	start := true
	for _, r := range path {
		if r == '/' {
			if start {
				return false
			}
			start = true
			continue
		}
		alnum := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
		if !(alnum || r == '_' || r == '.' || r == '-') || start && !alnum {
			return false
		}
		start = false
	}
	return !start
}
func sortedKeys(m map[string]bool) []string {
	r := make([]string, 0, len(m))
	for k := range m {
		r = append(r, k)
	}
	sort.Strings(r)
	return r
}
func sortedKeysRuns(m map[string]RunObservation) []string {
	r := make([]string, 0, len(m))
	for k := range m {
		r = append(r, k)
	}
	sort.Strings(r)
	return r
}
func addReason(r []Reason, add Reason) []Reason {
	for _, v := range r {
		if v == add {
			return r
		}
	}
	return append(r, add)
}
func sortReasons(r []Reason) []Reason {
	order := map[Reason]int{ReasonProtectedExplicit: 0, ReasonActive: 1, ReasonUncommitted: 2, ReasonCorrupt: 3, ReasonNewestSession: 4, ReasonAncestor: 5, ReasonGraphAnomaly: 6, ReasonMissingTime: 7, ReasonYoung: 8, ReasonEligibleAge: 9, ReasonEligibleSize: 10, ReasonDeletedAge: 11, ReasonDeletedSize: 12, ReasonTargetProtected: 13, ReasonStaleEpoch: 14, ReasonPartialResume: 15}
	sort.Slice(r, func(i, j int) bool { return order[r[i]] < order[r[j]] })
	return r
}

// ApplyPlan returns the effect-plan identity paired with a dry-run plan. The
// hash remains identical because mode and apply identity are excluded from the
// domain hash preimage.
func ApplyPlan(dryRun CleanPlan) (CleanPlan, error) {
	if dryRun.Mode != "dry_run" || dryRun.ApplyIdentity != nil {
		return CleanPlan{}, failure(FailureInvalidSnapshot, "apply identity requires a dry-run plan", nil)
	}
	hash, err := PlanHash(dryRun)
	if err != nil {
		return CleanPlan{}, err
	}
	if dryRun.PlanHash != "" && dryRun.PlanHash != hash {
		return CleanPlan{}, failure(FailureStalePlan, "dry-run plan hash does not match content", nil)
	}
	apply := dryRun.Clone()
	apply.Mode = "apply"
	apply.ApplyIdentity = &ApplyIdentity{
		DryRunPlanHash:            hash,
		ExpectedStoreEpoch:        apply.StoreEpoch,
		ExpectedInputPolicySHA256: apply.InputPolicySHA256,
	}
	apply.PlanHash, err = PlanHash(apply)
	if err != nil {
		return CleanPlan{}, err
	}
	return apply, nil
}
