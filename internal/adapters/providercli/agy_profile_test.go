package providercli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestAgyPermissionGrantPreservesNativeOperandParentheses(t *testing.T) {
	// ParseGrantString uses this anchored grammar in the two supported codecs.
	native := regexp.MustCompile(`^([^(]+)\((.*)\)$`)
	for _, operand := range []string{
		"/source/project (text)/README.md",
		"/source/path with 'apostrophe' (nested (text))",
		"/source/ending)",
		"/source/name),command(other)",
	} {
		command := agyReadCommandGuard + "git --no-pager show 'HEAD:" + operand + "'"
		for _, grant := range []string{"read_file(" + operand + ")", "command(" + command + ")"} {
			parsed := native.FindStringSubmatch(grant)
			if !validAgyPermissionGrant(grant) || len(parsed) != 3 || parsed[1]+"("+parsed[2]+")" != grant {
				t.Fatalf("native grant did not round-trip: %q", grant)
			}
		}
		profile, err := installAgyInvocationProfile(agyProfileTestHome(t), agyTrustedReadPlan{files: []string{operand}, commands: []string{command}}, "1.4.2")
		if err != nil {
			t.Fatal(err)
		}
		if err := profile.validateAfterRun(); err != nil {
			t.Fatal(err)
		}
		if err := profile.remove(); err != nil {
			t.Fatal(err)
		}
	}
	for _, grant := range []string{"read_file(relative)", "read_file(/source/a\nother)", "command(x\r)", "command(x\x00)", "unknown(/source/a)", "command()", "command(x)trailing"} {
		if validAgyPermissionGrant(grant) {
			t.Fatalf("unsafe grant admitted: %q", grant)
		}
	}
}

func agyProfileTestHome(t *testing.T) string {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(home, 0700); err != nil {
		t.Fatal(err)
	}
	return home
}

func TestAgyCommandPolicyRequiresGuardAndKnownCodec(t *testing.T) {
	const guarded = "MULGAE_READ_GUARD[1]=1 git --no-pager show 'HEAD:a b'"
	for _, item := range []struct {
		name, command, version string
		wantError              bool
	}{
		{"guarded", guarded, "1.4.0", false},
		{"guarded known 1.4.2", guarded, "1.4.2", false},
		{"bare", "git --no-pager show 'HEAD:a b'", "1.4.0", true},
		{"unknown command codec", guarded, "1.4.1", true},
		{"minimum is not codec proof", guarded, "1.2.9", true},
		{"command-free unknown codec", "", "1.4.1", false},
		{"command-free floor codec", "", "1.2.9", false},
	} {
		t.Run(item.name, func(t *testing.T) {
			plan := agyTrustedReadPlan{}
			if item.command != "" {
				plan.commands = []string{item.command}
			}
			profile, err := installAgyInvocationProfile(agyProfileTestHome(t), plan, item.version)
			if profile != nil {
				defer profile.remove()
			}
			if (err != nil) != item.wantError {
				t.Fatalf("profile admission error=%v, wantError=%t", err, item.wantError)
			}
			if err != nil {
				return
			}
			var settings agyNativeSettings
			if err := json.Unmarshal(profile.settings, &settings); err != nil {
				t.Fatal(err)
			}
			fallbackDenied := false
			for _, grant := range settings.Permissions.Deny {
				fallbackDenied = fallbackDenied || grant == "command(1)"
			}
			if fallbackDenied != (item.command != "") {
				t.Fatal("numeric fallback deny does not follow command authority")
			}
			if !bytes.Contains(profile.agentContent, []byte("`MULGAE_READ_GUARD[1]=1 `")) {
				t.Fatal("agent omitted exact command translation")
			}
			if err := profile.validateAfterRun(); err != nil {
				t.Fatal(err)
			}
			if item.command != "" {
				agyMutatePolicy(t, profile, func(fields map[string]any) {
					fields["permissions"].(map[string]any)["deny"] = agyCredentialDenyGrants(profile.geminiDir)
				})
				if profile.validateAfterRun() == nil {
					t.Fatal("native fallback deny removal went undetected")
				}
			}
		})
	}
	old := runtimeSafetyPolicyWithIdentity(RuntimeSafetyPolicy{family: CredentialSourceAgy, bytes: []byte("{\"family\":\"agy\",\"protocol\":\"stream-json\",\"credential\":\"disposable-file-token\",\"permissions\":\"request-review\",\"agent_inheritance\":false}\n")})
	current, err := RuntimeSafetyPolicyForFamily(CredentialSourceAgy)
	if err != nil || old.identity == current.identity {
		t.Fatal("old native command admission retained qualification identity", err)
	}
}

func TestAgyProfileAuthorsOnlyIsolatedPolicyAndAuditsSparseCodec(t *testing.T) {
	for _, version := range []string{"1.4.0", "1.4.2", "1.4.1"} {
		t.Run(version, func(t *testing.T) {
			home := agyProfileTestHome(t)
			plan := agyTrustedReadPlan{files: []string{"/source/a"}}
			profile, err := installAgyInvocationProfile(home, plan, version)
			if err != nil {
				t.Fatal(err)
			}
			defer profile.remove()
			if err := profile.validateAfterRun(); err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(profile.agentContent, []byte("inheritCustomizations: false\ninheritMcp: false\n")) || !bytes.Contains(profile.agentContent, []byte("  - view_file\n  - run_command\n")) {
				t.Fatal("agent inheritance or tool catalog changed")
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(profile.settings, &fields); err != nil {
				t.Fatal(err)
			}
			delete(fields, "toolPermission")
			delete(fields, "allowNonWorkspaceAccess")
			sparse, _ := json.Marshal(fields)
			if err := os.WriteFile(filepath.Join(home, profile.settingsPath), sparse, 0600); err != nil {
				t.Fatal(err)
			}
			err = profile.validateAfterRun()
			// Sparse omissions stay accepted only for the two established
			// codec versions; excluded intermediates such as 1.4.1 and the
			// 1.2.9 floor fail closed on the same drifted settings.
			if (err == nil) != (version == "1.4.0" || version == "1.4.2") {
				t.Fatalf("codec=%s error=%v", version, err)
			}
		})
	}
}
func TestAgyProfileAdmitsNative142OmittedEmptyAllowOnly(t *testing.T) {
	for _, item := range []struct {
		name, version string
		files         []string
		allow         any
		omit          bool
		wantOK        bool
	}{
		{name: "native empty omission", version: "1.4.2", omit: true, wantOK: true},
		{name: "old codec not established", version: "1.4.0", omit: true},
		{name: "unknown codec", version: "1.4.1", omit: true},
		{name: "floor is not codec", version: "1.2.9", omit: true},
		{name: "nonempty omission", version: "1.4.2", files: []string{"/source/README.md"}, omit: true},
		{name: "null is not omission", version: "1.4.2"},
		{name: "added permission", version: "1.4.2", allow: []string{"read_file(/other)"}},
	} {
		t.Run(item.name, func(t *testing.T) {
			profile, err := installAgyInvocationProfile(agyProfileTestHome(t), agyTrustedReadPlan{files: item.files}, item.version)
			if err != nil {
				t.Fatal(err)
			}
			defer profile.remove()
			agyMutatePolicy(t, profile, func(fields map[string]any) {
				permissions := fields["permissions"].(map[string]any)
				if item.omit {
					delete(permissions, "allow")
				} else {
					permissions["allow"] = item.allow
				}
			})
			if err := profile.validateAfterRun(); (err == nil) != item.wantOK {
				t.Fatalf("native allow omission: %v, want accepted=%t", err, item.wantOK)
			}
		})
	}
}

func TestAgyProfileRejectsPolicyAndFileDrift(t *testing.T) {
	cases := map[string]func(*testing.T, *agyInvocationProfile){
		"null mode": func(t *testing.T, p *agyInvocationProfile) {
			agyMutatePolicy(t, p, func(m map[string]any) { m["toolPermission"] = nil })
		},
		"unsafe mode": func(t *testing.T, p *agyInvocationProfile) {
			agyMutatePolicy(t, p, func(m map[string]any) { m["toolPermission"] = "yolo" })
		},
		"outside workspace": func(t *testing.T, p *agyInvocationProfile) {
			agyMutatePolicy(t, p, func(m map[string]any) { m["allowNonWorkspaceAccess"] = true })
		},
		"unknown top-level": func(t *testing.T, p *agyInvocationProfile) {
			agyMutatePolicy(t, p, func(m map[string]any) { m["unsafe"] = true })
		},
		"unknown permission": func(t *testing.T, p *agyInvocationProfile) {
			agyMutatePolicy(t, p, func(m map[string]any) { m["permissions"].(map[string]any)["ask"] = []string{"command(*)"} })
		},
		"missing empty allow": func(t *testing.T, p *agyInvocationProfile) {
			agyMutatePolicy(t, p, func(m map[string]any) { delete(m["permissions"].(map[string]any), "allow") })
		},
		"null grants": func(t *testing.T, p *agyInvocationProfile) {
			agyMutatePolicy(t, p, func(m map[string]any) { m["permissions"].(map[string]any)["allow"] = nil })
		},
		"weakened deny": func(t *testing.T, p *agyInvocationProfile) {
			agyMutatePolicy(t, p, func(m map[string]any) { m["permissions"].(map[string]any)["deny"] = []string{} })
		},
		"agent rewrite": func(t *testing.T, p *agyInvocationProfile) {
			if err := os.WriteFile(filepath.Join(p.geminiDir, p.agentPath), []byte("other"), 0600); err != nil {
				t.Fatal(err)
			}
		},
		"MCP server": func(t *testing.T, p *agyInvocationProfile) {
			if err := os.WriteFile(filepath.Join(p.geminiDir, p.mcpPath), []byte(`{"mcpServers":{"bad":{}}}`), 0600); err != nil {
				t.Fatal(err)
			}
		},
		"symlink leaf": func(t *testing.T, p *agyInvocationProfile) {
			name := filepath.Join(p.geminiDir, p.settingsPath)
			if err := os.Remove(name); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("../config/mcp_config.json", name); err != nil {
				t.Fatal(err)
			}
		},
		"parent substitution": func(t *testing.T, p *agyInvocationProfile) {
			name := filepath.Join(p.geminiDir, "config")
			if err := os.Rename(name, name+"-old"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("config-old", name); err != nil {
				t.Fatal(err)
			}
		},
		"hardlink": func(t *testing.T, p *agyInvocationProfile) {
			if err := os.Link(filepath.Join(p.geminiDir, p.settingsPath), filepath.Join(p.geminiDir, "linked")); err != nil {
				t.Fatal(err)
			}
		},
		"mode": func(t *testing.T, p *agyInvocationProfile) {
			if err := os.Chmod(filepath.Join(p.geminiDir, p.settingsPath), 0644); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := installAgyInvocationProfile(agyProfileTestHome(t), agyPromptBoundReadPlan(), "1.4.0")
			if err != nil {
				t.Fatal(err)
			}
			defer p.remove()
			mutate(t, p)
			if p.validateAfterRun() == nil {
				t.Fatal("accepted profile drift")
			}
		})
	}
}
func agyMutatePolicy(t *testing.T, p *agyInvocationProfile, mutate func(map[string]any)) {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(p.settings, &m); err != nil {
		t.Fatal(err)
	}
	mutate(m)
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.geminiDir, p.settingsPath), data, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestAgyProfileRollbackAndRepeatedInvocationsPreserveForeignFiles(t *testing.T) {
	home := agyProfileTestHome(t)
	if err := os.MkdirAll(filepath.Join(home, "config"), 0700); err != nil {
		t.Fatal(err)
	}
	conflict := filepath.Join(home, "config", "mcp_config.json")
	if err := os.WriteFile(conflict, []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := installAgyInvocationProfile(home, agyPromptBoundReadPlan(), "1.4.0"); err == nil {
		t.Fatal("overwrote pre-existing MCP config")
	}
	if data, err := os.ReadFile(conflict); err != nil || string(data) != "foreign" {
		t.Fatal("rollback removed foreign file")
	}
	if _, err := os.Lstat(filepath.Join(home, "antigravity-cli/settings.json")); !os.IsNotExist(err) {
		t.Fatal("partial settings not rolled back")
	}
	if err := os.Remove(conflict); err != nil {
		t.Fatal(err)
	}
	var previous string
	for i := 0; i < 2; i++ {
		p, err := installAgyInvocationProfile(home, agyPromptBoundReadPlan(), "1.4.0")
		if err != nil {
			t.Fatal(err)
		}
		if p.agentName == previous {
			t.Fatal("reused agent identity")
		}
		previous = p.agentName
		cache := filepath.Join(home, "config", "native-cache")
		if err := os.WriteFile(cache, []byte("native"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := p.remove(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(cache); err != nil {
			t.Fatal("removed unrelated native cache")
		}
	}
}
