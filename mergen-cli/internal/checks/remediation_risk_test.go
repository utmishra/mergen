package checks

import (
	"strings"
	"testing"
)

func TestEveryFixHasRiskClassification(t *testing.T) {
	for _, check := range All() {
		fix := check.Fix()
		if fix == nil {
			continue
		}
		if fix.Risk == "" {
			t.Errorf("check %s (%s) has an unclassified fix", check.CISID(), check.Name())
		}
	}
}

func TestHighImpactFixesAreNeverBatchSafe(t *testing.T) {
	highImpactIDs := map[string]bool{
		"2.3.3.1": true, // Screen Sharing
		"2.3.3.4": true, // Remote Login
		"5.2.1":   true, // password lockout policy
		"5.2.2":   true, // minimum password length
		"5.4":     true, // sudo timeout
		"5.5":     true, // sudo TTY policy
		"5.6":     true, // root account
		"5.11":    true, // sudo logging
	}

	for _, check := range All() {
		fix := check.Fix()
		if fix != nil && highImpactIDs[check.CISID()] && fix.Risk == RiskSafe {
			t.Errorf("high-impact check %s (%s) is batch safe", check.CISID(), check.Name())
		}
	}
}

func TestBatchSafeFixesDoNotContainDestructiveShellPatterns(t *testing.T) {
	patterns := []string{
		"rm -rf",
		"/etc/sudoers",
		"dsenableroot",
		"/users/root",
		"com.openssh.sshd",
		"com.apple.screensharing",
		"kickstart -deactivate",
	}

	for _, check := range All() {
		fix := check.Fix()
		if fix == nil || fix.Risk != RiskSafe {
			continue
		}
		command := strings.ToLower(fix.Command)
		for _, pattern := range patterns {
			if strings.Contains(command, pattern) {
				t.Errorf("batch-safe check %s contains destructive pattern %q", check.CISID(), pattern)
			}
		}
	}
}

func TestUnknownFixDefaultsToConfirmation(t *testing.T) {
	if got := remediationRiskFor("future.check"); got != RiskConfirm {
		t.Fatalf("unknown fix risk = %q, want %q", got, RiskConfirm)
	}
}
