// Package nftctl is the only place that executes the nft binary. It exists
// as an interface so the whole pipeline above it can be unit-tested with a
// fake, and so the project keeps its v1 promise of auditability: firewall
// state is applied via `nft -f` with a reviewable ruleset file, not opaque
// netlink calls (a netlink backend can implement Runner later if needed).
package nftctl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
)

// Runner abstracts nft for tests and future backends.
type Runner interface {
	// Check dry-runs the ruleset (`nft -c -f -`): full parse + kernel
	// validation without changing state.
	Check(ctx context.Context, ruleset []byte) error
	// Apply executes the ruleset (`nft -f -`) as one atomic transaction.
	Apply(ctx context.Context, ruleset []byte) error
	// CountSet returns the number of elements in a set (for status and
	// post-apply verification).
	CountSet(ctx context.Context, table, set string) (int, error)
}

// Exec runs the real nft binary.
type Exec struct {
	// Nft is the binary path; empty means "nft" from PATH. Distros place
	// it in /usr/sbin which may not be in a service's PATH, so packaging
	// sets this explicitly.
	Nft string
}

func (e Exec) bin() string {
	if e.Nft != "" {
		return e.Nft
	}
	return "nft"
}

func (e Exec) run(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, e.bin(), args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		// nft's stderr carries the line/column of a bad ruleset — that is
		// the actionable part, so it goes into the error.
		return nil, fmt.Errorf("%s %v: %w: %s", e.bin(), args, err, bytes.TrimSpace(errb.Bytes()))
	}
	return out.Bytes(), nil
}

func (e Exec) Check(ctx context.Context, ruleset []byte) error {
	_, err := e.run(ctx, ruleset, "-c", "-f", "-")
	return err
}

func (e Exec) Apply(ctx context.Context, ruleset []byte) error {
	_, err := e.run(ctx, ruleset, "-f", "-")
	return err
}

func (e Exec) CountSet(ctx context.Context, table, set string) (int, error) {
	out, err := e.run(ctx, nil, "-j", "list", "set", "inet", table, set)
	if err != nil {
		return 0, err
	}
	return ParseSetCount(out)
}

// ParseSetCount extracts the element count from `nft -j list set` output.
// Exported (rather than inlined) so the JSON contract with nft has direct
// unit tests against captured real output.
func ParseSetCount(jsonOut []byte) (int, error) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(jsonOut, &doc); err != nil {
		return 0, fmt.Errorf("parsing nft JSON: %w", err)
	}
	for _, obj := range doc.Nftables {
		raw, ok := obj["set"]
		if !ok {
			continue
		}
		var set struct {
			Elem []json.RawMessage `json:"elem"`
		}
		if err := json.Unmarshal(raw, &set); err != nil {
			return 0, fmt.Errorf("parsing set object: %w", err)
		}
		return len(set.Elem), nil
	}
	return 0, fmt.Errorf("no set object in nft output")
}
