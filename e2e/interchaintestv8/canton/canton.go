// SPDX-License-Identifier: Apache-2.0

// Package canton runs a local Canton sandbox and talks to its JSON Ledger API.
package canton

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
)

const (
	// sandboxStartTimeout bounds how long the sandbox may take to come up.
	sandboxStartTimeout = 5 * time.Minute
	// userID is the Ledger API user commands are submitted as. The sandbox runs without auth.
	userID = "e2e"
	// templateIDKey is the JSON field naming a template in commands and filters.
	templateIDKey = "templateId"
)

// Sandbox is a running Canton sandbox with one participant and one synchronizer.
type Sandbox struct {
	*Client
	cmd *exec.Cmd
}

// StartSandbox starts a Canton sandbox with the given DARs uploaded. It needs `dpm` on the PATH.
func StartSandbox(ctx context.Context, dars ...string) (*Sandbox, error) {
	dir, err := os.MkdirTemp("", "canton-sandbox-")
	if err != nil {
		return nil, err
	}
	portFile := filepath.Join(dir, "ports.json")

	// Every port is picked explicitly so that several sandboxes can run on one machine.
	args := []string{"sandbox", "--canton-port-file", portFile}
	var jsonAPIPort int
	for _, flag := range []string{
		"--json-api-port", "--ledger-api-port", "--admin-api-port",
		"--sequencer-public-port", "--sequencer-admin-port", "--mediator-admin-port",
	} {
		port, err := freePort()
		if err != nil {
			return nil, err
		}
		if flag == "--json-api-port" {
			jsonAPIPort = port
		}
		args = append(args, flag, strconv.Itoa(port))
	}
	for _, dar := range dars {
		path, err := filepath.Abs(dar)
		if err != nil {
			return nil, err
		}
		args = append(args, "--dar", path)
	}

	cmd := exec.Command("dpm", args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// dpm runs Canton as a child JVM; a process group lets Stop take both down.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start dpm sandbox: %w", err)
	}
	sandbox := &Sandbox{
		Client: &Client{url: fmt.Sprintf("http://127.0.0.1:%d", jsonAPIPort)},
		cmd:    cmd,
	}

	// Canton writes the port file once every API is serving.
	deadline := time.Now().Add(sandboxStartTimeout)
	for {
		if _, err := os.Stat(portFile); err == nil {
			return sandbox, nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			sandbox.Stop()
			return nil, fmt.Errorf("canton sandbox did not start within %s", sandboxStartTimeout)
		}
		time.Sleep(time.Second)
	}
}

// Stop kills the sandbox.
func (s *Sandbox) Stop() {
	_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
	_ = s.cmd.Wait()
	_ = os.RemoveAll(s.cmd.Dir)
}

func freePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

// Client talks to the JSON Ledger API of a participant.
type Client struct {
	url string
}

// URL returns the base URL of the JSON Ledger API.
func (c *Client) URL() string {
	return c.url
}

// Contract is a created contract. Daml `Int` fields are encoded as decimal strings.
type Contract struct {
	ContractID string          `json:"contractId"`
	TemplateID string          `json:"templateId"`
	Argument   json.RawMessage `json:"createArgument"`
}

// Is reports whether the contract is an instance of the template `Module:Entity`.
func (c Contract) Is(template string) bool {
	return strings.HasSuffix(c.TemplateID, ":"+template)
}

// Transaction is a committed transaction.
type Transaction struct {
	UpdateID string
	Created  []Contract
}

// Create builds a command that creates a contract.
func Create(templateID string, arguments any) any {
	return map[string]any{"CreateCommand": map[string]any{
		templateIDKey:     templateID,
		"createArguments": arguments,
	}}
}

// Exercise builds a command that exercises a choice on a contract.
func Exercise(templateID, contractID, choice string, argument any) any {
	return map[string]any{"ExerciseCommand": map[string]any{
		templateIDKey:    templateID,
		"contractId":     contractID,
		"choice":         choice,
		"choiceArgument": argument,
	}}
}

func (c *Client) post(ctx context.Context, path string, body, out any) error {
	bz, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+path, bytes.NewReader(bz))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBz, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s failed with %s: %s", path, resp.Status, respBz)
	}
	return json.Unmarshal(respBz, out)
}

// AllocateParty allocates a party on the participant and returns its id.
func (c *Client) AllocateParty(ctx context.Context, hint string) (string, error) {
	var resp struct {
		PartyDetails struct {
			Party string `json:"party"`
		} `json:"partyDetails"`
	}
	err := c.post(ctx, "/v2/parties", map[string]any{"partyIdHint": hint, "identityProviderId": ""}, &resp)
	return resp.PartyDetails.Party, err
}

// Submit submits commands as one transaction and waits for it to commit. `commands` and
// `disclosed` are the JSON arrays of a Ledger API submission; `disclosed` may be nil.
func (c *Client) Submit(ctx context.Context, actAs, readAs []string, commands, disclosed any) (*Transaction, error) {
	var resp struct {
		Transaction struct {
			UpdateID string `json:"updateId"`
			Events   []struct {
				CreatedEvent *Contract `json:"CreatedEvent"`
			} `json:"events"`
		} `json:"transaction"`
	}
	err := c.post(ctx, "/v2/commands/submit-and-wait-for-transaction", map[string]any{
		"commands": map[string]any{
			"commandId":          uuid.NewString(),
			"userId":             userID,
			"actAs":              actAs,
			"readAs":             readAs,
			"commands":           commands,
			"disclosedContracts": disclosed,
		},
	}, &resp)
	if err != nil {
		return nil, err
	}

	tx := &Transaction{UpdateID: resp.Transaction.UpdateID}
	for _, event := range resp.Transaction.Events {
		if event.CreatedEvent != nil {
			tx.Created = append(tx.Created, *event.CreatedEvent)
		}
	}
	return tx, nil
}

// ActiveContracts returns the active contracts of a template that `party` can see.
func (c *Client) ActiveContracts(ctx context.Context, party, templateID string) ([]Contract, error) {
	resp, err := http.Get(c.url + "/v2/state/ledger-end")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var ledgerEnd struct {
		Offset int64 `json:"offset"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ledgerEnd); err != nil {
		return nil, err
	}

	var entries []struct {
		ContractEntry struct {
			JsActiveContract *struct {
				CreatedEvent Contract `json:"createdEvent"`
			} `json:"JsActiveContract"`
		} `json:"contractEntry"`
	}
	err = c.post(ctx, "/v2/state/active-contracts", map[string]any{
		"activeAtOffset": ledgerEnd.Offset,
		"eventFormat": map[string]any{
			"filtersByParty": map[string]any{party: map[string]any{"cumulative": []any{map[string]any{
				"identifierFilter": map[string]any{"TemplateFilter": map[string]any{"value": map[string]any{
					templateIDKey:             templateID,
					"includeCreatedEventBlob": false,
				}}},
			}}}},
			"verbose": false,
		},
	}, &entries)
	if err != nil {
		return nil, err
	}

	var contracts []Contract
	for _, entry := range entries {
		if active := entry.ContractEntry.JsActiveContract; active != nil {
			contracts = append(contracts, active.CreatedEvent)
		}
	}
	return contracts, nil
}
