// SPDX-License-Identifier: Apache-2.0

package chainconfig

import (
	"context"
	"crypto/ecdsa"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/cosmos/interchaintest/v11/testutil"

	"github.com/lfdt-ibc/ibc-contracts/e2e/v8/testvalues"
)

const (
	lineaProjectName = "linea"

	defaultLineaChainID uint64 = 1339
)

//go:embed testdata/linea
var lineaAssets embed.FS

var lineaServices = []string{"besu", "maru"}

// LineaChain is a single-validator Linea network: Maru, Linea's QBFT consensus client, driving a Besu execution client.
type LineaChain struct {
	// RPC is the execution client's RPC endpoint.
	RPC string
	// BeaconAPI is Maru's beacon API endpoint, which serves the sealed beacon blocks.
	BeaconAPI string
	Faucet    *ecdsa.PrivateKey

	projectName string
	projectDir  string
}

func (c LineaChain) WaitForTransactionHandling(ctx context.Context) error {
	return waitForBesuTransactionHandling(ctx, c.RPC, c.Faucet)
}

// SpinUpLinea starts the embedded Linea fixture.
func SpinUpLinea(ctx context.Context) (chain LineaChain, err error) {
	faucet, err := crypto.HexToECDSA(testvalues.E2EDeployerPrivateKeyHex)
	if err != nil {
		return LineaChain{}, fmt.Errorf("parse linea faucet key: %w", err)
	}

	projectDir, err := os.MkdirTemp("", lineaProjectName+"-*")
	if err != nil {
		return LineaChain{}, fmt.Errorf("create linea temp dir: %w", err)
	}

	chain = LineaChain{Faucet: faucet, projectName: filepath.Base(projectDir), projectDir: projectDir}
	// The error returns reset chain, so the cleanup keeps its own copy.
	cleanupChain := chain
	defer func() {
		if err != nil {
			if logErr := cleanupChain.DumpLogs(context.Background()); logErr != nil {
				fmt.Printf("failed to dump linea logs after startup error: %v\n", logErr)
			}
			cleanupChain.Destroy(context.Background())
		}
	}()

	sub, err := fs.Sub(lineaAssets, "testdata/linea")
	if err != nil {
		return LineaChain{}, err
	}
	if err := os.CopyFS(projectDir, sub); err != nil {
		return LineaChain{}, fmt.Errorf("materialize linea assets: %w", err)
	}
	for _, genesis := range []string{"genesis-besu.json", "genesis-maru.json"} {
		if err := patchLineaGenesis(filepath.Join(projectDir, genesis), defaultLineaChainID); err != nil {
			return LineaChain{}, fmt.Errorf("patch %s: %w", genesis, err)
		}
	}

	if _, err := chain.runCompose(ctx, "up", "--detach"); err != nil {
		return LineaChain{}, fmt.Errorf("start linea compose stack: %w", err)
	}

	if chain.RPC, err = chain.hostEndpoint(ctx, "besu", "8545"); err != nil {
		return LineaChain{}, err
	}
	if chain.BeaconAPI, err = chain.hostEndpoint(ctx, "maru", "8080"); err != nil {
		return LineaChain{}, err
	}

	if err := chain.waitForReady(ctx); err != nil {
		return LineaChain{}, fmt.Errorf("wait for linea readiness: %w", err)
	}
	if err := chain.WaitForTransactionHandling(ctx); err != nil {
		return LineaChain{}, fmt.Errorf("wait for linea transaction handling: %w", err)
	}

	return chain, nil
}

func (c LineaChain) Destroy(ctx context.Context) {
	if _, err := c.runCompose(ctx, "down", "--volumes", "--remove-orphans"); err != nil {
		fmt.Printf("failed to tear down linea stack: %v\n", err)
	}
	if err := os.RemoveAll(c.projectDir); err != nil {
		fmt.Printf("failed to remove linea temp dir %s: %v\n", c.projectDir, err)
	}
}

func (c LineaChain) DumpLogs(ctx context.Context) error {
	logs, err := c.runCompose(ctx, append([]string{"logs", "--no-color"}, lineaServices...)...)
	if len(logs) > 0 {
		fmt.Print(string(logs))
	}
	return err
}

// LineaValidatorKey returns the key of the only validator of the embedded Linea fixture.
func LineaValidatorKey() (*ecdsa.PrivateKey, error) {
	keyHex, err := lineaAssets.ReadFile("testdata/linea/maru-key")
	if err != nil {
		return nil, fmt.Errorf("read maru key: %w", err)
	}
	// Maru stores the key as a libp2p protobuf: a secp256k1 key type prefix followed by the 32-byte key.
	keyBz, err := hexutil.Decode(strings.TrimSpace(string(keyHex)))
	if err != nil {
		return nil, fmt.Errorf("decode maru key: %w", err)
	}
	if len(keyBz) < 32 {
		return nil, fmt.Errorf("maru key has %d bytes, want at least 32", len(keyBz))
	}
	return crypto.ToECDSA(keyBz[len(keyBz)-32:])
}

func (c LineaChain) runCompose(ctx context.Context, args ...string) ([]byte, error) {
	return runDockerCompose(ctx, c.projectName, c.projectDir, args...)
}

// hostEndpoint returns the host URL that the container port of service is published on.
func (c LineaChain) hostEndpoint(ctx context.Context, service, port string) (string, error) {
	output, err := c.runCompose(ctx, "port", service, port)
	if err != nil {
		return "", fmt.Errorf("resolve %s port %s: %w", service, port, err)
	}
	_, hostPort, ok := strings.Cut(strings.TrimSpace(string(output)), ":")
	if !ok {
		return "", fmt.Errorf("resolve %s port %s: unexpected output %q", service, port, output)
	}
	return "http://127.0.0.1:" + hostPort, nil
}

// patchLineaGenesis sets the chain ID and, for the execution genesis, a timestamp a minute in the past. Besu only
// builds the block Maru asks for if its timestamp is after the genesis one, and Maru's clock in the Docker VM can
// trail the host's by seconds. With a genesis at the host's current time, Maru has failed to produce its first block.
func patchLineaGenesis(path string, chainID uint64) error {
	contents, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var genesis map[string]any
	if err := json.Unmarshal(contents, &genesis); err != nil {
		return err
	}
	if config, ok := genesis["config"].(map[string]any); ok && config["chainId"] != nil {
		config["chainId"] = chainID
		genesis["timestamp"] = hexutil.EncodeUint64(uint64(time.Now().Add(-time.Minute).Unix()))
	} else {
		genesis["chainId"] = chainID
	}

	updated, err := json.MarshalIndent(genesis, "", "  ")
	if err != nil {
		return err
	}
	// Besu and Maru read the generated genesis files as unprivileged container users.
	return os.WriteFile(path, append(updated, '\n'), 0o644) //nolint:gosec
}

// waitForReady waits until Maru has sealed a beacon block that carries an execution block.
func (c LineaChain) waitForReady(ctx context.Context) error {
	client, err := ethclient.DialContext(ctx, c.RPC)
	if err != nil {
		return fmt.Errorf("dial readiness rpc: %w", err)
	}
	defer client.Close()

	var lastErr error
	err = testutil.WaitForCondition(3*time.Minute, 2*time.Second, func() (bool, error) {
		blockNumber, err := client.BlockNumber(ctx)
		if err != nil {
			lastErr = err
			return false, nil
		}
		if blockNumber == 0 {
			lastErr = fmt.Errorf("block number is still zero")
			return false, nil
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BeaconAPI+"/eth/v1/beacon/headers/1", nil)
		if err != nil {
			return false, err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = err
			return false, nil
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("beacon block 1: %s", resp.Status)
			return false, nil
		}
		return true, nil
	})
	if err != nil && lastErr != nil {
		return fmt.Errorf("%w (last readiness observation: %v)", err, lastErr)
	}
	return err
}
