package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/atotto/cloudkms"
	"github.com/atotto/kssh/kssh-agent/server"
	"golang.org/x/crypto/ssh/agent"
)

// You can set key path `export KSSH_KEY_PATH=projects/[PROJECT_ID]/locations/[LOCATION]/keyRings/[KEY_RING]/cryptoKeys/[KEY]/cryptoKeyVersions/[VERSION]` EC_SIGN_P256_SHA256 Algorithm
var kmsKeyPath = os.Getenv("KSSH_KEY_PATH")

var (
	key = flag.String("i", kmsKeyPath, "Selects a Google Cloud KMS resource ID.")
)

const script = `SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;
SSH_AGENT_PID=%d; export SSH_AGENT_PID;
echo Agent pid %d;
`

func main() {
	flag.Parse()

	if *key == "" {
		fmt.Println("Please set kms key")
		os.Exit(2)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	ctx, cancel := context.WithCancel(context.Background())

	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		log.Printf("google cloud kms: %s", err)
		os.Exit(1)
	}
	defer client.Close()

	signer, err := cloudkms.NewSigner(client, *key)
	if err != nil {
		log.Printf("load key: %s", err)
		os.Exit(1)
	}

	kr := agent.NewKeyring()

	kr.Add(agent.AddedKey{
		PrivateKey: signer,
		Comment:    "kssh",
	})

	tmpDir, err := ioutil.TempDir("", "kssh-")
	if err != nil {
		log.Fatalf("dir: %s", err)
	}
	pid := os.Getpid()
	path := filepath.Join(tmpDir, fmt.Sprintf("agent.%d", pid))

	listener, err := net.Listen("unix", path)
	if err != nil {
		log.Fatalf("listen: %s", err)
	}

	go server.Serve(listener, kr)

	args := os.Args
	if len(args) >= 2 {
		name := args[1]
		args = args[2:]
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		env := os.Environ()
		env = append(env, fmt.Sprintf("SSH_AUTH_SOCK=%s", path), fmt.Sprintf("SSH_AGENT_PID=%d", pid))
		cmd.Env = env

		if err := cmd.Start(); err != nil {
			log.Fatalf("exec command: %s", err)
		}

		go func() {
			cmd.Wait()
			cancel()
		}()
	} else {
		// print script
		fmt.Fprintf(os.Stdout, script, path, pid, pid)
	}

	select {
	case <-sig:
		cancel()
	case <-ctx.Done():
	}
}
