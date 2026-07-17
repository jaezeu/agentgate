package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/jaezeu/agentgate/internal/grant"
)

const version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("agentgate command failed", "error", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("usage: agentgate <serve|revoke|grant-keygen|version> [flags]")
	}
	switch arguments[0] {
	case "serve":
		return runServe(arguments[1:])
	case "revoke":
		return runRevoke(arguments[1:])
	case "grant-keygen":
		return runGrantKeygen(arguments[1:])
	case "version":
		if len(arguments) != 1 {
			return errors.New("version does not accept arguments")
		}
		fmt.Println(version)
		return nil
	default:
		return fmt.Errorf("unknown subcommand %q", arguments[0])
	}
}

func runGrantKeygen(arguments []string) error {
	flags := flag.NewFlagSet("grant-keygen", flag.ContinueOnError)
	privateKeyPath := flags.String("private-key", "dispatcher-private.pem", "private key output path")
	publicKeyPath := flags.String("public-key", "dispatcher-public.pem", "public key output path")
	force := flags.Bool("force", false, "replace existing key files")
	if err := flags.Parse(arguments); err != nil {
		return err
	}

	publicKey, privateKey, err := grant.GenerateKeyPair(nil)
	if err != nil {
		return err
	}
	publicPEM, err := grant.MarshalPublicKeyPEM(publicKey)
	if err != nil {
		return err
	}
	privatePEM, err := grant.MarshalPrivateKeyPEM(privateKey)
	if err != nil {
		return err
	}
	if err := writeKeyFile(*publicKeyPath, publicPEM, 0o644, *force); err != nil {
		return err
	}
	if err := writeKeyFile(*privateKeyPath, privatePEM, 0o600, *force); err != nil {
		_ = os.Remove(*publicKeyPath)
		return err
	}
	fmt.Printf("wrote public key %s and private key %s\n", filepath.Clean(*publicKeyPath), filepath.Clean(*privateKeyPath))
	return nil
}

func writeKeyFile(path string, data []byte, mode os.FileMode, force bool) error {
	openFlags := os.O_WRONLY | os.O_CREATE
	if force {
		openFlags |= os.O_TRUNC
	} else {
		openFlags |= os.O_EXCL
	}
	file, err := os.OpenFile(path, openFlags, mode) // #nosec G304 -- output path is an explicit CLI argument.
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}
