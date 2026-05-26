package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/chenhg5/cc-connect/core"
)

func runSecret(args []string) {
	if len(args) == 0 {
		printSecretUsage()
		os.Exit(1)
	}
	switch args[0] {
	case "hash-password":
		runSecretHashPassword(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown secret subcommand: %s\n", args[0])
		printSecretUsage()
		os.Exit(1)
	}
}

func runSecretHashPassword(args []string) {
	fs := flag.NewFlagSet("secret hash-password", flag.ExitOnError)
	value := fs.String("value", "", "plain password to hash")
	_ = fs.Parse(args)

	if *value == "" {
		fmt.Fprintln(os.Stderr, "--value is required")
		os.Exit(1)
	}
	hashValue, err := core.HashPassword(*value)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hash password: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(hashValue)
}

func printSecretUsage() {
	fmt.Fprintf(os.Stderr, `Usage: cc-connect secret <subcommand>

Subcommands:
  hash-password   Generate an Argon2id password hash for high_risk_auth

Flags for 'hash-password':
  --value <plain>   Plain password to hash

Examples:
  cc-connect secret hash-password --value "your-password"
`)
}
