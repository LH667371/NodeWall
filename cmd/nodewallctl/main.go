package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"nodewall/internal/security"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("usage: nodewallctl set-password [--file path] [--password value]")
	}

	switch os.Args[1] {
	case "set-password":
		setPassword(os.Args[2:])
	default:
		log.Fatalf("unknown command %q", os.Args[1])
	}
}

func setPassword(args []string) {
	fs := flag.NewFlagSet("set-password", flag.ExitOnError)
	file := fs.String("file", "/etc/nodewall/auth.json", "password file path")
	password := fs.String("password", "", "password value")
	fs.Parse(args)

	if *password == "" {
		*password = os.Getenv("NODEWALL_ADMIN_PASSWORD")
	}
	if *password == "" {
		log.Fatal("password is required via --password or NODEWALL_ADMIN_PASSWORD")
	}

	if err := security.EnsureAdminUser(*file, "admin", *password); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("admin password updated: %s\n", *file)
}
