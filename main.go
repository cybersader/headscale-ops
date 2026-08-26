package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

var (
	buildVersion  = "dev"
	buildRevision = "unknown"
)

const usage = `Usage:
  headscale-ops [--config FILE] configure --server-url URL
  headscale-ops [--config FILE] status
  headscale-ops version
  headscale-ops [--config FILE] user list
  headscale-ops [--config FILE] user create --name NAME [options]
  headscale-ops [--config FILE] user rename --id ID --name NAME
  headscale-ops [--config FILE] user delete --id ID --yes
  headscale-ops [--config FILE] node list [--user USER]
  headscale-ops [--config FILE] node rename --id ID --name NAME
  headscale-ops [--config FILE] node expire --id ID [--expiration VALUE | --disable] --yes
  headscale-ops [--config FILE] node delete --id ID --yes
  headscale-ops [--config FILE] node set-tags --id ID --tag TAG [--tag TAG ...] --yes
  headscale-ops [--config FILE] preauth list
  headscale-ops [--config FILE] preauth create --user ID --expiration VALUE [options]
  headscale-ops [--config FILE] preauth expire --id ID --yes
  headscale-ops [--config FILE] apikey list
  headscale-ops [--config FILE] apikey create --expiration VALUE
  headscale-ops [--config FILE] apikey expire (--id ID | --prefix PREFIX) --yes

Global options:
  --config FILE  Owner-only JSON credential file (default: user config directory)

Expiration values accept a positive Go duration such as 24h or a future RFC3339 timestamp.
Create-key commands write the new secret only to stdout; diagnostics go to stderr.
`

type secretReader func() ([]byte, error)

type commandDependencies struct {
	readSecret secretReader
	now        func() time.Time
	newClient  func(Config) (*Client, error)
}

func defaultCommandDependencies(stdin io.Reader) commandDependencies {
	return commandDependencies{
		readSecret: terminalSecretReader(stdin),
		now:        time.Now,
		newClient: func(config Config) (*Client, error) {
			return NewClient(config, nil)
		},
	}
}

func terminalSecretReader(stdin io.Reader) secretReader {
	return func() ([]byte, error) {
		file, ok := stdin.(*os.File)
		if !ok || !term.IsTerminal(int(file.Fd())) {
			return nil, errors.New("hidden API-key input requires an interactive terminal")
		}
		return term.ReadPassword(int(file.Fd()))
	}
}

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func runCLI(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return runCLIWithDependencies(args, stdout, stderr, defaultCommandDependencies(stdin))
}

func runCLIWithDependencies(args []string, stdout, stderr io.Writer, dependencies commandDependencies) int {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	configPath, remaining, err := extractConfigPath(args)
	if err != nil {
		fmt.Fprintf(stderr, "headscale-ops: %v\n\n%s", err, usage)
		return 2
	}
	if configPath == "" {
		configPath, err = defaultConfigPath()
		if err != nil {
			fmt.Fprintf(stderr, "headscale-ops: %v\n", err)
			return 1
		}
	}
	if len(remaining) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	if remaining[0] == "help" || remaining[0] == "--help" || remaining[0] == "-h" {
		fmt.Fprint(stdout, usage)
		return 0
	}
	if remaining[0] == "version" {
		if len(remaining) != 1 {
			fmt.Fprintln(stderr, "headscale-ops: version does not accept arguments")
			return 2
		}
		fmt.Fprintf(stdout, "headscale-ops %s (%s)\n", buildVersion, buildRevision)
		return 0
	}
	if dependencies.now == nil {
		dependencies.now = time.Now
	}
	if dependencies.newClient == nil {
		dependencies.newClient = func(config Config) (*Client, error) { return NewClient(config, nil) }
	}

	if remaining[0] == "configure" {
		if err := runConfigureCommand(remaining[1:], configPath, stdout, stderr, dependencies); err != nil {
			return reportCommandError(stderr, err)
		}
		return 0
	}

	config, err := readConfig(configPath)
	if err != nil {
		fmt.Fprintf(stderr, "headscale-ops: %v\n", err)
		return 1
	}
	client, err := dependencies.newClient(config)
	if err != nil {
		fmt.Fprintf(stderr, "headscale-ops: create client: %v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	switch remaining[0] {
	case "status":
		if len(remaining) != 1 {
			fmt.Fprintln(stderr, "headscale-ops: status does not accept arguments")
			return 2
		}
		err = runStatusCommand(ctx, client, config, stdout)
	case "user":
		err = runUserCommand(ctx, client, remaining[1:], stdout)
	case "node":
		err = runNodeCommand(ctx, client, remaining[1:], stdout, dependencies.now)
	case "preauth":
		err = runPreAuthCommand(ctx, client, remaining[1:], stdout, stderr, dependencies.now)
	case "apikey":
		err = runAPIKeyCommand(ctx, client, remaining[1:], stdout, stderr, dependencies.now)
	default:
		fmt.Fprintf(stderr, "headscale-ops: unknown command %q\n\n%s", safeText(remaining[0]), usage)
		return 2
	}
	if err != nil {
		return reportCommandError(stderr, err)
	}
	return 0
}

func reportCommandError(stderr io.Writer, err error) int {
	var usageError *commandUsageError
	if errors.As(err, &usageError) {
		fmt.Fprintf(stderr, "headscale-ops: %s\n", usageError.Error())
		return 2
	}
	fmt.Fprintf(stderr, "headscale-ops: %v\n", err)
	return 1
}

func extractConfigPath(args []string) (string, []string, error) {
	remaining := make([]string, 0, len(args))
	var configPath string
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case argument == "--config":
			if configPath != "" {
				return "", nil, errors.New("--config may be specified only once")
			}
			if index+1 >= len(args) {
				return "", nil, errors.New("--config requires a path")
			}
			index++
			if strings.TrimSpace(args[index]) == "" {
				return "", nil, errors.New("--config path must not be empty")
			}
			configPath = args[index]
		case strings.HasPrefix(argument, "--config="):
			if configPath != "" {
				return "", nil, errors.New("--config may be specified only once")
			}
			value := strings.TrimPrefix(argument, "--config=")
			if strings.TrimSpace(value) == "" {
				return "", nil, errors.New("--config path must not be empty")
			}
			configPath = value
		default:
			remaining = append(remaining, argument)
		}
	}
	return configPath, remaining, nil
}

func runConfigureCommand(args []string, path string, stdout, stderr io.Writer, dependencies commandDependencies) error {
	flags := flag.NewFlagSet("configure", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var serverURL string
	flags.StringVar(&serverURL, "server-url", "", "Headscale server URL")
	if err := flags.Parse(args); err != nil {
		return newUsageError("configure: %v", err)
	}
	if flags.NArg() != 0 || strings.TrimSpace(serverURL) == "" {
		return newUsageError("configure requires --server-url URL")
	}
	if dependencies.readSecret == nil {
		return errors.New("hidden API-key reader is unavailable")
	}
	normalizedURL, err := normalizeServerURL(serverURL)
	if err != nil {
		return err
	}
	fmt.Fprint(stderr, "Headscale API key [input hidden]: ")
	secret, err := dependencies.readSecret()
	fmt.Fprintln(stderr)
	if err != nil {
		return err
	}
	apiKey := string(secret)
	for index := range secret {
		secret[index] = 0
	}
	if err := writeConfig(path, Config{ServerURL: normalizedURL, APIKey: apiKey}); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Wrote owner-only configuration to %s\n", safeText(path))
	return nil
}

type commandUsageError struct {
	message string
}

func (err *commandUsageError) Error() string { return err.message }

func newUsageError(format string, arguments ...any) error {
	return &commandUsageError{message: fmt.Sprintf(format, arguments...)}
}
