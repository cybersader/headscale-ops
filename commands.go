package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"
)

const (
	maxInputLength            = 320
	supportedHeadscaleVersion = "v0.29.3"
	apiKeyPrefixMarker        = "hskey-api-"
	apiKeyPrefixLength        = 12
)

type stringFlags []string

func (values *stringFlags) String() string { return strings.Join(*values, ",") }
func (values *stringFlags) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func runStatusCommand(ctx context.Context, client *Client, config Config, stdout io.Writer) error {
	version, publicHealth, databaseHealth, info, err := client.Status(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Server: %s\n", config.ServerURL)
	fmt.Fprintf(stdout, "Headscale version: %s\n", valueOrDash(safeText(version.Version)))
	fmt.Fprintf(stdout, "Headscale commit: %s\n", valueOrDash(safeText(version.Commit)))
	fmt.Fprintf(stdout, "Headscale build time: %s\n", valueOrDash(safeText(version.BuildTime)))
	fmt.Fprintf(stdout, "Headscale Go build: %s %s/%s\n", valueOrDash(safeText(version.Go.Version)), valueOrDash(safeText(version.Go.OS)), valueOrDash(safeText(version.Go.Arch)))
	fmt.Fprintf(stdout, "Headscale dirty build: %t\n", version.Dirty)
	fmt.Fprintf(stdout, "Public health: %s\n", valueOrDash(publicHealth.Status))
	fmt.Fprintf(stdout, "Database connectivity: %t\n", databaseHealth.DatabaseConnectivity)
	fmt.Fprintf(stdout, "TLS: %s\n", valueOrDash(info.TLSVersion))
	fmt.Fprintf(stdout, "Certificate subject: %s\n", valueOrDash(safeText(info.Subject)))
	fmt.Fprintf(stdout, "Certificate DNS names: %s\n", valueOrDash(safeJoined(info.DNSNames)))
	if info.NotAfter.IsZero() {
		fmt.Fprintln(stdout, "Certificate expires: -")
	} else {
		fmt.Fprintf(stdout, "Certificate expires: %s\n", info.NotAfter.UTC().Format(time.RFC3339))
	}
	if !isSupportedHeadscaleVersion(version.Version) {
		return fmt.Errorf("unsupported Headscale version %q; require %s", safeText(version.Version), supportedHeadscaleVersion)
	}
	if version.Dirty {
		return errors.New("Headscale reports a dirty build; require an unmodified v0.29.3 release")
	}
	if !strings.EqualFold(publicHealth.Status, "pass") {
		return fmt.Errorf("Headscale public health is %q", safeText(publicHealth.Status))
	}
	if !databaseHealth.DatabaseConnectivity {
		return errors.New("Headscale database connectivity check failed")
	}
	if info.TLSVersion == "" {
		return errors.New("verified TLS metadata is unavailable")
	}
	return nil
}

func runUserCommand(ctx context.Context, client *Client, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return newUsageError("user requires list, create, rename, or delete")
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return newUsageError("user list does not accept arguments")
		}
		users, err := client.ListUsers(ctx)
		if err != nil {
			return err
		}
		sort.Slice(users, func(i, j int) bool { return lessNumericID(users[i].ID, users[j].ID) })
		writer := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(writer, "ID\tNAME\tDISPLAY NAME\tEMAIL\tCREATED")
		for _, user := range users {
			fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n", safeText(user.ID), safeText(user.Name), valueOrDash(safeText(user.DisplayName)), valueOrDash(safeText(user.Email)), valueOrDash(safeText(user.CreatedAt)))
		}
		return writer.Flush()
	case "create":
		flags := flag.NewFlagSet("user create", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		var input CreateUserInput
		flags.StringVar(&input.Name, "name", "", "user name")
		flags.StringVar(&input.DisplayName, "display-name", "", "display name")
		flags.StringVar(&input.Email, "email", "", "email")
		flags.StringVar(&input.PictureURL, "picture-url", "", "profile picture URL")
		if err := flags.Parse(args[1:]); err != nil {
			return newUsageError("user create: %v", err)
		}
		if flags.NArg() != 0 {
			return newUsageError("user create does not accept positional arguments")
		}
		name, err := validateTextInput("name", input.Name, true)
		if err != nil {
			return newUsageError("user create: %v", err)
		}
		input.Name = name
		input.DisplayName, err = validateTextInput("display-name", input.DisplayName, false)
		if err != nil {
			return newUsageError("user create: %v", err)
		}
		input.Email, err = validateTextInput("email", input.Email, false)
		if err != nil {
			return newUsageError("user create: %v", err)
		}
		input.PictureURL, err = validateTextInput("picture-url", input.PictureURL, false)
		if err != nil {
			return newUsageError("user create: %v", err)
		}
		user, err := client.CreateUser(ctx, input)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Created user id=%s name=%s\n", safeText(user.ID), safeText(user.Name))
		return nil
	case "rename":
		flags := flag.NewFlagSet("user rename", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		var id, name string
		flags.StringVar(&id, "id", "", "user ID")
		flags.StringVar(&name, "name", "", "new user name")
		if err := flags.Parse(args[1:]); err != nil {
			return newUsageError("user rename: %v", err)
		}
		if flags.NArg() != 0 {
			return newUsageError("user rename does not accept positional arguments")
		}
		id, err := validateID("user ID", id)
		if err != nil {
			return newUsageError("user rename: %v", err)
		}
		name, err = validateTextInput("name", name, true)
		if err != nil {
			return newUsageError("user rename: %v", err)
		}
		user, err := client.RenameUser(ctx, id, name)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Renamed user id=%s name=%s\n", safeText(user.ID), safeText(user.Name))
		return nil
	case "delete":
		flags := flag.NewFlagSet("user delete", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		var id string
		var yes bool
		flags.StringVar(&id, "id", "", "user ID")
		flags.BoolVar(&yes, "yes", false, "confirm deletion")
		if err := flags.Parse(args[1:]); err != nil {
			return newUsageError("user delete: %v", err)
		}
		if flags.NArg() != 0 || !yes {
			return newUsageError("user delete requires --id ID --yes")
		}
		id, err := validateID("user ID", id)
		if err != nil {
			return newUsageError("user delete: %v", err)
		}
		if err := client.DeleteUser(ctx, id); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Deleted user id=%s\n", safeText(id))
		return nil
	default:
		return newUsageError("unknown user command %q", safeText(args[0]))
	}
}

func runNodeCommand(ctx context.Context, client *Client, args []string, stdout io.Writer, now func() time.Time) error {
	if len(args) == 0 {
		return newUsageError("node requires list, rename, expire, delete, or set-tags")
	}
	switch args[0] {
	case "list":
		flags := flag.NewFlagSet("node list", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		var user string
		flags.StringVar(&user, "user", "", "optional user filter")
		if err := flags.Parse(args[1:]); err != nil {
			return newUsageError("node list: %v", err)
		}
		if flags.NArg() != 0 {
			return newUsageError("node list does not accept positional arguments")
		}
		if _, err := validateTextInput("user", user, false); err != nil {
			return newUsageError("node list: %v", err)
		}
		nodes, err := client.ListNodes(ctx, strings.TrimSpace(user))
		if err != nil {
			return err
		}
		sort.Slice(nodes, func(i, j int) bool { return lessNumericID(nodes[i].ID, nodes[j].ID) })
		writer := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(writer, "ID\tNAME\tUSER\tONLINE\tIPS\tTAGS\tEXPIRY")
		for _, node := range nodes {
			name := node.Name
			if node.GivenName != "" {
				name = node.GivenName
			}
			fmt.Fprintf(writer, "%s\t%s\t%s\t%t\t%s\t%s\t%s\n", safeText(node.ID), safeText(name), safeText(node.User.Name), node.Online, valueOrDash(safeJoined(node.IPAddresses)), valueOrDash(safeJoined(node.Tags)), valueOrDash(safeText(node.Expiry)))
		}
		return writer.Flush()
	case "rename":
		flags := flag.NewFlagSet("node rename", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		var id, name string
		flags.StringVar(&id, "id", "", "node ID")
		flags.StringVar(&name, "name", "", "new node name")
		if err := flags.Parse(args[1:]); err != nil {
			return newUsageError("node rename: %v", err)
		}
		if flags.NArg() != 0 {
			return newUsageError("node rename does not accept positional arguments")
		}
		id, err := validateID("node ID", id)
		if err != nil {
			return newUsageError("node rename: %v", err)
		}
		name, err = validateTextInput("name", name, true)
		if err != nil {
			return newUsageError("node rename: %v", err)
		}
		node, err := client.RenameNode(ctx, id, name)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Renamed node id=%s name=%s\n", safeText(node.ID), valueOrDash(safeText(node.GivenName)))
		return nil
	case "expire":
		flags := flag.NewFlagSet("node expire", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		var id, expiration string
		var disable, yes bool
		flags.StringVar(&id, "id", "", "node ID")
		flags.StringVar(&expiration, "expiration", "now", "now, duration, or RFC3339 timestamp")
		flags.BoolVar(&disable, "disable", false, "remove node expiry")
		flags.BoolVar(&yes, "yes", false, "confirm change")
		if err := flags.Parse(args[1:]); err != nil {
			return newUsageError("node expire: %v", err)
		}
		if flags.NArg() != 0 || !yes {
			return newUsageError("node expire requires --id ID --yes")
		}
		id, err := validateID("node ID", id)
		if err != nil {
			return newUsageError("node expire: %v", err)
		}
		var expiry *time.Time
		if disable {
			if expiration != "now" {
				return newUsageError("node expire: --disable cannot be combined with --expiration")
			}
		} else if strings.TrimSpace(expiration) != "now" {
			parsed, err := parseExpiration(expiration, now())
			if err != nil {
				return newUsageError("node expire: %v", err)
			}
			expiry = &parsed
		}
		node, err := client.SetNodeExpiry(ctx, id, expiry, disable)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Updated node expiry id=%s expiry=%s\n", safeText(node.ID), valueOrDash(safeText(node.Expiry)))
		return nil
	case "delete":
		flags := flag.NewFlagSet("node delete", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		var id string
		var yes bool
		flags.StringVar(&id, "id", "", "node ID")
		flags.BoolVar(&yes, "yes", false, "confirm deletion")
		if err := flags.Parse(args[1:]); err != nil {
			return newUsageError("node delete: %v", err)
		}
		if flags.NArg() != 0 || !yes {
			return newUsageError("node delete requires --id ID --yes")
		}
		id, err := validateID("node ID", id)
		if err != nil {
			return newUsageError("node delete: %v", err)
		}
		if err := client.DeleteNode(ctx, id); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Deleted node id=%s\n", safeText(id))
		return nil
	case "set-tags":
		flags := flag.NewFlagSet("node set-tags", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		var id string
		var tags stringFlags
		var yes bool
		flags.StringVar(&id, "id", "", "node ID")
		flags.Var(&tags, "tag", "forced tag; repeatable")
		flags.BoolVar(&yes, "yes", false, "confirm irreversible ownership conversion")
		if err := flags.Parse(args[1:]); err != nil {
			return newUsageError("node set-tags: %v", err)
		}
		if flags.NArg() != 0 || len(tags) == 0 || !yes {
			return newUsageError("node set-tags requires --id ID, repeated --tag TAG, and --yes")
		}
		id, err := validateID("node ID", id)
		if err != nil {
			return newUsageError("node set-tags: %v", err)
		}
		tags, err = validateTags(tags)
		if err != nil {
			return newUsageError("node set-tags: %v", err)
		}
		node, err := client.SetNodeTags(ctx, id, tags)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Updated node tags id=%s tags=%s\n", safeText(node.ID), valueOrDash(safeJoined(node.Tags)))
		return nil
	default:
		return newUsageError("unknown node command %q", safeText(args[0]))
	}
}

func runPreAuthCommand(ctx context.Context, client *Client, args []string, stdout, stderr io.Writer, now func() time.Time) error {
	if len(args) == 0 {
		return newUsageError("preauth requires list, create, or expire")
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return newUsageError("preauth list does not accept arguments")
		}
		keys, err := client.ListPreAuthKeys(ctx)
		if err != nil {
			return err
		}
		sort.Slice(keys, func(i, j int) bool { return lessNumericID(keys[i].ID, keys[j].ID) })
		writer := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(writer, "ID\tUSER\tREUSABLE\tEPHEMERAL\tUSED\tEXPIRATION\tTAGS")
		for _, key := range keys {
			fmt.Fprintf(writer, "%s\t%s\t%t\t%t\t%t\t%s\t%s\n", safeText(key.ID), safeText(key.User.Name), key.Reusable, key.Ephemeral, key.Used, valueOrDash(safeText(key.Expiration)), valueOrDash(safeJoined(key.ACLTags)))
		}
		return writer.Flush()
	case "create":
		flags := flag.NewFlagSet("preauth create", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		var user, expiration string
		var reusable, ephemeral bool
		var tags stringFlags
		flags.StringVar(&user, "user", "", "user ID")
		flags.StringVar(&expiration, "expiration", "", "duration or RFC3339 timestamp")
		flags.BoolVar(&reusable, "reusable", false, "allow repeated use")
		flags.BoolVar(&ephemeral, "ephemeral", false, "create ephemeral nodes")
		flags.Var(&tags, "tag", "ACL tag; repeatable")
		if err := flags.Parse(args[1:]); err != nil {
			return newUsageError("preauth create: %v", err)
		}
		if flags.NArg() != 0 || expiration == "" {
			return newUsageError("preauth create requires --user ID --expiration VALUE")
		}
		user, err := validateID("user ID", user)
		if err != nil {
			return newUsageError("preauth create: %v", err)
		}
		expires, err := parseExpiration(expiration, now())
		if err != nil {
			return newUsageError("preauth create: %v", err)
		}
		if len(tags) > 0 {
			tags, err = validateTags(tags)
			if err != nil {
				return newUsageError("preauth create: %v", err)
			}
		}
		key, err := client.CreatePreAuthKey(ctx, CreatePreAuthKeyInput{User: user, Reusable: reusable, Ephemeral: ephemeral, Expiration: expires.Format(time.RFC3339), ACLTags: tags})
		if err != nil {
			return err
		}
		if err := writeSecret(stdout, key.Key); err != nil {
			rollbackErr := expirePreAuthKeyAfterOutputFailure(client, key.ID)
			if rollbackErr != nil {
				return fmt.Errorf("write newly created pre-auth key: %w; automatic expiry failed for id=%s: %v", err, safeText(key.ID), rollbackErr)
			}
			return fmt.Errorf("write newly created pre-auth key: %w; key id=%s was expired automatically", err, safeText(key.ID))
		}
		fmt.Fprintf(stderr, "Created pre-auth key id=%s; secret written once to stdout.\n", safeText(key.ID))
		return nil
	case "expire":
		flags := flag.NewFlagSet("preauth expire", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		var id string
		var yes bool
		flags.StringVar(&id, "id", "", "pre-auth key ID")
		flags.BoolVar(&yes, "yes", false, "confirm expiry")
		if err := flags.Parse(args[1:]); err != nil {
			return newUsageError("preauth expire: %v", err)
		}
		if flags.NArg() != 0 || !yes {
			return newUsageError("preauth expire requires --id ID --yes")
		}
		id, err := validateID("pre-auth key ID", id)
		if err != nil {
			return newUsageError("preauth expire: %v", err)
		}
		if err := client.ExpirePreAuthKey(ctx, id); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Expired pre-auth key id=%s\n", safeText(id))
		return nil
	default:
		return newUsageError("unknown preauth command %q", safeText(args[0]))
	}
}

func runAPIKeyCommand(ctx context.Context, client *Client, args []string, stdout, stderr io.Writer, now func() time.Time) error {
	if len(args) == 0 {
		return newUsageError("apikey requires list, create, or expire")
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return newUsageError("apikey list does not accept arguments")
		}
		keys, err := client.ListAPIKeys(ctx)
		if err != nil {
			return err
		}
		sort.Slice(keys, func(i, j int) bool { return lessNumericID(keys[i].ID, keys[j].ID) })
		writer := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(writer, "ID\tPREFIX\tCREATED\tEXPIRATION\tLAST SEEN")
		for _, key := range keys {
			fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n", safeText(key.ID), safeText(key.Prefix), valueOrDash(safeText(key.CreatedAt)), valueOrDash(safeText(key.Expiration)), valueOrDash(safeText(key.LastSeen)))
		}
		return writer.Flush()
	case "create":
		flags := flag.NewFlagSet("apikey create", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		var expiration string
		flags.StringVar(&expiration, "expiration", "", "duration or RFC3339 timestamp")
		if err := flags.Parse(args[1:]); err != nil {
			return newUsageError("apikey create: %v", err)
		}
		if flags.NArg() != 0 || expiration == "" {
			return newUsageError("apikey create requires --expiration VALUE")
		}
		expires, err := parseExpiration(expiration, now())
		if err != nil {
			return newUsageError("apikey create: %v", err)
		}
		key, err := client.CreateAPIKey(ctx, expires)
		if err != nil {
			return err
		}
		prefix, prefixErr := apiKeyPrefix(key)
		if err := writeSecret(stdout, key); err != nil {
			if prefixErr != nil {
				return fmt.Errorf("write newly created API key: %w; automatic expiry is unavailable and the key may remain active: %v", err, prefixErr)
			}
			rollbackErr := expireAPIKeyAfterOutputFailure(client, prefix)
			if rollbackErr != nil {
				return fmt.Errorf("write newly created API key: %w; automatic expiry failed for prefix=%s: %v", err, safeText(prefix), rollbackErr)
			}
			return fmt.Errorf("write newly created API key: %w; key prefix=%s was expired automatically", err, safeText(prefix))
		}
		if prefixErr != nil {
			fmt.Fprintf(stderr, "Warning: created API key uses an unsupported format; automatic expiry after an output failure would be unavailable: %v\n", prefixErr)
		}
		fmt.Fprintln(stderr, "Created API key; secret written once to stdout.")
		return nil
	case "expire":
		flags := flag.NewFlagSet("apikey expire", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		var id, prefix string
		var yes bool
		flags.StringVar(&id, "id", "", "API key ID")
		flags.StringVar(&prefix, "prefix", "", "API key prefix")
		flags.BoolVar(&yes, "yes", false, "confirm expiry")
		if err := flags.Parse(args[1:]); err != nil {
			return newUsageError("apikey expire: %v", err)
		}
		if flags.NArg() != 0 || !yes || (id == "") == (prefix == "") {
			return newUsageError("apikey expire requires exactly one of --id ID or --prefix PREFIX, plus --yes")
		}
		var err error
		if id != "" {
			id, err = validateID("API key ID", id)
		} else {
			prefix, err = validateTextInput("API key prefix", prefix, true)
		}
		if err != nil {
			return newUsageError("apikey expire: %v", err)
		}
		if err := client.ExpireAPIKey(ctx, id, prefix); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "Expired API key")
		return nil
	default:
		return newUsageError("unknown apikey command %q", safeText(args[0]))
	}
}

func isSupportedHeadscaleVersion(version string) bool {
	return "v"+strings.TrimPrefix(strings.TrimSpace(version), "v") == supportedHeadscaleVersion
}

func lessNumericID(left, right string) bool {
	leftID, leftErr := strconv.ParseUint(left, 10, 64)
	rightID, rightErr := strconv.ParseUint(right, 10, 64)
	switch {
	case leftErr == nil && rightErr == nil:
		if leftID == rightID {
			return left < right
		}
		return leftID < rightID
	case leftErr == nil:
		return true
	case rightErr == nil:
		return false
	default:
		return left < right
	}
}

func apiKeyPrefix(secret string) (string, error) {
	if !strings.HasPrefix(secret, apiKeyPrefixMarker) {
		return "", errors.New("API key does not use the expected hskey-api format")
	}
	remainder := strings.TrimPrefix(secret, apiKeyPrefixMarker)
	if len(remainder) <= apiKeyPrefixLength || remainder[apiKeyPrefixLength] != '-' {
		return "", errors.New("API key does not contain the expected 12-character prefix")
	}
	prefix := remainder[:apiKeyPrefixLength]
	for _, character := range prefix {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_') {
			return "", errors.New("API key prefix is not URL-safe")
		}
	}
	return apiKeyPrefixMarker + prefix, nil
}

func expirePreAuthKeyAfterOutputFailure(client *Client, id string) error {
	id, err := validateID("pre-auth key ID", id)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	return client.ExpirePreAuthKey(ctx, id)
}

func expireAPIKeyAfterOutputFailure(client *Client, prefix string) error {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	return client.ExpireAPIKey(ctx, "", prefix)
}

func validateID(label, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || value == 0 {
		return "", fmt.Errorf("%s must be a positive integer", label)
	}
	return strconv.FormatUint(value, 10), nil
}

func validateTextInput(label, raw string, required bool) (string, error) {
	value := strings.TrimSpace(raw)
	if required && value == "" {
		return "", fmt.Errorf("%s must not be empty", label)
	}
	if len([]rune(value)) > maxInputLength {
		return "", fmt.Errorf("%s exceeds %d characters", label, maxInputLength)
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return "", fmt.Errorf("%s must not contain control characters", label)
		}
	}
	return value, nil
}

func validateTags(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, errors.New("at least one tag is required")
	}
	result := make([]string, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, candidate := range raw {
		tag, err := validateTextInput("tag", candidate, true)
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(tag, "tag:") || len(tag) == len("tag:") {
			return nil, fmt.Errorf("tag %q must use tag:name form", safeText(tag))
		}
		if tag != strings.ToLower(tag) {
			return nil, fmt.Errorf("tag %q must be lowercase", safeText(tag))
		}
		if strings.IndexFunc(tag, unicode.IsSpace) >= 0 {
			return nil, fmt.Errorf("tag %q must not contain spaces", safeText(tag))
		}
		if seen[tag] {
			return nil, fmt.Errorf("duplicate tag %q", safeText(tag))
		}
		seen[tag] = true
		result = append(result, tag)
	}
	sort.Strings(result)
	return result, nil
}

func parseExpiration(raw string, now time.Time) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if duration, err := time.ParseDuration(raw); err == nil {
		if duration <= 0 {
			return time.Time{}, errors.New("expiration duration must be positive")
		}
		return now.Add(duration).UTC(), nil
	}
	expiration, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, errors.New("expiration must be a positive Go duration or future RFC3339 timestamp")
	}
	if !expiration.After(now) {
		return time.Time{}, errors.New("expiration timestamp must be in the future")
	}
	return expiration.UTC(), nil
}

func writeSecret(writer io.Writer, secret string) error {
	if secret == "" {
		return errors.New("server returned an empty secret")
	}
	for _, character := range secret {
		if character < 0x21 || character > 0x7e {
			return errors.New("server returned a secret containing unsafe characters")
		}
	}
	_, err := fmt.Fprintln(writer, secret)
	return err
}

func safeJoined(values []string) string {
	return safeText(strings.Join(values, ","))
}

func safeText(value string) string {
	var builder strings.Builder
	count := 0
	for _, character := range value {
		if count >= maxInputLength {
			builder.WriteString("...")
			break
		}
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			builder.WriteRune('?')
		} else {
			builder.WriteRune(character)
		}
		count++
	}
	return builder.String()
}

func valueOrDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
