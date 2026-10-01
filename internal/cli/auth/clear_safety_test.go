package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/Scale-Flow/marten/pkg/oauth"
	"github.com/spf13/cobra"
)

func safetyAuthCommand(ctx context.Context, in io.Reader, stderr io.Writer, args ...string) *cobra.Command {
	root := &cobra.Command{Use: "dj", SilenceUsage: true, SilenceErrors: true}
	root.PersistentFlags().String("profile", "test", "")
	root.PersistentFlags().String("auth-storage", "auto", "")
	root.PersistentFlags().Bool("dry-run", false, "")
	root.PersistentFlags().Bool("yes", false, "")
	root.PersistentFlags().Bool("pretty", false, "")
	root.SetContext(ctx)
	root.SetIn(in)
	root.SetErr(stderr)
	root.AddCommand(NewAuthCmd())
	root.SetArgs(args)
	return root
}

func captureSafetyCommand(t *testing.T, root *cobra.Command) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = previous; r.Close() }()
	executeErr := root.Execute()
	w.Close()
	output, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(output), executeErr
}

func TestAuthClearCommandSafetyGuards(t *testing.T) {
	for _, tc := range []struct {
		name, input, status string
		flags               []string
		wantConstruct       bool
		wantPrompt          bool
	}{
		{name: "dry run", flags: []string{"--dry-run"}},
		{name: "dry run wins over yes", flags: []string{"--dry-run", "--yes"}},
		{name: "decline", input: "n\n", status: "cancelled", wantPrompt: true},
		{name: "EOF declines", status: "cancelled", wantPrompt: true},
		{name: "yes flag", flags: []string{"--yes"}, status: "cleared", wantConstruct: true},
		{name: "command input confirms", input: "y\n", status: "cleared", wantConstruct: true, wantPrompt: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			original := authClearStores
			t.Cleanup(func() { authClearStores = original })
			constructs, deletes := 0, 0
			authClearStores = func(_ string, backend string) []authClearStore {
				constructs++
				if backend != "auto" {
					t.Errorf("unexpected backend %q", backend)
				}
				stores := make([]authClearStore, 5)
				for i := range stores {
					stores[i].delete = func(profile string) error {
						deletes++
						if profile != "test" {
							t.Errorf("unexpected profile %q", profile)
						}
						return nil
					}
				}
				return stores
			}
			var stderr bytes.Buffer
			cmd := safetyAuthCommand(context.Background(), strings.NewReader(tc.input), &stderr, append([]string{"auth", "clear"}, tc.flags...)...)
			output, err := captureSafetyCommand(t, cmd)
			if err != nil {
				t.Fatalf("execute: %v; %s", err, output)
			}
			wantConstructs, wantDeletes := 0, 0
			if tc.wantConstruct {
				wantConstructs, wantDeletes = 1, 5
			}
			if constructs != wantConstructs || deletes != wantDeletes {
				t.Fatalf("constructs/deletes = %d/%d, want %d/%d", constructs, deletes, wantConstructs, wantDeletes)
			}
			if strings.Contains(stderr.String(), "Continue?") != tc.wantPrompt {
				t.Fatalf("unexpected prompt output %q", stderr.String())
			}
			var response struct {
				OK   bool `json:"ok"`
				Data struct {
					DryRun  bool   `json:"dry_run"`
					Status  string `json:"status"`
					Profile string `json:"profile"`
				} `json:"data"`
			}
			if err := json.Unmarshal([]byte(output), &response); err != nil || !response.OK || response.Data.Profile != "test" {
				t.Fatalf("invalid response %s: %v", output, err)
			}
			if tc.status == "" && !response.Data.DryRun || response.Data.Status != tc.status {
				t.Fatalf("unexpected response %s", output)
			}
		})
	}
}

func TestAuthClearFileCommandPreservesOtherProfiles(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	path, err := oauthStorePath()
	if err != nil {
		t.Fatal(err)
	}
	tokens := oauth.NewOAuthStore(path)
	creds := oauth.NewClientCredentialFileStore(oauth.ClientCredentialPathForTokenStore(path))
	metadata := oauth.NewMetadataStore(oauth.MetadataPathForTokenStore(path))
	for _, profile := range []string{"test", "other"} {
		if err := tokens.Save(profile, oauth.TokenSet{AccessToken: "mock-token"}); err != nil {
			t.Fatal(err)
		}
		if err := creds.Save(profile, oauth.ClientCredentials{ClientID: "mock-client"}); err != nil {
			t.Fatal(err)
		}
		if err := metadata.Save(profile, oauth.Metadata{ClientID: "mock-client"}); err != nil {
			t.Fatal(err)
		}
	}
	paths := []string{path, oauth.ClientCredentialPathForTokenStore(path), oauth.MetadataPathForTokenStore(path)}
	before := make([][]byte, len(paths))
	for i, p := range paths {
		before[i], err = os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, flags := range [][]string{{"--dry-run"}, {}} {
		args := append([]string{"auth", "clear", "--auth-storage", "file"}, flags...)
		if out, err := captureSafetyCommand(t, safetyAuthCommand(context.Background(), strings.NewReader("n\n"), io.Discard, args...)); err != nil {
			t.Fatalf("execute: %v; %s", err, out)
		}
		for i, p := range paths {
			after, err := os.ReadFile(p)
			if err != nil || !bytes.Equal(before[i], after) {
				t.Fatalf("guard modified store %s: %v", p, err)
			}
		}
	}
	if out, err := captureSafetyCommand(t, safetyAuthCommand(context.Background(), strings.NewReader(""), io.Discard, "auth", "clear", "--auth-storage", "file", "--yes")); err != nil {
		t.Fatalf("execute: %v; %s", err, out)
	}
	if _, err := tokens.Load("test"); err == nil {
		t.Fatal("target token remains")
	}
	if _, err := creds.Load("test"); err == nil {
		t.Fatal("target credentials remain")
	}
	if _, err := metadata.Load("test"); err == nil {
		t.Fatal("target metadata remains")
	}
	if _, err := tokens.Load("other"); err != nil {
		t.Fatalf("other profile token removed: %v", err)
	}
	if _, err := creds.Load("other"); err != nil {
		t.Fatalf("other profile credentials removed: %v", err)
	}
	if _, err := metadata.Load("other"); err != nil {
		t.Fatalf("other profile metadata removed: %v", err)
	}
	for _, store := range authClearStores(path, "file") {
		if store.keychain {
			t.Fatal("explicit file selection included keychain")
		}
	}
}

func TestAuthClearDryRunDescribesSelectedResources(t *testing.T) {
	for _, backend := range []string{"auto", "file", "keychain"} {
		t.Run(backend, func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			original := authClearStores
			t.Cleanup(func() { authClearStores = original })
			authClearStores = func(string, string) []authClearStore {
				t.Fatal("dry-run constructed stores")
				return nil
			}
			out, err := captureSafetyCommand(t, safetyAuthCommand(context.Background(), strings.NewReader(""), io.Discard, "auth", "clear", "--profile", "preview-profile", "--auth-storage", backend, "--dry-run"))
			if err != nil {
				t.Fatalf("preview failed: %v; %s", err, out)
			}
			var response struct {
				Data struct {
					Profile   string   `json:"profile"`
					Storage   string   `json:"storage"`
					Resources []string `json:"resources"`
				} `json:"data"`
			}
			if err := json.Unmarshal([]byte(out), &response); err != nil {
				t.Fatal(err)
			}
			resources := strings.Join(response.Data.Resources, ",")
			if response.Data.Profile != "preview-profile" || response.Data.Storage != backend || !strings.Contains(resources, "oauth metadata") {
				t.Fatalf("incorrect preview: %s", out)
			}
			if strings.Contains(resources, "keychain") != (backend != "file") || strings.Contains(resources, "file ") != (backend != "keychain") {
				t.Fatalf("incorrect resource scope: %s", out)
			}
		})
	}
}
