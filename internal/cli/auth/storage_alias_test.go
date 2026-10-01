package auth

import (
	"github.com/spf13/cobra"
	"testing"
)

func TestHeadlessStorageAlias(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		want    string
		wantErr bool
	}{
		{args: []string{"--auth-storage", "file"}, want: "file"},
		{args: []string{"--storage", "file"}, want: "file"},
		{args: []string{"--auth-storage", "keychain"}, want: "keychain"},
		{args: []string{"--auth-storage", "file", "--storage", "file"}, want: "file"},
		{args: []string{"--auth-storage", "file", "--storage", "auto"}, wantErr: true},
	} {
		cmd := &cobra.Command{}
		cmd.Flags().String("auth-storage", "auto", "")
		cmd.Flags().String("storage", "auto", "")
		if err := cmd.ParseFlags(tc.args); err != nil {
			t.Fatal(err)
		}
		got, err := headlessStorage(cmd)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Fatalf("args=%v got=%q err=%v", tc.args, got, err)
		}
	}
}
