package cli

import (
	"github.com/Scale-Flow/marten/pkg/cmdutil"
	"github.com/Scale-Flow/marten/pkg/contract"
	"github.com/spf13/cobra"
)

// Execute is the process boundary: Cobra validation errors need the same JSON
// contract as command errors, and an error must never become a successful exit.
func Execute(root *cobra.Command) int {
	cmd, err := root.ExecuteC()
	if err == nil {
		return 0
	}
	if code := cmdutil.ExitCode(err); code != 0 {
		return code
	}
	if coded, ok := err.(interface{ ExitCode() int }); ok && coded.ExitCode() != 0 {
		return coded.ExitCode()
	}
	if cmd == nil {
		cmd = root
	}
	return cmdutil.ExitCode(cmdutil.WriteError(cmd, contract.ErrCodeValidation, err.Error()))
}
