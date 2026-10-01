package cliutil

import (
	"errors"
	"net"
	"os"

	"github.com/Scale-Flow/marten/pkg/cmdutil"
	"github.com/Scale-Flow/marten/pkg/contract"
	"github.com/Scale-Flow/marten/pkg/transport"
	"github.com/scale-flow/dj/internal/dj"
	"github.com/spf13/cobra"
)

type apiExitError struct{ code int }

func (e *apiExitError) Error() string { return "" }
func (e *apiExitError) ExitCode() int { return e.code }

// WriteAPIError preserves service status codes, nested error messages, retry
// guidance, and network failures in the CLI's structured error contract.
func WriteAPIError(cmd *cobra.Command, err error) error {
	code, message := contract.ErrCodeServer, err.Error()
	var detail any
	var apiErr *transport.APIError
	var networkErr *dj.NetworkError
	var netErr net.Error
	switch {
	case errors.As(err, &apiErr):
		code, message, detail = apiErr.Code, apiErr.Message, apiErr.Detail
	case errors.As(err, &networkErr), errors.As(err, &netErr):
		code = contract.ErrCodeNetwork
	}
	resp := contract.Err(code, message)
	resp.Error.Detail = detail
	_ = contract.Write(os.Stdout, resp, cmdutil.Pretty(cmd))
	cmd.SilenceErrors, cmd.SilenceUsage = true, true
	return &apiExitError{code: cmdutil.ExitCodeForError(code)}
}
