package dj

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/Scale-Flow/marten/pkg/contract"
	"github.com/Scale-Flow/marten/pkg/transport"
)

// NetworkError retains transport failures so callers can distinguish an API
// response from a failure to reach or read the service.
type NetworkError struct{ Err error }

func (e *NetworkError) Error() string { return e.Err.Error() }
func (e *NetworkError) Unwrap() error { return e.Err }

func networkError(operation string, err error) error {
	return &NetworkError{Err: fmt.Errorf("%s: %w", operation, err)}
}

// checkResponse validates status before callers decode a successful payload. On
// failure it consumes and closes the body, preserving Spotify's nested message.
func checkResponse(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return networkError("read API error response", err)
	}
	code := transport.MapHTTPStatus(resp.StatusCode)
	if resp.StatusCode == http.StatusBadRequest {
		code = contract.ErrCodeValidation
	}
	detail := map[string]any{"status_code": resp.StatusCode}
	if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
		detail["retry_after"] = retryAfter
	}
	apiErr := &transport.APIError{StatusCode: resp.StatusCode, Code: code, Message: http.StatusText(resp.StatusCode), Detail: detail}
	var payload struct {
		Message          string          `json:"message"`
		Error            json.RawMessage `json:"error"`
		ErrorDescription string          `json:"error_description"`
	}
	if json.Unmarshal(data, &payload) == nil {
		var nested struct {
			Message string `json:"message"`
		}
		var message string
		switch {
		case json.Unmarshal(payload.Error, &nested) == nil && nested.Message != "":
			apiErr.Message = nested.Message
		case payload.ErrorDescription != "":
			apiErr.Message = payload.ErrorDescription
		case payload.Message != "":
			apiErr.Message = payload.Message
		case json.Unmarshal(payload.Error, &message) == nil && message != "":
			apiErr.Message = message
		}
	}
	return apiErr
}

func decodeResponse(resp *http.Response, target any) error {
	if err := checkResponse(resp); err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return networkError("read response", err)
	}
	if target != nil && len(data) > 0 {
		if err := json.Unmarshal(data, target); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}
