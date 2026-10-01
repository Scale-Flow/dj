package auth

import (
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
)

// validatedCallbackServer accepts OAuth results only for the current login.
type validatedCallbackServer struct {
	server *http.Server
	CodeCh chan string
	ErrCh  chan error
}

func (s *validatedCallbackServer) Close() error { return s.server.Close() }

func validatedCallbackHandler(state string, codes chan<- string, errs chan<- error) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		received := r.URL.Query().Get("state")
		if state == "" || received == "" || subtle.ConstantTimeCompare([]byte(received), []byte(state)) != 1 {
			http.Error(w, "Invalid OAuth state", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("error") != "" {
			http.Error(w, "Authorization declined", http.StatusBadRequest)
			select {
			case errs <- fmt.Errorf("authorization declined"):
			default:
			}
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Missing authorization code", http.StatusBadRequest)
			return
		}
		select {
		case codes <- code:
			fmt.Fprintln(w, "Authorization received. You can close this window.")
		default:
			http.Error(w, "Authorization already received", http.StatusConflict)
		}
	})
	return mux
}

func startValidatedCallbackServer(port int, state string) (*validatedCallbackServer, error) {
	if state == "" {
		return nil, fmt.Errorf("missing OAuth state")
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, err
	}
	s := &validatedCallbackServer{CodeCh: make(chan string, 1), ErrCh: make(chan error, 1)}
	s.server = &http.Server{Handler: validatedCallbackHandler(state, s.CodeCh, s.ErrCh)}
	go s.server.Serve(listener)
	return s, nil
}
