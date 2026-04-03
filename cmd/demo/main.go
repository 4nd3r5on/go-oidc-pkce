package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"

	oidcpkce "github.com/4nd3r5on/go-oidc-pkce"
	"github.com/4nd3r5on/go-oidc-pkce/pkg/memory"
)

func main() {
	cfg, err := loadConfig()
	if err != nil {
		slog.Error("config", "error", err)
		os.Exit(1)
	}

	ctx := context.Background()

	provider, err := oidcpkce.NewProvider(ctx, cfg.providerConfig())
	if err != nil {
		slog.Error("oidc provider init", "error", err)
		os.Exit(1)
	}

	states := memory.NewStateStore()
	users := memory.NewUserStore()
	sessions := memory.NewSessionStore(cfg.SessionTTL)

	login := oidcpkce.NewLogin(states, provider, oidcpkce.DefaultValidateRedirectURI)
	callback := oidcpkce.NewCallback(states, provider, users, sessions)

	mux := http.NewServeMux()

	mux.Handle("GET /auth/login", &oidcpkce.LoginHandler{
		LoginInterface: login,
		HandleError:    oidcpkce.DefaultErrorHandlerFunc,
		HandleSuccess: func(w http.ResponseWriter, r *http.Request, authURL string) {
			http.Redirect(w, r, authURL, http.StatusFound)
		},
	})

	mux.Handle("GET /auth/callback", &oidcpkce.CallbackHandler[memory.Session]{
		CallbackInterface: callback,
		HandleError:       oidcpkce.DefaultErrorHandlerFunc,
		HandleSuccess: func(w http.ResponseWriter, r *http.Request, sess memory.Session, redirectURL string) {
			http.SetCookie(w, sessionCookie(sess))
			http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		},
	})

	mux.HandleFunc("POST /auth/logout", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session_id"); err == nil {
			sessions.Delete(c.Value)
		}
		http.SetCookie(w, clearCookie())
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		c, err := r.Cookie("session_id")
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
			return
		}

		sess, ok := sessions.Get(c.Value)
		if !ok {
			http.SetCookie(w, clearCookie())
			writeJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
			return
		}

		user, _ := users.Get(sess.UserID)
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": true,
			"session": map[string]any{
				"id":         sess.ID,
				"user_id":    sess.UserID,
				"expires_at": sess.ExpiresAt,
			},
			"user": user,
		})
	})

	slog.Info("demo server starting", "addr", cfg.Addr)
	if err := http.ListenAndServe(cfg.Addr, mux); err != nil {
		slog.Error("server", "error", err)
		os.Exit(1)
	}
}

func sessionCookie(sess memory.Session) *http.Cookie {
	return &http.Cookie{
		Name:     "session_id",
		Value:    sess.ID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  sess.ExpiresAt,
	}
}

func clearCookie() *http.Cookie {
	return &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
