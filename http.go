package oidcpkce

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

func GetErrHTTPCode(err error) int {
	switch err {
	case ErrInvalidState,
		ErrStateMissing,
		ErrCodeMissing,
		ErrInvalidRedirectURI:
		return http.StatusBadRequest
	case ErrIDTokenVerificationFailed,
		ErrNonceMismatch:
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}

func GetHTTPErrMessage(err error) string {
	switch err {
	// Safe to output errors
	case ErrNonceMismatch,
		ErrMissingIDToken,
		ErrStateMissing,
		ErrCodeMissing,
		ErrInvalidState,
		ErrInvalidRedirectURI:
		return err.Error()
	// Internal errors
	default:
		return http.StatusText(GetErrHTTPCode(err))
	}
}

type ErrorHandlerFunc func(w http.ResponseWriter, r *http.Request, err error)

type LoginSuccessHandlerFunc func(
	w http.ResponseWriter,
	r *http.Request,
	redirectURL string,
)

type CallbackSuccessHandlerFunc[SessionT any] func(
	w http.ResponseWriter,
	r *http.Request,
	session SessionT,
	redirectURL string,
)

func DefaultErrorHandlerFunc(w http.ResponseWriter, r *http.Request, err error) {
	code := GetErrHTTPCode(err)
	if code == http.StatusInternalServerError {
		slog.Error(err.Error())
	} else {
		slog.Debug(err.Error())
	}
	message := GetHTTPErrMessage(err)
	resp, err := json.Marshal(map[string]any{"error": message})
	if err != nil {
		slog.Error("failed to marshal response body", "error", err.Error())
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(resp)
}

type LoginHandler struct {
	LoginInterface
	HandleError   ErrorHandlerFunc
	HandleSuccess LoginSuccessHandlerFunc
}

func (handler *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirectURI, err := handler.Login(r.Context(), q.Get("redirect_uri"))
	if err != nil {
		handler.HandleError(w, r, err)
		return
	}
	handler.HandleSuccess(w, r, redirectURI)
}

type CallbackHandler[SessionT any] struct {
	CallbackInterface[SessionT]
	HandleError   ErrorHandlerFunc
	HandleSuccess CallbackSuccessHandlerFunc[SessionT]
}

func (handler *CallbackHandler[SessionT]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	session, redirectURL, err := handler.Callback(r.Context(), q.Get("state"), q.Get("code"))
	if err != nil {
		handler.HandleError(w, r, err)
		return
	}
	handler.HandleSuccess(w, r, session, redirectURL)
}
