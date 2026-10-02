package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

// useTokenFiles points the token file globals at a temp dir for one test.
func useTokenFiles(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	prevAccess, prevRefresh := AccessTokenFile, RefreshTokenFile
	AccessTokenFile = filepath.Join(dir, "access_token.json")
	RefreshTokenFile = filepath.Join(dir, "refresh_token.json")
	t.Cleanup(func() { AccessTokenFile, RefreshTokenFile = prevAccess, prevRefresh })
}

// fakeLegion serves /authorize with the given handler and a token endpoint
// that issues fixed tokens for code "code-1".
func fakeLegion(t *testing.T, authorize http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v3/integrations/oauth/authorize", authorize)
	mux.HandleFunc("/v3/integrations/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.PostForm.Get("code") != "code-1" ||
			r.PostForm.Get("redirect_uri") != "http://127.0.0.1:8000/oauth_callback" {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "integration-access", RefreshToken: "integration-refresh", ExpiresIn: 3600,
		})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	useHTTPClient(t, server.Client())
	return server
}

func flowConfig(baseURL string) AppConfig {
	return AppConfig{
		ClientID:       "client-1",
		ClientSecret:   "secret-1",
		RedirectURL:    "http://127.0.0.1:8000/oauth_callback",
		OrganizationID: "org-1",
		LegionBaseURL:  baseURL,
	}
}

func TestHeadlessOAuthFlow_ReadsCodeFromRedirectWithoutListening(t *testing.T) {
	useTokenFiles(t)
	server := fakeLegion(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.Header.Get("Authorization") != "Bearer user-token" || q.Get("code_challenge_method") != "S256" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		target := q.Get("redirect_uri") + "?" + url.Values{"code": {"code-1"}, "state": {q.Get("state")}}.Encode()
		http.Redirect(w, r, target, http.StatusSeeOther)
	})

	// Nothing listens on the redirect URI's port; the flow must not need it.
	token, ok := performHeadlessOAuthFlow(flowConfig(server.URL), "user-token")
	if !ok || token != "integration-access" {
		t.Fatalf("flow = %q, %v; want integration-access, true", token, ok)
	}

	var stored StoredToken
	data, err := os.ReadFile(AccessTokenFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.AccessToken != "integration-access" {
		t.Errorf("access token = %q, want integration-access", stored.AccessToken)
	}
}

func TestHeadlessOAuthFlow_FailsOnServerError(t *testing.T) {
	useTokenFiles(t)
	server := fakeLegion(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
	})

	if _, ok := performHeadlessOAuthFlow(flowConfig(server.URL), "user-token"); ok {
		t.Fatal("flow succeeded on a 400 from authorize")
	}
	if _, err := os.Stat(AccessTokenFile); !os.IsNotExist(err) {
		t.Errorf("access token file written after failed flow: %v", err)
	}
}

func TestHeadlessOAuthFlow_FailsOnRedirectedError(t *testing.T) {
	useTokenFiles(t)
	server := fakeLegion(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		target := q.Get("redirect_uri") + "?" + url.Values{"error": {"access_denied"}, "state": {q.Get("state")}}.Encode()
		http.Redirect(w, r, target, http.StatusSeeOther)
	})

	if _, ok := performHeadlessOAuthFlow(flowConfig(server.URL), "user-token"); ok {
		t.Fatal("flow succeeded on an OAuth error redirect")
	}
}

func TestHeadlessOAuthFlow_RejectsStateMismatch(t *testing.T) {
	useTokenFiles(t)
	server := fakeLegion(t, func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("redirect_uri") + "?code=code-1&state=forged"
		http.Redirect(w, r, target, http.StatusSeeOther)
	})

	if _, ok := performHeadlessOAuthFlow(flowConfig(server.URL), "user-token"); ok {
		t.Fatal("flow accepted a mismatched state")
	}
}

func TestGetIntegrationOAuthConfig_ReadsRegisteredRedirectURIs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"client_id":"client-1","redirect_uris":["http://localhost:8000/oauth_callback"]}`))
	}))
	defer server.Close()
	useHTTPClient(t, server.Client())

	cfg, err := getIntegrationOAuthConfig(server.URL, "user-token", "org-1", "integ-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.RedirectURLs) != 1 || cfg.RedirectURLs[0] != "http://localhost:8000/oauth_callback" {
		t.Errorf("RedirectURLs = %v", cfg.RedirectURLs)
	}
}
