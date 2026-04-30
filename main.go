package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	pgtel "legion-auth-go/internal/otel"

	"golang.org/x/term"
	"legion-auth-go/pkg/install"
)

// ============================================================================
// Constants & Configuration
// ============================================================================

var (
	// Version information - updated by build process via ldflags
	Version   = "dev"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

const (
	ColorBlue   = "\033[94m"
	ColorGreen  = "\033[92m"
	ColorYellow = "\033[93m"
	ColorRed    = "\033[91m"
	ColorCyan   = "\033[96m"
	ColorWhite  = "\033[97m"
	ColorGray   = "\033[90m"
	ColorBold   = "\033[1m"
	ColorReset  = "\033[0m"

	orgSelectionPageSize = 10
	integrationPageSize  = 10
)

var (
	StoragePath        string
	ConfigFile         string
	AccessTokenFile    string
	RefreshTokenFile   string
	TerminalEntityFile string
	LegionOAuthPath    string

	// Structured logger (JSON to stdout)
	logger *slog.Logger

	// Instrumented HTTP client (OTel tracing on all outbound requests)
	httpClient *http.Client

	// OTel providers (nil-safe — Shutdown is safe to call when nil)
	otelProviders *pgtel.Providers

	// Legion metrics (nil-safe — Set*/Record* methods are nil-receiver safe)
	legionMetrics *pgtel.LegionMetrics

	// Shutdown signal
	shutdownChan = make(chan struct{})

	// File permissions (env: LEGION_AUTH_FILE_GID)
	filePermissions os.FileMode = 0640
	fileGID                     = -1

	// Valid terminal entity types for --entity-type flag and interactive menu.
	validEntityTypes = []string{"lander", "helios", "portal", "dev-unit"}
)

func init() {
	if g := os.Getenv("LEGION_AUTH_FILE_GID"); g != "" {
		parsed, err := strconv.Atoi(g)
		if err != nil {
			slog.Warn("LEGION_AUTH_FILE_GID is not a valid integer, ignoring", slog.String("value", g))
		} else if parsed < 0 {
			slog.Warn("LEGION_AUTH_FILE_GID must be non-negative, ignoring", slog.Int("value", parsed))
		} else {
			fileGID = parsed
		}
	}

	if fileGID < 0 && os.Geteuid() == 0 {
		if grp, err := user.LookupGroup(install.PicogridGroupName); err == nil {
			if gid, err := strconv.Atoi(grp.Gid); err == nil {
				fileGID = gid
			}
		}
	}
}

// ============================================================================
// Data Structures
// ============================================================================

type OAuthConfig struct {
	Issuer                string `json:"issuer"`
	TokenEndpoint         string `json:"token_endpoint"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
}

type StoredToken struct {
	AccessToken    string `json:"access_token,omitempty"`
	RefreshToken   string `json:"refresh_token,omitempty"`
	ExpiresAt      string `json:"expires_at,omitempty"`
	Scope          string `json:"scope,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
}

type Organization struct {
	OrganizationID   string `json:"organization_id"`
	OrganizationName string `json:"organization_name"`
	UserRole         string `json:"user_role"`
}

type Integration struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Version     string          `json:"version"`
	Description string          `json:"description"`
	Manifest    json.RawMessage `json:"manifest,omitempty"` // Keep as raw
	OAuthConfig *IntOAuthCfg    `json:"oauth_config,omitempty"`
}

type IntOAuthCfg struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret,omitempty"`
	RedirectURLs []string `json:"redirect_urls"`
	Scopes       []string `json:"scopes"`
}

type Manifest struct {
	Name        string              `json:"name"`
	Version     string              `json:"version"`
	Description string              `json:"description"`
	OAuthConfig ManifestOAuthConfig `json:"oauth_config"`
}

type PermissionRequest struct {
	// The resource type this permission applies to (e.g., "entity", "feed", "track", "integration")
	ResourceType string `json:"resource_type"`
	// The relation/role being requested (e.g., "viewer", "operator", "admin")
	Relation string `json:"relation"`
	// Human-readable description of why this permission is needed
	Description string `json:"description"`
}

type ManifestOAuthConfig struct {
	// Legacy scopes (optional, for backward compatibility)
	Scopes []string `json:"scopes,omitempty"`
	// Permissions (preferred - replaces scopes)
	Permissions []PermissionRequest `json:"permissions,omitempty"`
	// OAuth redirect URLs - required for software integrations only
	RedirectURLs []string `json:"redirect_urls,omitempty"`
}

type AppConfig struct {
	IntegrationID    string   `json:"integrationId"`
	ClientID         string   `json:"clientId"`
	ClientSecret     string   `json:"clientSecret,omitempty"`
	RedirectURL      string   `json:"redirectUrl"`
	OrganizationID   string   `json:"organizationId"`
	OrganizationName string   `json:"organizationName"`
	LegionBaseURL    string   `json:"legionBaseUrl"`
	Manifest         Manifest `json:"manifest"`
	AccessToken      string   `json:"accessToken,omitempty"`
}

type PagedIntegrations struct {
	Integrations []Integration `json:"integrations"`
	Total        int           `json:"total"`
	Offset       int           `json:"offset"`
}

type PagedOrganizations struct {
	Paging struct {
		Next     *int `json:"next"`
		Previous *int `json:"previous"`
	} `json:"paging"`
	Results    []Organization `json:"results"`
	TotalCount int            `json:"total_count"`
}

type EntitySearchResult struct {
	Results    []map[string]interface{} `json:"results"`
	TotalCount int                      `json:"total_count"`
}

// setupOpts holds CLI flag values for non-interactive setup.
type setupOpts struct {
	APIURL          string
	Username        string
	Password        string
	OrgID           string
	IntegrationName string
	Description     string
	Version         string
	RedirectURL     string
	AccessLevel     string
	EntityName      string
	EntityType      string
	CreateEntity    bool
	NonInteractive  bool
}

// setupFlagResult holds the parsed setup flags, separating storage-path
// (which is not part of setupOpts) from the rest.
type setupFlagResult struct {
	Opts        setupOpts
	StoragePath string
}

// registerSetupFlags registers all setup sub-command flags on fs.
// Both production code and tests call this to keep flag definitions in sync.
func registerSetupFlags(fs *flag.FlagSet) *setupFlagResult {
	r := &setupFlagResult{}
	fs.StringVar(&r.StoragePath, "storage-path", "", "Custom storage path")
	fs.StringVar(&r.Opts.APIURL, "api-url", "", "Legion API URL (skips environment selector)")
	fs.StringVar(&r.Opts.Username, "username", "", "Username for authentication")
	fs.StringVar(&r.Opts.Password, "password", "", "Password for authentication")
	fs.StringVar(&r.Opts.OrgID, "org-id", "", "Organization ID (skips org selector)")
	fs.StringVar(&r.Opts.IntegrationName, "integration-name", "", "Integration name")
	fs.StringVar(&r.Opts.Description, "description", "", "Integration description")
	fs.StringVar(&r.Opts.Version, "version", "", "Integration version")
	fs.StringVar(&r.Opts.RedirectURL, "redirect-url", "", "OAuth redirect URL")
	fs.StringVar(&r.Opts.AccessLevel, "access-level", "", "Access level: viewer/operator/admin")
	fs.StringVar(&r.Opts.EntityName, "entity-name", "", "Terminal entity name / serial number")
	fs.StringVar(&r.Opts.EntityType, "entity-type", "", "Terminal type: lander/helios/portal/dev-unit")
	fs.BoolVar(&r.Opts.CreateEntity, "create-entity", false, "Create terminal entity during setup")
	fs.BoolVar(&r.Opts.NonInteractive, "non-interactive", false, "Run without prompts, use flags and defaults")
	return r
}

// applySetupEnvDefaults fills empty string fields with LEGION_AUTH_* environment
// variables. Flags take precedence; env vars are fallbacks only.
//
// Mapping:
//
//	--storage-path     → LEGION_AUTH_STORAGE_PATH
//	--api-url          → LEGION_AUTH_API_URL
//	--username         → LEGION_AUTH_USERNAME
//	--password         → LEGION_AUTH_PASSWORD
//	--org-id           → LEGION_AUTH_ORG_ID
//	--integration-name → LEGION_AUTH_INTEGRATION_NAME
//	--description      → LEGION_AUTH_DESCRIPTION
//	--version          → LEGION_AUTH_VERSION
//	--redirect-url     → LEGION_AUTH_REDIRECT_URL
//	--access-level     → LEGION_AUTH_ACCESS_LEVEL
//	--entity-name      → LEGION_AUTH_ENTITY_NAME
//	--entity-type      → LEGION_AUTH_ENTITY_TYPE
//	--create-entity    → LEGION_AUTH_CREATE_ENTITY  ("true"/"1" to enable)
//	--non-interactive  → LEGION_AUTH_NON_INTERACTIVE ("true"/"1" to enable)
func applySetupEnvDefaults(r *setupFlagResult) {
	envStr := func(ptr *string, envKey string) {
		if *ptr == "" {
			if v := os.Getenv(envKey); v != "" {
				*ptr = v
			}
		}
	}
	envBool := func(ptr *bool, envKey string) {
		if !*ptr {
			if v := os.Getenv(envKey); v == "true" || v == "1" {
				*ptr = true
			}
		}
	}

	envStr(&r.StoragePath, "LEGION_AUTH_STORAGE_PATH")
	envStr(&r.Opts.APIURL, "LEGION_AUTH_API_URL")
	envStr(&r.Opts.APIURL, "LEGION_API_URL") // deprecated; prefer LEGION_AUTH_API_URL
	envStr(&r.Opts.Username, "LEGION_AUTH_USERNAME")
	envStr(&r.Opts.Password, "LEGION_AUTH_PASSWORD")
	envStr(&r.Opts.OrgID, "LEGION_AUTH_ORG_ID")
	envStr(&r.Opts.IntegrationName, "LEGION_AUTH_INTEGRATION_NAME")
	envStr(&r.Opts.Description, "LEGION_AUTH_DESCRIPTION")
	envStr(&r.Opts.Version, "LEGION_AUTH_VERSION")
	envStr(&r.Opts.RedirectURL, "LEGION_AUTH_REDIRECT_URL")
	envStr(&r.Opts.AccessLevel, "LEGION_AUTH_ACCESS_LEVEL")
	envStr(&r.Opts.EntityName, "LEGION_AUTH_ENTITY_NAME")
	envStr(&r.Opts.EntityType, "LEGION_AUTH_ENTITY_TYPE")
	envBool(&r.Opts.CreateEntity, "LEGION_AUTH_CREATE_ENTITY")
	envBool(&r.Opts.NonInteractive, "LEGION_AUTH_NON_INTERACTIVE")
}

// HTTPError represents an HTTP error response with status code
type HTTPError struct {
	StatusCode int
	Body       string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Body)
}

// ============================================================================
// Utility Functions
// ============================================================================

func printColored(text string, color string, bold bool) {
	if bold {
		fmt.Printf("%s%s%s%s\n", ColorBold, color, text, ColorReset)
	} else {
		fmt.Printf("%s%s%s\n", color, text, ColorReset)
	}
}

func printError(text string) {
	if strings.HasPrefix(text, "\n") {
		fmt.Println()
		text = strings.TrimPrefix(text, "\n")
	}
	printColored(fmt.Sprintf("✘ %s", text), ColorRed, false)
}

func printSuccess(text string) {
	if strings.HasPrefix(text, "\n") {
		fmt.Println()
		text = strings.TrimPrefix(text, "\n")
	}
	printColored(fmt.Sprintf("✔ %s", text), ColorGreen, false)
}

func printInfo(text string) {
	if strings.HasPrefix(text, "\n") {
		fmt.Println()
		text = strings.TrimPrefix(text, "\n")
	}
	printColored(fmt.Sprintf("ℹ %s", text), ColorBlue, false)
}

func printWarning(text string) {
	if strings.HasPrefix(text, "\n") {
		fmt.Println()
		text = strings.TrimPrefix(text, "\n")
	}
	printColored(fmt.Sprintf("⚠ %s", text), ColorYellow, false)
}

func confirmRecreateEntity(reason string, autoYes bool) bool {
	printWarning(reason)
	if autoYes {
		printInfo("Auto-confirming entity recreation (--non-interactive)")
		return true
	}
	choice := strings.ToLower(strings.TrimSpace(inputPrompt("Recreate terminal entity now? (y/N): ")))
	return choice == "y" || choice == "yes"
}

func inputPrompt(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	text, err := reader.ReadString('\n')
	if err != nil {
		if err == io.EOF {
			fmt.Println()
			printError("EOF on stdin (running non-interactively without required flags?)")
			os.Exit(1)
		}
		return ""
	}
	return strings.TrimSpace(text)
}

func readPasswordSimple(prompt string) string {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return ""
	}
	return string(password)
}

func makeRequest(method, urlStr string, data interface{}, headers map[string]string) ([]byte, error) {
	logger.Debug("HTTP request", slog.String("method", method), slog.String("url", urlStr))

	var body io.Reader
	if data != nil {
		if headers != nil && headers["Content-Type"] == "application/x-www-form-urlencoded" {
			if values, ok := data.(url.Values); ok {
				body = strings.NewReader(values.Encode())
			} else if m, ok := data.(map[string]string); ok {
				vals := url.Values{}
				for k, v := range m {
					vals.Set(k, v)
				}
				body = strings.NewReader(vals.Encode())
			}
		} else {
			jsonData, err := json.Marshal(data)
			if err != nil {
				return nil, err
			}
			body = bytes.NewBuffer(jsonData)
			if headers == nil {
				headers = make(map[string]string)
			}
			headers["Content-Type"] = "application/json"
		}
	}

	req, err := http.NewRequest(method, urlStr, body)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return respBody, &HTTPError{StatusCode: resp.StatusCode, Body: string(respBody)}
	}

	return respBody, nil
}

func makeRequestJSON(method, urlStr string, data interface{}, headers map[string]string, result interface{}) error {
	respBody, err := makeRequest(method, urlStr, data, headers)
	if err != nil {
		return err
	}
	return json.Unmarshal(respBody, result)
}

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func generateCodeVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64URLEncode(b), nil
}

func generateCodeChallenge(verifier string) string {
	h := sha256.New()
	h.Write([]byte(verifier))
	return base64URLEncode(h.Sum(nil))
}

func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64URLEncode(b), nil
}

func setupStorage(customPath string) error {
	storageBase := os.Getenv("STORAGE_BASE_PATH")
	if storageBase == "" {
		storageBase = "/etc"
	}
	storagePathEnv := os.Getenv("STORAGE_PATH")

	var sp string
	if customPath != "" {
		sp = customPath
	} else if storagePathEnv != "" {
		sp = storagePathEnv
	} else {
		sp = filepath.Join(storageBase, "picogrid", "auth")
	}

	StoragePath = sp
	ConfigFile = filepath.Join(StoragePath, "oauth_config.json")
	AccessTokenFile = filepath.Join(StoragePath, "access_token.json")
	RefreshTokenFile = filepath.Join(StoragePath, "refresh_token.json")
	TerminalEntityFile = filepath.Join(StoragePath, "terminal_entity.json")
	LegionOAuthPath = filepath.Join(filepath.Dir(StoragePath), "legion-auth")

	// Create directory
	if err := os.MkdirAll(StoragePath, 0755); err != nil {
		return fmt.Errorf("failed to create storage path %s: %w", StoragePath, err)
	}

	setOwnership(StoragePath)

	// Check write permission
	testFile := filepath.Join(StoragePath, ".write_test")
	if err := os.WriteFile(testFile, []byte("test"), 0600); err != nil {
		return fmt.Errorf("storage path %s is not writable: %w", StoragePath, err)
	}
	_ = os.Remove(testFile)

	// Handle Symlink
	if _, err := os.Lstat(LegionOAuthPath); err == nil {
		_ = os.Remove(LegionOAuthPath)
	}
	if err := os.Symlink(StoragePath, LegionOAuthPath); err != nil {
		logger.Warn("failed to create symlink (non-fatal)", slog.String("error", err.Error()))
	}
	return nil
}

func setOwnership(path string) {
	pgUser, err := user.Lookup("pg")
	if err != nil {
		logger.Debug("user 'pg' not found, keeping default ownership")
		return
	}

	uid, err := strconv.Atoi(pgUser.Uid)
	if err != nil {
		logger.Warn("failed to parse pg user UID", slog.String("error", err.Error()))
		return
	}
	gid, err := strconv.Atoi(pgUser.Gid)
	if err != nil {
		logger.Warn("failed to parse pg user GID", slog.String("error", err.Error()))
		return
	}

	if err := os.Chown(path, uid, gid); err != nil {
		logger.Warn("insufficient permissions to chown", slog.String("path", path), slog.String("error", err.Error()))
		return
	}
	// #nosec G302 -- directory requires execute bit for traversal by the service user/group.
	if err := os.Chmod(path, 0755); err != nil {
		logger.Warn("failed to chmod", slog.String("path", path), slog.String("error", err.Error()))
	}

	// Also chown all files inside the directory so the pg user can read them
	// (fixes root-owned files left by sudo runs)
	entries, err := os.ReadDir(path)
	if err == nil {
		for _, e := range entries {
			fp := filepath.Join(path, e.Name())
			fi, stErr := os.Lstat(fp)
			if stErr != nil {
				logger.Warn("failed to lstat file", slog.String("path", fp), slog.String("error", stErr.Error()))
				continue
			}
			if fi.Mode()&os.ModeSymlink != 0 {
				logger.Warn("skipping symlink in storage dir", slog.String("path", fp))
				continue
			}
			fileGroupID := gid
			if fileGID >= 0 {
				fileGroupID = fileGID
			}
			if chErr := os.Chown(fp, uid, fileGroupID); chErr != nil {
				logger.Warn("failed to chown file", slog.String("path", fp), slog.String("error", chErr.Error()))
			}
			if !fi.IsDir() {
				if chErr := os.Chmod(fp, filePermissions); chErr != nil {
					logger.Warn("failed to chmod file", slog.String("path", fp), slog.String("error", chErr.Error()))
				}
			}
		}
	}

	parent := filepath.Dir(path)
	if _, err := os.Stat(parent); err == nil {
		if err := os.Chown(parent, uid, gid); err != nil {
			logger.Warn("failed to chown parent", slog.String("path", parent), slog.String("error", err.Error()))
		}
		// #nosec G302 -- parent directory requires execute bit for traversal.
		if err := os.Chmod(parent, 0755); err != nil {
			logger.Warn("failed to chmod parent", slog.String("path", parent), slog.String("error", err.Error()))
		}
	}
	logger.Info("set ownership to pg user", slog.String("path", path))
}

func ensureRedirectUriAvailable(redirectURI string) string {
	parsed, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}

	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "80"
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), time.Second)
	if err == nil {
		_ = conn.Close()
		// Port in use, find random
		listener, err := net.Listen("tcp", ":0")
		if err != nil {
			return redirectURI
		}
		defer func() { _ = listener.Close() }()
		port = strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)

		parsed.Host = net.JoinHostPort(host, port)
		newURI := parsed.String()
		logger.Info("port in use, switching redirect URI", slog.String("new_uri", newURI))
		return newURI
	}
	return redirectURI
}

// ============================================================================
// Interactive Setup
// ============================================================================

func selectLegionEnvironment() string {
	envs := []struct{ Name, URL string }{
		{"Commercial", "https://legion.picogrid.com"},
		{"Local", "http://localhost:9876"},
		{"Other", ""},
	}

	printColored("\nSelect Legion Environment:", ColorCyan, false)
	for i, env := range envs {
		if env.URL != "" {
			fmt.Printf("  %d. %s (%s)\n", i+1, env.Name, env.URL)
		} else {
			fmt.Printf("  %d. %s\n", i+1, env.Name)
		}
	}

	for {
		choice := inputPrompt("\nSelect environment (number): ")
		idx, err := strconv.Atoi(choice)
		if err == nil && idx > 0 && idx <= len(envs) {
			selected := envs[idx-1]
			if selected.URL != "" {
				printSuccess(fmt.Sprintf("Selected: %s", selected.Name))
				return selected.URL
			}
			// Custom
			for {
				custom := inputPrompt("\nLegion API URL: ")
				if strings.HasPrefix(custom, "http") {
					return strings.TrimRight(custom, "/")
				}
				printError("Invalid URL. Must start with http:// or https://")
			}
		}
		printError("Invalid selection.")
	}
}

func getWellKnownConfig(legionAPIURL string, nonInteractive bool) OAuthConfig {
	wellKnownURL := fmt.Sprintf("%s/v3/.well-known/oauth-authorization-server", legionAPIURL)
	printInfo(fmt.Sprintf("Fetching OAuth configuration from %s", wellKnownURL))

	var config OAuthConfig
	err := makeRequestJSON("GET", wellKnownURL, nil, nil, &config)
	if err != nil || config.TokenEndpoint == "" {
		if nonInteractive {
			printError(fmt.Sprintf("Failed to fetch OAuth config from %s (cannot prompt for fallback in non-interactive mode)", wellKnownURL))
			os.Exit(1)
		}
		printWarning("Using fallback configuration")
		return getKeycloakFallbackConfig()
	}

	printSuccess(fmt.Sprintf("Found Keycloak at: %s", config.Issuer))

	if nonInteractive {
		return config
	}

	choice := inputPrompt("Do you want to override the Keycloak URL? (y/N): ")
	if strings.ToLower(choice) == "y" {
		return getKeycloakFallbackConfig()
	}
	return config
}

func getKeycloakFallbackConfig() OAuthConfig {
	keycloakURL := os.Getenv("KEYCLOAK_URL")
	if keycloakURL == "" {
		manual := inputPrompt("Enter Keycloak URL (default http://localhost:8099): ")
		if manual != "" {
			keycloakURL = manual
		} else {
			keycloakURL = "http://localhost:8099"
		}
	}
	return OAuthConfig{
		Issuer:                fmt.Sprintf("%s/realms/legion", keycloakURL),
		TokenEndpoint:         fmt.Sprintf("%s/realms/legion/protocol/openid-connect/token", keycloakURL),
		AuthorizationEndpoint: fmt.Sprintf("%s/realms/legion/protocol/openid-connect/auth", keycloakURL),
	}
}

func authenticateUser(tokenEndpoint, username, password string) (string, error) {
	clientID := os.Getenv("KEYCLOAK_CLIENT_ID")
	if clientID == "" {
		clientID = "frontend...orion"
	}

	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("grant_type", "password")
	data.Set("username", username)
	data.Set("password", password)

	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}

	var resp TokenResponse
	err := makeRequestJSON("POST", tokenEndpoint, data, headers, &resp)
	if err != nil {
		return "", err
	}
	return resp.AccessToken, nil
}

func getOrganizationsPage(legionAPIURL, token string, offset, limit int) (*PagedOrganizations, error) {
	headers := map[string]string{"Authorization": "Bearer " + token}
	var resp PagedOrganizations
	err := makeRequestJSON("GET", fmt.Sprintf("%s/v3/me/orgs?offset=%d&limit=%d", legionAPIURL, offset, limit), nil, headers, &resp)
	return &resp, err
}

func getOrganization(legionAPIURL, token, orgID string) (Organization, error) {
	page, err := getOrganizationsPage(legionAPIURL, token, 0, 50)
	if err != nil {
		return Organization{}, fmt.Errorf("fetch organizations: %w", err)
	}
	org, ok := findOrgByID(page.Results, orgID)
	if !ok {
		return Organization{}, fmt.Errorf("organization %q not found in available organizations", orgID)
	}
	return org, nil
}

func findOrgByID(orgs []Organization, id string) (Organization, bool) {
	for _, org := range orgs {
		if org.OrganizationID == id {
			return org, true
		}
	}
	return Organization{}, false
}

func paginationStep(resultCount, fallback int) int {
	if resultCount > 0 {
		return resultCount
	}
	return fallback
}

func selectOrganization(legionAPIURL, token string) (Organization, error) {
	printColored("\nAvailable organizations:", ColorCyan, false)
	pageSize := orgSelectionPageSize
	offset := 0
	var offsetHistory []int
	pageIndex := 1

	for {
		page, err := getOrganizationsPage(legionAPIURL, token, offset, pageSize)
		if err != nil {
			return Organization{}, err
		}

		if len(page.Results) == 0 {
			if offset == 0 {
				return Organization{}, fmt.Errorf("no organizations found")
			}
			printError("No more organizations found.")
			if len(offsetHistory) > 0 {
				offset = offsetHistory[len(offsetHistory)-1]
				offsetHistory = offsetHistory[:len(offsetHistory)-1]
				pageIndex = max(1, pageIndex-1)
			} else {
				offset = max(0, offset-pageSize)
			}
			continue
		}

		total := page.TotalCount
		if total < len(page.Results) {
			total = len(page.Results)
		}
		totalPages := (total + pageSize - 1) / pageSize
		if totalPages < 1 {
			totalPages = 1
		}
		if totalPages < pageIndex {
			totalPages = pageIndex
		}

		printInfo(fmt.Sprintf("Page %d of %d (showing %d of %d)", pageIndex, totalPages, len(page.Results), total))

		for i, org := range page.Results {
			fmt.Printf("  %d. %s (%s)\n", i+1, org.OrganizationName, org.OrganizationID)
		}

		hasPrev := page.Paging.Previous != nil || offset > 0
		hasNext := page.Paging.Next != nil

		optIdx := len(page.Results) + 1
		nextOpt, prevOpt := 0, 0

		if hasNext {
			fmt.Printf("  %d. Next page\n", optIdx)
			nextOpt = optIdx
			optIdx++
		}
		if hasPrev {
			fmt.Printf("  %d. Previous page\n", optIdx)
			prevOpt = optIdx
		}

		choice := inputPrompt("\nSelect organization (number): ")
		idx, convErr := strconv.Atoi(choice)
		if convErr != nil {
			printError("Invalid selection.")
			continue
		}

		if idx > 0 && idx <= len(page.Results) {
			return page.Results[idx-1], nil
		}
		if nextOpt > 0 && idx == nextOpt {
			offsetHistory = append(offsetHistory, offset)
			offset += paginationStep(len(page.Results), pageSize)
			pageIndex++
			continue
		}
		if prevOpt > 0 && idx == prevOpt {
			if len(offsetHistory) > 0 {
				offset = offsetHistory[len(offsetHistory)-1]
				offsetHistory = offsetHistory[:len(offsetHistory)-1]
			} else {
				offset = max(0, offset-paginationStep(len(page.Results), pageSize))
			}
			pageIndex = max(1, pageIndex-1)
			continue
		}

		printError("Invalid selection.")
	}
}

func createManifestInteractively(opts setupOpts) Manifest {
	printColored("\nIntegration Configuration", ColorCyan, true)

	if _, err := os.Stat("manifest.json"); err == nil {
		if opts.NonInteractive {
			content, _ := os.ReadFile("manifest.json")
			var m Manifest
			if json.Unmarshal(content, &m) == nil {
				printSuccess("Using existing manifest.json")
				return m
			}
		} else {
			use := inputPrompt("Found manifest.json. Use existing? (Y/n): ")
			if use == "" || strings.ToLower(use) == "y" {
				content, _ := os.ReadFile("manifest.json")
				var m Manifest
				if json.Unmarshal(content, &m) == nil {
					return m
				}
			}
		}
	}

	defaultName := "Portal Integration"
	var name string
	if opts.IntegrationName != "" {
		name = opts.IntegrationName
	} else if opts.NonInteractive {
		name = defaultName
	} else {
		name = inputPrompt(fmt.Sprintf("   Name [%s]: ", defaultName))
		if name == "" {
			name = defaultName
		}
	}

	defaultDesc := "OAuth integration for portal authentication"
	var desc string
	if opts.Description != "" {
		desc = opts.Description
	} else if opts.NonInteractive {
		desc = defaultDesc
	} else {
		desc = inputPrompt("   Description [OAuth integration...]: ")
		if desc == "" {
			desc = defaultDesc
		}
	}

	defaultVer := "1.0.0"
	var ver string
	if opts.Version != "" {
		ver = opts.Version
	} else if opts.NonInteractive {
		ver = defaultVer
	} else {
		ver = inputPrompt("   Version [1.0.0]: ")
		if ver == "" {
			ver = defaultVer
		}
	}

	defaultRedirect := "http://localhost:8000/oauth_callback"
	var redirect string
	if opts.RedirectURL != "" {
		redirect = opts.RedirectURL
	} else if opts.NonInteractive {
		redirect = defaultRedirect
	} else {
		redirect = inputPrompt("   Redirect URL [http://localhost:8000/oauth_callback]: ")
		if redirect == "" {
			redirect = defaultRedirect
		}
	}

	redirect = ensureRedirectUriAvailable(redirect)

	var permissions []PermissionRequest
	var scopes []string

	if opts.AccessLevel != "" {
		switch opts.AccessLevel {
		case "viewer", "operator", "admin":
			permissions = getPermissionsForRelation(opts.AccessLevel)
		default:
			printWarning(fmt.Sprintf("Unknown access level %q, defaulting to operator", opts.AccessLevel))
			permissions = getPermissionsForRelation("operator")
		}
	} else if opts.NonInteractive {
		permissions = getPermissionsForRelation("operator")
	} else {
		// Ask if they want to use permissions or legacy scopes
		printColored("\nPermission Configuration", ColorCyan, false)
		printInfo("Choose authorization method:")
		fmt.Println("  1. Permissions (Recommended - fine-grained access control)")
		fmt.Println("  2. Legacy Scopes (Deprecated - for backward compatibility)")

		authChoice := inputPrompt("\nSelect (1 or 2) [1]: ")
		if authChoice == "" {
			authChoice = "1"
		}

		if authChoice == "1" {
			printColored("\nSelect permissions to grant:", ColorCyan, false)
			permissions = selectPermissionsWithPresets()
		} else {
			printWarning("Using deprecated scopes. Consider migrating to permissions.")
			scopes = []string{
				"offline_access",
				"entities:read",
				"entities:write",
				"feeds:read",
				"feeds:write",
				"tasking:read",
				"tasking:write",
				"organizations:read",
			}
		}
	}

	return Manifest{
		Name:        name,
		Version:     ver,
		Description: desc,
		OAuthConfig: ManifestOAuthConfig{
			Permissions:  permissions,
			Scopes:       scopes,
			RedirectURLs: []string{redirect},
		},
	}
}

// ============================================================================
// Permission Selection Helpers
// ============================================================================

func selectPermissions() []PermissionRequest {
	availablePermissions := []struct {
		ResourceType string
		Relation     string
		Description  string
		Display      string
	}{
		{"org", "viewer", "Read organization information", "Org: Viewer"},
		{"org", "operator", "Manage organization settings", "Org: Operator"},
		{"org", "admin", "Full organization admin access", "Org: Admin"},
		{"feed", "viewer", "Read feed data and telemetry", "Feed: Viewer"},
		{"feed", "operator", "Manage feeds and data streams", "Feed: Operator"},
		{"feed", "admin", "Full feed admin access", "Feed: Admin"},
		{"entity", "viewer", "Read entity information", "Entity: Viewer"},
		{"entity", "operator", "Create and manage entities", "Entity: Operator"},
		{"entity", "admin", "Full entity admin access", "Entity: Admin"},
		{"integration", "viewer", "Read integration information", "Integration: Viewer"},
		{"integration", "operator", "Manage integrations", "Integration: Operator"},
		{"integration", "admin", "Full integration admin access", "Integration: Admin"},
		{"event", "viewer", "Read event information", "Event: Viewer"},
		{"event", "operator", "Manage events", "Event: Operator"},
		{"event", "admin", "Full event admin access", "Event: Admin"},
		{"track", "viewer", "Read track information", "Track: Viewer"},
		{"track", "operator", "Manage tracks", "Track: Operator"},
		{"track", "admin", "Full track admin access", "Track: Admin"},
	}

	printInfo("Available permissions:")
	for i, perm := range availablePermissions {
		fmt.Printf("  %2d. %-25s (%s)\n", i+1, perm.Display, perm.Description)
	}

	printInfo("\nEnter permission numbers separated by commas (e.g., 1,2,3)")
	printInfo("Or press Enter for default permissions (Operator access on all resources)")

	selection := inputPrompt("Permissions: ")

	var selectedPerms []PermissionRequest

	if selection == "" {
		// Default permissions - operator on all resource types
		selectedPerms = getPermissionsForRelation("operator")
	} else {
		// Parse selected indices
		indices := strings.Split(selection, ",")
		seen := make(map[int]bool)

		for _, idxStr := range indices {
			idxStr = strings.TrimSpace(idxStr)
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(availablePermissions) {
				printWarning(fmt.Sprintf("Invalid selection: %s", idxStr))
				continue
			}

			if seen[idx] {
				continue // Skip duplicates
			}
			seen[idx] = true

			perm := availablePermissions[idx-1]
			selectedPerms = append(selectedPerms, PermissionRequest{
				ResourceType: perm.ResourceType,
				Relation:     perm.Relation,
				Description:  perm.Description,
			})
		}
	}

	printSuccess(fmt.Sprintf("Selected %d permissions:", len(selectedPerms)))
	for _, perm := range selectedPerms {
		fmt.Printf("  • %s:%s - %s\n", perm.ResourceType, perm.Relation, perm.Description)
	}

	return selectedPerms
}

func getPermissionsForRelation(relation string) []PermissionRequest {
	resourceTypes := []struct {
		Type        string
		Description string
	}{
		{"org", "Organization access"},
		{"feed", "Feed data access"},
		{"entity", "Entity access"},
		{"integration", "Integration access"},
		{"event", "Event access"},
		{"track", "Track access"},
	}

	var permissions []PermissionRequest
	for _, rt := range resourceTypes {
		permissions = append(permissions, PermissionRequest{
			ResourceType: rt.Type,
			Relation:     relation,
			Description:  fmt.Sprintf("%s (%s)", rt.Description, relation),
		})
	}
	return permissions
}

func selectPermissionsWithPresets() []PermissionRequest {
	printColored("\nSelect Access Level:", ColorCyan, false)
	fmt.Println("  1. Viewer   - Read-only access to all resources")
	fmt.Println("  2. Operator - Create and manage resources")
	fmt.Println("  3. Admin    - Full administrative access")
	fmt.Println("  4. Custom   - Select individual permissions")

	choice := inputPrompt("\nSelect access level (1-4) [2]: ")
	if choice == "" {
		choice = "2"
	}

	var permissions []PermissionRequest
	switch choice {
	case "1":
		permissions = getPermissionsForRelation("viewer")
		printSuccess("Selected: Viewer access")
	case "2":
		permissions = getPermissionsForRelation("operator")
		printSuccess("Selected: Operator access")
	case "3":
		permissions = getPermissionsForRelation("admin")
		printSuccess("Selected: Admin access")
	case "4":
		return selectPermissions()
	default:
		printWarning("Invalid choice, using Operator access")
		permissions = getPermissionsForRelation("operator")
	}

	for _, perm := range permissions {
		fmt.Printf("  • %s:%s\n", perm.ResourceType, perm.Relation)
	}

	return permissions
}

func createIntegration(apiURL, token, orgID string, manifest Manifest) (*Integration, error) {
	headers := map[string]string{
		"Authorization": "Bearer " + token,
		"X-ORG-ID":      orgID,
		"Content-Type":  "application/json",
	}

	data := map[string]interface{}{"manifest_content": manifest}

	var integ Integration
	err := makeRequestJSON("POST", fmt.Sprintf("%s/v3/integrations", apiURL), data, headers, &integ)
	if err != nil {
		return nil, err
	}
	return &integ, nil
}

func findIntegrationByName(apiURL, token, orgID, name string) *Integration {
	headers := map[string]string{"Authorization": "Bearer " + token, "X-ORG-ID": orgID}
	pageSize := 50
	offset := 0

	for {
		urlStr := fmt.Sprintf("%s/v3/integrations?offset=%d&limit=%d", apiURL, offset, pageSize)
		var page PagedIntegrations
		if err := makeRequestJSON("GET", urlStr, nil, headers, &page); err != nil {
			printError(fmt.Sprintf("Failed to list integrations: %v", err))
			return nil
		}
		for i := range page.Integrations {
			if page.Integrations[i].Name == name {
				return &page.Integrations[i]
			}
		}
		offset += len(page.Integrations)
		if offset >= page.Total || len(page.Integrations) == 0 {
			break
		}
	}

	printError(fmt.Sprintf("Integration %q not found", name))
	return nil
}

func selectExistingIntegrationPaginated(apiURL, token, orgID string) *Integration {
	printColored("\nExisting Integrations (paged):", ColorCyan, false)
	pageSize := integrationPageSize
	offset := 0
	var offsetHistory []int
	pageIndex := 1

	for {
		urlStr := fmt.Sprintf("%s/v3/integrations?offset=%d&limit=%d", apiURL, offset, pageSize)
		headers := map[string]string{"Authorization": "Bearer " + token, "X-ORG-ID": orgID}

		var page PagedIntegrations
		if err := makeRequestJSON("GET", urlStr, nil, headers, &page); err != nil {
			printError(fmt.Sprintf("Failed to fetch: %v", err))
			return nil
		}

		if len(page.Integrations) == 0 {
			printError("No integrations found.")
			return nil
		}

		total := page.Total
		totalPages := (total + pageSize - 1) / pageSize
		if totalPages < 1 {
			totalPages = 1
		}
		if totalPages < pageIndex {
			totalPages = pageIndex
		}

		printInfo(fmt.Sprintf("Page %d of %d (showing %d of %d)", pageIndex, totalPages, len(page.Integrations), total))

		for i, integ := range page.Integrations {
			fmt.Printf("  %d. %s (v%s)\n     ID: %s\n", i+1, integ.Name, integ.Version, integ.ID)
		}

		hasPrev := offset > 0
		hasNext := (offset + len(page.Integrations)) < total

		optIdx := len(page.Integrations) + 1
		nextOpt, prevOpt := 0, 0

		if hasNext {
			fmt.Printf("  %d. Next page\n", optIdx)
			nextOpt = optIdx
			optIdx++
		}
		if hasPrev {
			fmt.Printf("  %d. Previous page\n", optIdx)
			prevOpt = optIdx
			optIdx++
		}
		fmt.Printf("  %d. Exit\n", optIdx)
		exitOpt := optIdx

		choice := inputPrompt("\nSelect (number): ")
		idx, err := strconv.Atoi(choice)
		if err != nil {
			continue
		}

		if idx > 0 && idx <= len(page.Integrations) {
			return &page.Integrations[idx-1]
		}
		if nextOpt > 0 && idx == nextOpt {
			offsetHistory = append(offsetHistory, offset)
			offset += paginationStep(len(page.Integrations), pageSize)
			pageIndex++
			continue
		}
		if prevOpt > 0 && idx == prevOpt {
			if len(offsetHistory) > 0 {
				offset = offsetHistory[len(offsetHistory)-1]
				offsetHistory = offsetHistory[:len(offsetHistory)-1]
			} else {
				offset = max(0, offset-paginationStep(len(page.Integrations), pageSize))
			}
			pageIndex = max(1, pageIndex-1)
			continue
		}
		if idx == exitOpt {
			return nil
		}
	}
}

func getIntegrationOAuthConfig(apiURL, token, orgID, integID string) (*IntOAuthCfg, error) {
	headers := map[string]string{"Authorization": "Bearer " + token, "X-ORG-ID": orgID}
	var cfg IntOAuthCfg
	err := makeRequestJSON("GET", fmt.Sprintf("%s/v3/integrations/%s/oauth", apiURL, integID), nil, headers, &cfg)
	return &cfg, err
}

func regenerateClientSecret(apiURL, token, orgID, integID string) (string, error) {
	headers := map[string]string{"Authorization": "Bearer " + token, "X-ORG-ID": orgID}
	var resp struct {
		ClientSecret string `json:"client_secret"`
	}
	err := makeRequestJSON("POST", fmt.Sprintf("%s/v3/integrations/%s/oauth/secret/regenerate", apiURL, integID), map[string]string{}, headers, &resp)
	return resp.ClientSecret, err
}

// ============================================================================
// OAuth Server & Flow
// ============================================================================

type OAuthResult struct {
	Code             string
	State            string
	Error            string
	ErrorDescription string
}

func performHeadlessOAuthFlow(config AppConfig, userToken string) bool {
	printInfo("\n→ Starting headless OAuth flow...")

	// 1. Start Local Server
	redirectURL, _ := url.Parse(config.RedirectURL)
	port := redirectURL.Port()
	if port == "" {
		port = "80"
	}

	mux := http.NewServeMux()
	resultChan := make(chan OAuthResult, 1)

	mux.HandleFunc(redirectURL.Path, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		res := OAuthResult{
			Code:             q.Get("code"),
			State:            q.Get("state"),
			Error:            q.Get("error"),
			ErrorDescription: q.Get("error_description"),
		}
		resultChan <- res

		msg := "<h1>✅ OAuth Authorization Successful</h1><p>You can close this window.</p>"
		if res.Error != "" {
			msg = fmt.Sprintf("<h1>❌ Failed</h1><p>%s: %s</p>", res.Error, res.ErrorDescription)
		}
		_, _ = w.Write([]byte(msg))
	})

	server := &http.Server{
		Addr:    "127.0.0.1:" + port,
		Handler: mux,
	}

	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			logger.Error("OAuth callback server error", slog.String("error", err.Error()))
		}
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			logger.Warn("OAuth callback server shutdown error", slog.String("error", err.Error()))
		}
	}()

	// 2. Prepare PKCE
	verifier, err := generateCodeVerifier()
	if err != nil {
		printError(fmt.Sprintf("Failed to generate code verifier: %v", err))
		return false
	}
	challenge := generateCodeChallenge(verifier)
	state, err := generateState()
	if err != nil {
		printError(fmt.Sprintf("Failed to generate state: %v", err))
		return false
	}

	// 3. Construct Auth URL
	scopes := strings.Join(config.Manifest.OAuthConfig.Scopes, " ")
	params := url.Values{}
	params.Set("client_id", config.ClientID)
	params.Set("redirect_uri", config.RedirectURL)
	params.Set("response_type", "code")
	params.Set("scope", scopes)
	params.Set("state", state)
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", "S256")

	authURL := fmt.Sprintf("%s/v3/integrations/oauth/authorize?%s", config.LegionBaseURL, params.Encode())

	// 4. Make Request with User Token (Headless trigger)
	printInfo("→ Making authorization request...")

	req, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		printError(fmt.Sprintf("Failed to create auth request: %v", err))
		return false
	}
	req.Header.Set("Authorization", "Bearer "+userToken)
	req.Header.Set("X-ORG-ID", config.OrganizationID)

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Allow redirects
			return nil
		},
	}

	// This request will follow the redirect to localhost, which hits our server above
	resp, err := client.Do(req)
	if err != nil {
		// It might fail if the client can't connect to localhost (e.g. invalid certs or something),
		// but typically it succeeds or at least the server gets hit.
		logger.Debug("auth request finished", slog.String("error", err.Error()))
	} else {
		_ = resp.Body.Close()
	}

	// 5. Wait for result
	select {
	case res := <-resultChan:
		if res.Error != "" {
			printError(fmt.Sprintf("OAuth error: %s", res.Error))
			return false
		}
		if res.State != state {
			printError("State mismatch!")
			return false
		}
		return exchangeCodeForTokens(config, res.Code, verifier)
	case <-time.After(30 * time.Second):
		printError("Timeout waiting for OAuth callback")
		return false
	}
}

func exchangeCodeForTokens(config AppConfig, code, verifier string) bool {
	printInfo("→ Exchanging code for tokens...")

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", config.ClientID)
	data.Set("redirect_uri", config.RedirectURL)
	data.Set("code_verifier", verifier)
	if config.ClientSecret != "" {
		data.Set("client_secret", config.ClientSecret)
	}

	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"X-ORG-ID":     config.OrganizationID,
	}

	var resp TokenResponse
	urlStr := fmt.Sprintf("%s/v3/integrations/oauth/token", config.LegionBaseURL)

	if err := makeRequestJSON("POST", urlStr, data, headers, &resp); err != nil {
		printError(fmt.Sprintf("Token exchange failed: %v", err))
		return false
	}

	expiresAt := time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second)

	// Save Token
	tokenData := StoredToken{
		AccessToken:    resp.AccessToken,
		RefreshToken:   resp.RefreshToken,
		ExpiresAt:      expiresAt.Format(time.RFC3339),
		Scope:          resp.Scope,
		OrganizationID: config.OrganizationID,
	}

	if err := saveJSON(AccessTokenFile, tokenData); err != nil {
		printError(fmt.Sprintf("Failed to save access token: %v", err))
		return false
	}

	if resp.RefreshToken != "" {
		if err := saveJSON(RefreshTokenFile, StoredToken{
			RefreshToken:   resp.RefreshToken,
			OrganizationID: config.OrganizationID,
		}); err != nil {
			printError(fmt.Sprintf("Failed to save refresh token: %v", err))
		}
	}

	printSuccess("OAuth flow complete!")
	return true
}
func saveJSON(path string, data interface{}) error {
	file, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	// Write with configured permissions (default 0640)
	if err := os.WriteFile(path, file, filePermissions); err != nil {
		return fmt.Errorf("failed to write file %s: %w", path, err)
	}

	// Explicitly set permissions to ensure it sticks (overriding umask if needed)
	if err := os.Chmod(path, filePermissions); err != nil {
		return fmt.Errorf("failed to set file permissions for %s: %w", path, err)
	}

	// Set group ownership if configured via LEGION_AUTH_FILE_GID
	if fileGID >= 0 {
		if err := os.Chown(path, -1, fileGID); err != nil {
			return fmt.Errorf("failed to set group ownership on %s: %w", path, err)
		}
	}

	return nil
}

// ============================================================================
// Token Refresh Logic
// ============================================================================

func shouldRefreshToken() bool {
	content, err := os.ReadFile(AccessTokenFile)
	if err != nil {
		// File missing or unreadable — need a fresh token
		return true
	}

	var t StoredToken
	if json.Unmarshal(content, &t) != nil {
		return true
	}

	expires, err := time.Parse(time.RFC3339, t.ExpiresAt)
	if err != nil {
		return true
	}

	remaining := time.Until(expires)
	return remaining < 5*time.Minute
}

func refreshAccessToken() bool {
	printColored("\n→ REFRESHING TOKEN", ColorYellow, true)

	// Read Refresh Token
	rContent, err := os.ReadFile(RefreshTokenFile)
	if err != nil {
		return false
	}
	var rToken StoredToken
	if err := json.Unmarshal(rContent, &rToken); err != nil {
		printError(fmt.Sprintf("Failed to unmarshal refresh token from %s: %v", RefreshTokenFile, err))
		return false
	}

	// Read Config
	cContent, err := os.ReadFile(ConfigFile)
	if err != nil {
		return false
	}
	var config AppConfig
	if err := json.Unmarshal(cContent, &config); err != nil {
		printError(fmt.Sprintf("Failed to unmarshal config from %s: %v", ConfigFile, err))
		return false
	}

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", rToken.RefreshToken)
	data.Set("client_id", config.ClientID)
	if config.ClientSecret != "" {
		data.Set("client_secret", config.ClientSecret)
	}

	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"X-ORG-ID":     rToken.OrganizationID,
	}

	var resp TokenResponse
	urlStr := fmt.Sprintf("%s/v3/integrations/oauth/token", config.LegionBaseURL)

	if err := makeRequestJSON("POST", urlStr, data, headers, &resp); err != nil {
		printError(fmt.Sprintf("Refresh failed: %v", err))
		return false
	}

	expiresAt := time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second)

	tData := StoredToken{
		AccessToken:    resp.AccessToken,
		ExpiresAt:      expiresAt.Format(time.RFC3339),
		Scope:          resp.Scope,
		OrganizationID: rToken.OrganizationID,
	}
	if err := saveJSON(AccessTokenFile, tData); err != nil {
		printError(fmt.Sprintf("Failed to save access token: %v", err))
		return false
	}

	if resp.RefreshToken != "" {
		if err := saveJSON(RefreshTokenFile, StoredToken{
			RefreshToken:   resp.RefreshToken,
			OrganizationID: rToken.OrganizationID,
		}); err != nil {
			printError(fmt.Sprintf("Failed to save refresh token: %v", err))
		}
	}

	// Update Config
	config.AccessToken = resp.AccessToken
	if err := saveJSON(ConfigFile, config); err != nil {
		printError(fmt.Sprintf("Failed to update config file: %v", err))
	}

	printSuccess(fmt.Sprintf("Token Refreshed! Expires in %v", time.Duration(resp.ExpiresIn)*time.Second))
	return true
}
func interactiveSetup(opts setupOpts) error {
	// Upfront validation for non-interactive mode: fail fast on missing required flags.
	if opts.NonInteractive {
		var missing []string
		if opts.APIURL == "" {
			missing = append(missing, "--api-url")
		}
		if opts.Username == "" {
			missing = append(missing, "--username")
		}
		if opts.Password == "" {
			missing = append(missing, "--password")
		}
		if opts.OrgID == "" {
			missing = append(missing, "--org-id")
		}
		if opts.CreateEntity {
			if opts.EntityName == "" {
				missing = append(missing, "--entity-name")
			}
			if opts.EntityType == "" {
				missing = append(missing, "--entity-type")
			}
		}
		if len(missing) > 0 {
			return fmt.Errorf("--non-interactive requires flags: %s", strings.Join(missing, ", "))
		}
	}

	// Validate --entity-type value early (applies to both interactive and non-interactive).
	if opts.EntityType != "" {
		valid := false
		for _, t := range validEntityTypes {
			if t == opts.EntityType {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("unknown entity type %q, must be one of: %s", opts.EntityType, strings.Join(validEntityTypes, ", "))
		}
	}

	// Validate --access-level value early (applies to both interactive and non-interactive).
	if opts.AccessLevel != "" {
		switch opts.AccessLevel {
		case "viewer", "operator", "admin":
		default:
			return fmt.Errorf("unknown access level %q, must be one of: viewer, operator, admin", opts.AccessLevel)
		}
	}

	apiURL := opts.APIURL
	if apiURL == "" {
		apiURL = selectLegionEnvironment()
	}

	oauthCfg := getWellKnownConfig(apiURL, opts.NonInteractive)

	var username string
	if opts.Username != "" {
		username = opts.Username
	} else {
		printInfo("\nEnter Credentials")
		username = inputPrompt("Username: ")
	}

	var token string
	if opts.Username != "" && opts.Password != "" {
		var err error
		token, err = authenticateUser(oauthCfg.TokenEndpoint, username, opts.Password)
		if err != nil {
			return fmt.Errorf("auth failed: %w", err)
		}
	} else {
		if opts.Username == "" {
			printInfo("\nEnter Credentials")
		}
		for {
			password := readPasswordSimple("Password: ")
			var err error
			token, err = authenticateUser(oauthCfg.TokenEndpoint, username, password)
			if err == nil {
				break
			}
			printError(fmt.Sprintf("Auth failed: %v", err))
			printInfo("Please try again (Ctrl+C to abort)")
		}
	}
	printSuccess("Authenticated!")

	var (
		org Organization
		err error
	)
	if opts.OrgID != "" {
		org, err = getOrganization(apiURL, token, opts.OrgID)
		if err != nil {
			return fmt.Errorf("failed to fetch organization %q: %w", opts.OrgID, err)
		}
		printSuccess(fmt.Sprintf("Using organization: %s (%s)", org.OrganizationName, org.OrganizationID))
	} else {
		org, err = selectOrganization(apiURL, token)
		if err != nil {
			return err
		}
	}

	manifest := createManifestInteractively(opts)

	printInfo("\nCreating integration...")
	integ, err := createIntegration(apiURL, token, org.OrganizationID, manifest)
	if err != nil {
		var httpErr *HTTPError
		if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusConflict {
			printWarning("Integration exists.")
			if opts.NonInteractive {
				integ = findIntegrationByName(apiURL, token, org.OrganizationID, manifest.Name)
			} else {
				integ = selectExistingIntegrationPaginated(apiURL, token, org.OrganizationID)
			}
		} else {
			return fmt.Errorf("failed to create integration: %w", err)
		}
	}

	if integ == nil {
		return fmt.Errorf("no integration selected")
	}

	// Get OAuth Credentials
	var clientID, clientSecret string
	if integ.OAuthConfig != nil {
		clientID = integ.OAuthConfig.ClientID
		clientSecret = integ.OAuthConfig.ClientSecret
	}

	// Update manifest from integration if available
	if len(integ.Manifest) > 0 {
		var m Manifest
		if err := json.Unmarshal(integ.Manifest, &m); err == nil {
			manifest = m
		}
	}

	if clientID == "" {
		cfg, err := getIntegrationOAuthConfig(apiURL, token, org.OrganizationID, integ.ID)
		if err == nil {
			clientID = cfg.ClientID
			clientSecret = cfg.ClientSecret
		}
	}

	if clientID != "" && (clientSecret == "" || clientSecret == "[REDACTED]") {
		printWarning("Regenerating client secret...")
		clientSecret, err = regenerateClientSecret(apiURL, token, org.OrganizationID, integ.ID)
		if err != nil {
			return fmt.Errorf("failed to regenerate client secret: %w", err)
		}
	}

	redirectURL := ""
	if len(manifest.OAuthConfig.RedirectURLs) > 0 {
		redirectURL = manifest.OAuthConfig.RedirectURLs[0]
	}

	config := AppConfig{
		IntegrationID:    integ.ID,
		ClientID:         clientID,
		ClientSecret:     clientSecret,
		RedirectURL:      redirectURL,
		OrganizationID:   org.OrganizationID,
		OrganizationName: org.OrganizationName,
		LegionBaseURL:    apiURL,
		Manifest:         manifest,
	}

	if err := saveJSON(ConfigFile, config); err != nil {
		return fmt.Errorf("critical: failed to save configuration: %w", err)
	}

	// Initial User Token Save
	printInfo("\n→ Saving authentication token...")
	if err := saveJSON(AccessTokenFile, StoredToken{
		AccessToken:    token,
		ExpiresAt:      time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		OrganizationID: org.OrganizationID,
	}); err != nil {
		return fmt.Errorf("failed to save access token: %w", err)
	}

	// Perform Headless
	if performHeadlessOAuthFlow(config, token) {
		// Update config with bridge token
		content, err := os.ReadFile(AccessTokenFile)
		if err != nil {
			return fmt.Errorf("failed to read access token file: %w", err)
		}
		var t StoredToken
		if err := json.Unmarshal(content, &t); err != nil {
			return fmt.Errorf("failed to unmarshal access token from %s: %w", AccessTokenFile, err)
		}
		config.AccessToken = t.AccessToken
		if err := saveJSON(ConfigFile, config); err != nil {
			printError(fmt.Sprintf("Failed to update config with bridge token: %v", err))
		}
	}

	// Entity creation
	if opts.CreateEntity {
		createEntityToken := config.AccessToken
		if createEntityToken == "" {
			createEntityToken = token
			printWarning("Headless OAuth token unavailable; using initial user token for entity creation.")
		}
		if createEntityToken == "" {
			return fmt.Errorf("no access token available for entity creation")
		}
		createTerminalEntity(apiURL, config.OrganizationID, config.IntegrationID, createEntityToken, opts)
	}

	return nil
}

var errEntityNotFound = errors.New("entity not found")

func entityIDFromMap(entity map[string]interface{}) string {
	if id, ok := entity["id"]; ok {
		if normalized := normalizeEntityID(id); normalized != "" {
			return normalized
		}
	}
	if id, ok := entity["entity_id"]; ok {
		if normalized := normalizeEntityID(id); normalized != "" {
			return normalized
		}
	}
	return ""
}

func normalizeEntityID(id interface{}) string {
	if id == nil {
		return ""
	}
	value := strings.TrimSpace(fmt.Sprintf("%v", id))
	if value == "" || value == "<nil>" {
		return ""
	}
	return value
}

func entitySerialNumberFromMap(entity map[string]interface{}) string {
	meta, ok := entity["metadata"].(map[string]interface{})
	if !ok {
		return ""
	}
	sn, ok := meta["serial_number"].(string)
	if !ok {
		return ""
	}
	return sn
}

func entityRecencyTime(entity map[string]interface{}) (time.Time, bool) {
	parse := func(key string) (time.Time, bool) {
		raw, ok := entity[key].(string)
		if !ok {
			return time.Time{}, false
		}
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return time.Time{}, false
		}
		parsed, err := time.Parse(time.RFC3339Nano, trimmed)
		if err != nil {
			return time.Time{}, false
		}
		return parsed.UTC(), true
	}

	if parsed, ok := parse("updated_at"); ok {
		return parsed, true
	}
	if parsed, ok := parse("created_at"); ok {
		return parsed, true
	}
	return time.Time{}, false
}

func loadCachedTerminalEntity() (map[string]interface{}, error) {
	// #nosec G304 -- TerminalEntityFile is initialized from controlled storage path during setupStorage.
	content, err := os.ReadFile(TerminalEntityFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errEntityNotFound
		}
		return nil, fmt.Errorf("failed to read cached terminal entity: %w", err)
	}

	var entity map[string]interface{}
	if err := json.Unmarshal(content, &entity); err != nil {
		return nil, fmt.Errorf("failed to parse cached terminal entity: %w", err)
	}
	return entity, nil
}

func fetchEntityByID(apiURL, orgID, token, id string) (map[string]interface{}, error) {
	headers := map[string]string{"Authorization": "Bearer " + token, "X-ORG-ID": orgID}

	var entity map[string]interface{}
	if err := makeRequestJSON("GET", fmt.Sprintf("%s/v3/entities/%s", apiURL, url.PathEscape(id)), nil, headers, &entity); err != nil {
		var httpErr *HTTPError
		if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound {
			return nil, errEntityNotFound
		}
		return nil, fmt.Errorf("failed to fetch entity by id %s: %w", id, err)
	}
	return entity, nil
}

func fetchEntityBySerialNumber(apiURL, orgID, token, serialNumber string) (map[string]interface{}, error) {
	headers := map[string]string{"Authorization": "Bearer " + token, "X-ORG-ID": orgID}
	target := strings.ToLower(serialNumber)
	const pageSize = 50
	var matched map[string]interface{}
	matchedID := ""
	var matchedTime time.Time
	matchedHasTime := false
	seenIDs := map[string]struct{}{}

	for offset := 0; ; offset += pageSize {
		searchPayload := map[string]interface{}{
			"filters": map[string]interface{}{
				"category": []string{"DEVICE"},
				"types":    []string{"Terminal"},
			},
		}

		var result EntitySearchResult
		if err := makeRequestJSON("POST", fmt.Sprintf("%s/v3/entities/search?limit=%d&offset=%d", apiURL, pageSize, offset), searchPayload, headers, &result); err != nil {
			return nil, fmt.Errorf("failed to search entities: %w", err)
		}

		for _, entity := range result.Results {
			sn := entitySerialNumberFromMap(entity)
			if strings.ToLower(sn) == target {
				id := entityIDFromMap(entity)
				if id != "" {
					if _, exists := seenIDs[id]; exists {
						continue
					}
					seenIDs[id] = struct{}{}
				}

				candidateTime, candidateHasTime := entityRecencyTime(entity)
				if matched == nil {
					matched = entity
					matchedID = id
					matchedTime = candidateTime
					matchedHasTime = candidateHasTime
					continue
				}

				shouldReplace := false
				if candidateHasTime {
					if !matchedHasTime || candidateTime.After(matchedTime) {
						shouldReplace = true
					} else if matchedHasTime && candidateTime.Equal(matchedTime) && id != "" && matchedID != "" && id > matchedID {
						// Deterministic tie-breaker when timestamps match.
						shouldReplace = true
					}
				}
				if !candidateHasTime && !matchedHasTime && matchedID == "" && id != "" {
					shouldReplace = true
				}

				if shouldReplace {
					matched = entity
					matchedID = id
					matchedTime = candidateTime
					matchedHasTime = candidateHasTime
				}
			}
		}

		if offset+pageSize >= result.TotalCount {
			break
		}
	}

	if matched != nil {
		return matched, nil
	}
	return nil, errEntityNotFound
}

func fetchEntityBySerialNumberWithRetry(apiURL, orgID, token, serialNumber string, attempts int, initialDelay time.Duration, retryOnNotFound bool) (map[string]interface{}, error) {
	if attempts < 1 {
		attempts = 1
	}
	if initialDelay <= 0 {
		initialDelay = 200 * time.Millisecond
	}

	delay := initialDelay
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		entity, err := fetchEntityBySerialNumber(apiURL, orgID, token, serialNumber)
		if err == nil {
			return entity, nil
		}
		lastErr = err
		if !isRetryableEntityLookupError(err, retryOnNotFound) {
			return nil, err
		}
		if attempt < attempts {
			time.Sleep(delay)
			if delay < 2*time.Second {
				delay *= 2
			}
		}
	}

	return nil, lastErr
}

func isRetryableEntityLookupError(err error, retryOnNotFound bool) bool {
	if retryOnNotFound && errors.Is(err, errEntityNotFound) {
		return true
	}
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode == http.StatusTooManyRequests || httpErr.StatusCode >= http.StatusInternalServerError
	}
	return false
}

func resolveEntityBySerialNumber(apiURL, orgID, token, serialNumber string) (map[string]interface{}, string, error) {
	entity, err := fetchEntityBySerialNumberWithRetry(apiURL, orgID, token, strings.ToLower(serialNumber), 5, 200*time.Millisecond, false)
	if err != nil {
		return nil, "", err
	}
	return entity, "search", nil
}

func createTerminalEntity(apiURL, orgID, integID, token string, opts setupOpts) {
	printColored("\n→ Creating terminal entity...", ColorCyan, true)

	cachedEntity, cacheErr := loadCachedTerminalEntity()
	if cacheErr == nil {
		cachedID := entityIDFromMap(cachedEntity)
		if cachedID == "" {
			if !confirmRecreateEntity("Cached terminal entity is missing an id.", opts.NonInteractive) {
				printInfo("Keeping cached terminal entity. Setup cancelled.")
				return
			}
			printInfo("Proceeding with terminal entity recreation.")
		} else {
			resolved, fetchErr := fetchEntityByID(apiURL, orgID, token, cachedID)
			if fetchErr != nil {
				if errors.Is(fetchErr, errEntityNotFound) {
					if !confirmRecreateEntity("Cached terminal entity no longer exists on server.", opts.NonInteractive) {
						printInfo("Keeping cached terminal entity. Setup cancelled.")
						return
					}
					printInfo("Proceeding with terminal entity recreation.")
				} else {
					printError(fmt.Sprintf("Failed to validate cached terminal entity id %s: %v", cachedID, fetchErr))
					return
				}
			} else {
				if saveErr := saveJSON(TerminalEntityFile, resolved); saveErr != nil {
					printError(fmt.Sprintf("Failed to save terminal entity: %v", saveErr))
					return
				}

				printSuccess("Using cached terminal entity. Remove terminal_entity.json to provision a different entity.")
				return
			}
		}
	}
	if !errors.Is(cacheErr, errEntityNotFound) {
		if !confirmRecreateEntity(fmt.Sprintf("Cached terminal entity is unreadable: %v", cacheErr), opts.NonInteractive) {
			printInfo("Keeping cached terminal entity. Setup cancelled.")
			return
		}
		printInfo("Proceeding with terminal entity recreation.")
	}

	var sn string
	if opts.EntityName != "" {
		sn = opts.EntityName
	} else if opts.NonInteractive {
		printError("--entity-name is required when using --create-entity with --non-interactive")
		return
	} else {
		sn = inputPrompt("Terminal Serial Number: ")
		if sn == "" {
			return
		}
	}

	var tType string
	if opts.EntityType != "" {
		valid := false
		for _, t := range validEntityTypes {
			if t == opts.EntityType {
				valid = true
				break
			}
		}
		if !valid {
			printError(fmt.Sprintf("Unknown entity type %q, must be one of: %s", opts.EntityType, strings.Join(validEntityTypes, ", ")))
			return
		}
		tType = opts.EntityType
	} else if opts.NonInteractive {
		printError("--entity-type is required when using --create-entity with --non-interactive")
		return
	} else {
		fmt.Println("Available types:")
		for i, t := range validEntityTypes {
			fmt.Printf("  %d. %s\n", i+1, t)
		}
		typeChoice := inputPrompt(fmt.Sprintf("Select type (1-%d): ", len(validEntityTypes)))
		idx, err := strconv.Atoi(typeChoice)
		if err != nil || idx < 1 || idx > len(validEntityTypes) {
			printError(fmt.Sprintf("Invalid selection %q", typeChoice))
			return
		}
		tType = validEntityTypes[idx-1]
	}

	payload := map[string]interface{}{
		"organization_id": orgID,
		"integration_id":  integID,
		"name":            strings.ToUpper(sn),
		"category":        "DEVICE",
		"type":            "Terminal",
		"status":          "active",
		"affiliation":     "FRIEND",
		"metadata": map[string]string{
			"manufacturer":  "picogrid",
			"serial_number": strings.ToLower(sn),
			"terminal_type": tType,
		},
	}

	headers := map[string]string{"Authorization": "Bearer " + token, "X-ORG-ID": orgID}

	// Resolve by immutable serial number before creation. If lookup fails, fail closed to avoid duplicates.
	existing, source, resolveErr := resolveEntityBySerialNumber(apiURL, orgID, token, sn)
	if resolveErr == nil {
		if saveErr := saveJSON(TerminalEntityFile, existing); saveErr != nil {
			printError(fmt.Sprintf("Failed to save terminal entity: %v", saveErr))
			return
		}
		printSuccess(fmt.Sprintf("Found existing terminal entity by serial number via %s. Skipping creation.", source))
		return
	}
	if !errors.Is(resolveErr, errEntityNotFound) {
		printError(fmt.Sprintf("Failed to verify existing terminal entity: %v", resolveErr))
		printError("Aborting entity creation to avoid duplicate entities.")
		return
	}

	var resp map[string]interface{}
	err := makeRequestJSON("POST", fmt.Sprintf("%s/v3/entities", apiURL), payload, headers, &resp)
	if err != nil {
		var httpErr *HTTPError
		if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusConflict {
			printWarning("Entity create returned 409 conflict. Resolving existing entity by serial number...")
			fetchedEntity, fetchErr := fetchEntityBySerialNumberWithRetry(apiURL, orgID, token, sn, 5, 200*time.Millisecond, true)
			if fetchErr != nil {
				if errors.Is(fetchErr, errEntityNotFound) {
					printError("Create conflicted on entity name, but no terminal entity was found with this serial_number.")
					printError("An existing entity likely has this name with different metadata.serial_number. Rename that entity or use the matching serial number.")
					return
				}
				printError(fmt.Sprintf("Failed to resolve conflicting entity by serial number: %v", fetchErr))
				printError("Terminal entity setup failed. Creation was rejected and identity could not be resolved.")
				return
			}
			if saveErr := saveJSON(TerminalEntityFile, fetchedEntity); saveErr != nil {
				printError(fmt.Sprintf("Failed to save terminal entity: %v", saveErr))
				printError("Terminal entity setup failed. The entity was retrieved but could not be saved.")
				return
			}
			printSuccess("Resolved conflict and saved existing terminal entity by serial number.")
			return
		}
		printError(fmt.Sprintf("Failed to create terminal entity: %v", err))
		return
	}

	if err := saveJSON(TerminalEntityFile, resp); err != nil {
		printError(fmt.Sprintf("Failed to save terminal entity: %v", err))
		printError("Terminal entity was created but could not be saved locally.")
		return
	}
	printSuccess("Terminal Entity Created!")
}

// ============================================================================
// Main Execution
// ============================================================================

func main() {

	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Default plain HTTP client (replaced with instrumented client in daemon mode)
	httpClient = &http.Client{Timeout: 30 * time.Second}

	setupCmd := flag.NewFlagSet("setup", flag.ExitOnError)
	setupFlags := registerSetupFlags(setupCmd)

	installCmd := flag.NewFlagSet("install-service", flag.ExitOnError)
	installStoragePath := installCmd.String("storage-path", "", "Custom storage path")
	installServiceUser := installCmd.String("service-user", "", "User to run the service as (Linux system-level only)")
	installServiceGroup := installCmd.String("service-group", "", "Group to run the service as (Linux system-level only, default: picogrid when present, else primary group of service user)")
	installUserLevel := installCmd.Bool("user", false, "Install as user-level service (no sudo required)")

	uninstallCmd := flag.NewFlagSet("uninstall-service", flag.ExitOnError)
	uninstallUserLevel := uninstallCmd.Bool("user", false, "Uninstall user-level service")

	storagePathFlag := flag.String("storage-path", "", "Custom storage path")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [command] [options]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Commands:")
		fmt.Fprintln(os.Stderr, "  setup")
		fmt.Fprintln(os.Stderr, "        Run setup (interactive by default, or with --non-interactive)")
		fmt.Fprintln(os.Stderr, "        Flags:")
		fmt.Fprintln(os.Stderr, "          --storage-path   Custom storage path")
		fmt.Fprintln(os.Stderr, "          --api-url        Legion API URL (skips environment selector)")
		fmt.Fprintln(os.Stderr, "          --username       Username for authentication")
		fmt.Fprintln(os.Stderr, "          --password       Password for authentication")
		fmt.Fprintln(os.Stderr, "          --org-id         Organization ID (skips org selector)")
		fmt.Fprintln(os.Stderr, "          --integration-name  Integration name")
		fmt.Fprintln(os.Stderr, "          --description    Integration description")
		fmt.Fprintln(os.Stderr, "          --version        Integration version")
		fmt.Fprintln(os.Stderr, "          --redirect-url   OAuth redirect URL")
		fmt.Fprintln(os.Stderr, "          --access-level   Access level: viewer/operator/admin")
		fmt.Fprintln(os.Stderr, "          --create-entity  Create terminal entity during setup")
		fmt.Fprintln(os.Stderr, "          --entity-name    Terminal entity name / serial number")
		fmt.Fprintln(os.Stderr, "          --entity-type    Terminal type: lander/helios/portal/dev-unit")
		fmt.Fprintln(os.Stderr, "          --non-interactive Run without prompts, use flags and defaults")

		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  install-service")
		fmt.Fprintln(os.Stderr, "        Install as a system or user service (systemd/Launchd)")
		fmt.Fprintln(os.Stderr, "        Flags:")
		fmt.Fprintln(os.Stderr, "          --user           Install as user-level service (no sudo required)")
		fmt.Fprintln(os.Stderr, "          --storage-path   Custom storage path")
		fmt.Fprintln(os.Stderr, "          --service-user   User to run service as (Linux system-level only, default: pg if exists, else root)")
		fmt.Fprintln(os.Stderr, "          --service-group  Group to run service as (Linux system-level only, default: picogrid when present, else primary group of service user)")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  uninstall-service")
		fmt.Fprintln(os.Stderr, "        Uninstall the service (systemd/Launchd)")
		fmt.Fprintln(os.Stderr, "        Flags:")
		fmt.Fprintln(os.Stderr, "          --user           Uninstall user-level service")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  version")
		fmt.Fprintln(os.Stderr, "        Display version information")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options (Daemon mode):")
		flag.PrintDefaults()
	}

	if len(os.Args) > 1 {

		switch os.Args[1] {

		case "version":
			fmt.Printf("legion-auth version %s\n", Version)
			fmt.Printf("Git commit: %s\n", GitCommit)
			fmt.Printf("Build date: %s\n", BuildDate)
			fmt.Printf("Go version: %s\n", runtime.Version())
			fmt.Printf("OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
			return

		case "setup":

			if err := setupCmd.Parse(os.Args[2:]); err != nil {
				printError(fmt.Sprintf("Failed to parse setup flags: %v", err))
				os.Exit(1)
			}
			applySetupEnvDefaults(setupFlags)

			if err := setupStorage(setupFlags.StoragePath); err != nil {
				printError(fmt.Sprintf("Storage setup failed: %v", err))
				os.Exit(1)
			}

			if err := interactiveSetup(setupFlags.Opts); err != nil {
				printError(err.Error())
				os.Exit(1)
			}

			return

		case "install-service":

			if err := installCmd.Parse(os.Args[2:]); err != nil {
				printError(fmt.Sprintf("Failed to parse install-service flags: %v", err))
				os.Exit(1)
			}
			if *installServiceUser == "" {
				*installServiceUser = install.DefaultServiceUser()
			}
			if *installServiceGroup == "" {
				*installServiceGroup = install.DefaultServiceGroup()
			}

			// Setup storage first to ensure paths match defaults if not provided

			if err := setupStorage(*installStoragePath); err != nil {

				printError(fmt.Sprintf("Storage configuration failed: %v", err))

				os.Exit(1)

			}

			if err := installService(StoragePath, *installServiceUser, *installServiceGroup, *installUserLevel); err != nil {

				printError(fmt.Sprintf("Service installation failed: %v", err))

				os.Exit(1)

			}

			return

		case "uninstall-service":
			if err := uninstallCmd.Parse(os.Args[2:]); err != nil {
				printError(fmt.Sprintf("Failed to parse uninstall-service flags: %v", err))
				os.Exit(1)
			}

			if err := uninstallService(*uninstallUserLevel); err != nil {
				printError(fmt.Sprintf("Service uninstallation failed: %v", err))
				os.Exit(1)
			}

			return
		}

	}

	flag.Parse()

	if err := setupStorage(*storagePathFlag); err != nil {
		printError(fmt.Sprintf("Storage setup failed: %v", err))
		os.Exit(1)
	}

	// Initialize OpenTelemetry (metrics + traces)
	otelCfg := pgtel.ConfigFromEnv(Version)
	var err error
	otelProviders, err = pgtel.Init(context.Background(), otelCfg)
	if err != nil {
		logger.Warn("OTel init failed, metrics/traces disabled", slog.String("error", err.Error()))
		otelProviders = &pgtel.Providers{}
	} else if otelCfg.Enabled {
		logger.Info("OTel initialized", slog.String("endpoint", otelCfg.Endpoint), slog.String("service", otelCfg.ServiceName))
	}

	// Replace HTTP client with instrumented version (tracing on all outbound requests)
	httpClient = pgtel.NewHTTPClient()

	// Register legion metrics (observable gauges + counters)
	legionMetrics, err = pgtel.NewLegionMetrics(otelProviders.Meter())
	if err != nil {
		logger.Warn("failed to register legion metrics", slog.String("error", err.Error()))
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Info("shutdown initiated")
		close(shutdownChan)

		// Flush all telemetry before exit
		done := make(chan error, 1)
		go func() {
			done <- otelProviders.Shutdown(context.Background())
		}()

		// Force exit after timeout if shutdown is not complete
		select {
		case shutdownErr := <-done:
			if shutdownErr != nil {
				logger.Error("OTel shutdown error", slog.String("error", shutdownErr.Error()))
			}
		case <-time.After(2 * time.Second):
			logger.Warn("OTel shutdown timeout, forcing exit")
		}
		os.Exit(0)
	}()

	runTokenMonitoring()
}

func installService(storagePath, serviceUser, serviceGroup string, userLevel bool) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	exePath, _ = filepath.Abs(exePath)

	switch runtime.GOOS {
	case "linux":
		// Systemd
		var serviceContent string
		var servicePath string
		var systemctlArgs []string

		if userLevel {
			// User-level service
			serviceContent = fmt.Sprintf(`[Unit]
Description=Legion Authentication Service
After=network.target

[Service]
ExecStart=%s --storage-path %s
Restart=always
RestartSec=10
Environment=PG_OTEL_ENABLED=false
Environment=OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318

[Install]
WantedBy=default.target
`, exePath, storagePath)

			home, _ := os.UserHomeDir()
			servicePath = filepath.Join(home, ".config/systemd/user/legion-auth.service")
			systemctlArgs = []string{"--user"}

			printInfo(fmt.Sprintf("Installing user-level systemd service to %s...", servicePath))
		} else {
			// System-level service (requires sudo)
			account, err := user.Lookup(serviceUser)
			if err != nil {
				return fmt.Errorf("service user %q does not exist: %w (create it with: useradd --system --no-create-home %s)", serviceUser, err, serviceUser)
			}

			resolvedServiceGroup := account.Gid
			if group, err := user.LookupGroupId(account.Gid); err == nil {
				resolvedServiceGroup = group.Name
			}
			if serviceGroup != "" {
				if _, err := user.LookupGroup(serviceGroup); err != nil {
					return fmt.Errorf("service group %q does not exist: %w", serviceGroup, err)
				}
				resolvedServiceGroup = serviceGroup
			}

			serviceContent = fmt.Sprintf(`[Unit]
Description=Legion Authentication Service
After=network.target

[Service]
ExecStart=%s --storage-path %s
Restart=always
RestartSec=10
User=%s
Group=%s
Environment=PG_OTEL_ENABLED=false
Environment=OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318

[Install]
WantedBy=multi-user.target
`, exePath, storagePath, serviceUser, resolvedServiceGroup)

			servicePath = "/etc/systemd/system/legion-auth.service"
			systemctlArgs = []string{}

			printInfo(fmt.Sprintf("Installing system-level systemd service to %s...", servicePath))
		}

		// Ensure directory exists (for user services)
		if err := os.MkdirAll(filepath.Dir(servicePath), 0755); err != nil {
			return fmt.Errorf("failed to create service directory: %w", err)
		}

		if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
			if userLevel {
				return fmt.Errorf("failed to write service file: %w", err)
			}
			return fmt.Errorf("failed to write service file (try running with sudo): %w", err)
		}

		printInfo("Reloading systemd daemon...")
		daemonReloadCmd := append(systemctlArgs, "daemon-reload")
		// #nosec G204 -- command and flags are controlled by in-process logic (only optional --user flag).
		_ = exec.Command("systemctl", daemonReloadCmd...).Run()

		printInfo("Enabling legion-auth service...")
		enableCmd := append(systemctlArgs, "enable", "legion-auth")
		// #nosec G204 -- arguments are fixed systemctl subcommands with optional trusted --user prefix.
		if err := exec.Command("systemctl", enableCmd...).Run(); err != nil {
			return fmt.Errorf("failed to enable service: %w", err)
		}

		printInfo("Starting legion-auth service...")
		restartCmd := append(systemctlArgs, "restart", "legion-auth")
		// #nosec G204 -- arguments are fixed systemctl subcommands with optional trusted --user prefix.
		if err := exec.Command("systemctl", restartCmd...).Run(); err != nil {
			return fmt.Errorf("failed to start service: %w", err)
		}

		if userLevel {
			printSuccess("User-level service installed and started on Linux (Systemd)!")
			printInfo("Service runs without sudo and will start automatically on login")
		} else {
			printSuccess("System-level service installed and started on Linux (Systemd)!")
		}

	case "darwin":
		// Launchd
		var plistPath string
		var logPath string
		var errorLogPath string

		if userLevel || os.Geteuid() != 0 {
			// User-level service (LaunchAgent)
			home, _ := os.UserHomeDir()
			plistPath = filepath.Join(home, "Library/LaunchAgents/com.picogrid.legion-auth.plist")
			logPath = filepath.Join(home, "Library/Logs/legion-auth.log")
			errorLogPath = filepath.Join(home, "Library/Logs/legion-auth.error.log")
			printInfo(fmt.Sprintf("Installing user-level Launchd agent to %s...", plistPath))
		} else {
			// System-level service (LaunchDaemon)
			plistPath = "/Library/LaunchDaemons/com.picogrid.legion-auth.plist"
			logPath = "/var/log/legion-auth.log"
			errorLogPath = "/var/log/legion-auth.error.log"
			printInfo(fmt.Sprintf("Installing system-level Launchd daemon to %s...", plistPath))
		}

		plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.picogrid.legion-auth</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>--storage-path</string>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PG_OTEL_ENABLED</key>
        <string>false</string>
        <key>OTEL_EXPORTER_OTLP_ENDPOINT</key>
        <string>http://localhost:4318</string>
    </dict>
    <key>StandardOutPath</key>
    <string>%s</string>
    <key>StandardErrorPath</key>
    <string>%s</string>
</dict>
</plist>
`, exePath, storagePath, logPath, errorLogPath)

		// Ensure directory exists (mostly for user agents)
		if err := os.MkdirAll(filepath.Dir(plistPath), 0755); err != nil {
			return fmt.Errorf("failed to create plist directory: %w", err)
		}

		if err := os.WriteFile(plistPath, []byte(plistContent), 0644); err != nil {
			return fmt.Errorf("failed to write plist file: %w", err)
		}

		// Unload if exists, then load
		// #nosec G204 -- launchctl binary/subcommand are fixed; plistPath is internally constructed.
		_ = exec.Command("launchctl", "unload", plistPath).Run()

		printInfo("Loading service with launchctl...")
		// #nosec G204 -- launchctl binary/subcommand are fixed; plistPath is internally constructed.
		if err := exec.Command("launchctl", "load", plistPath).Run(); err != nil {
			return fmt.Errorf("failed to load service: %w", err)
		}

		if userLevel || os.Geteuid() != 0 {
			printSuccess("User-level service installed and loaded on macOS (Launchd)!")
			printInfo("Service runs without sudo and will start automatically on login")
		} else {
			printSuccess("System-level service installed and loaded on macOS (Launchd)!")
		}

	default:
		return fmt.Errorf("service installation not supported on %s", runtime.GOOS)
	}

	return nil
}

func uninstallService(userLevel bool) error {
	switch runtime.GOOS {
	case "linux":
		// Systemd
		var servicePath string
		var systemctlArgs []string

		if userLevel {
			home, _ := os.UserHomeDir()
			servicePath = filepath.Join(home, ".config/systemd/user/legion-auth.service")
			systemctlArgs = []string{"--user"}
			printInfo("Uninstalling user-level systemd service...")
		} else {
			servicePath = "/etc/systemd/system/legion-auth.service"
			systemctlArgs = []string{}
			printInfo("Uninstalling system-level systemd service...")
		}

		// Stop service
		printInfo("Stopping legion-auth service...")
		stopCmd := append(systemctlArgs, "stop", "legion-auth")
		// #nosec G204 -- arguments are fixed systemctl subcommands with optional trusted --user prefix.
		_ = exec.Command("systemctl", stopCmd...).Run()

		// Disable service
		printInfo("Disabling legion-auth service...")
		disableCmd := append(systemctlArgs, "disable", "legion-auth")
		// #nosec G204 -- arguments are fixed systemctl subcommands with optional trusted --user prefix.
		_ = exec.Command("systemctl", disableCmd...).Run()

		// Remove service file
		if err := os.Remove(servicePath); err != nil && !os.IsNotExist(err) {
			if !userLevel {
				return fmt.Errorf("failed to remove service file (try running with sudo): %w", err)
			}
			return fmt.Errorf("failed to remove service file: %w", err)
		}

		// Reload daemon
		printInfo("Reloading systemd daemon...")
		daemonReloadCmd := append(systemctlArgs, "daemon-reload")
		// #nosec G204 -- arguments are fixed systemctl subcommands with optional trusted --user prefix.
		_ = exec.Command("systemctl", daemonReloadCmd...).Run()

		printSuccess("Service uninstalled successfully from Linux (Systemd)!")

	case "darwin":
		// Launchd
		var plistPath string

		if userLevel || os.Geteuid() != 0 {
			home, _ := os.UserHomeDir()
			plistPath = filepath.Join(home, "Library/LaunchAgents/com.picogrid.legion-auth.plist")
			printInfo("Uninstalling user-level Launchd agent...")
		} else {
			plistPath = "/Library/LaunchDaemons/com.picogrid.legion-auth.plist"
			printInfo("Uninstalling system-level Launchd daemon...")
		}

		// Unload service
		printInfo("Unloading service with launchctl...")
		// #nosec G204 -- launchctl binary/subcommand are fixed; plistPath is internally constructed.
		_ = exec.Command("launchctl", "unload", plistPath).Run()

		// Remove plist file
		if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove plist file: %w", err)
		}

		printSuccess("Service uninstalled successfully from macOS (Launchd)!")

	default:
		return fmt.Errorf("service uninstallation not supported on %s", runtime.GOOS)
	}

	return nil
}

func runTokenMonitoring() {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("panic in token monitoring", slog.Any("panic", r), slog.String("stack", string(debug.Stack())))
		}
	}()

	logger.Info("legion authentication service starting",
		slog.String("version", Version),
		slog.String("storage_path", StoragePath),
	)

	if _, err := os.Stat(ConfigFile); os.IsNotExist(err) {
		printInfo("No configuration found. Running setup...")
		if err := interactiveSetup(setupOpts{}); err != nil {
			printError(err.Error())
			return
		}
		// If setup succeeded but config still missing, bail out
		if _, err := os.Stat(ConfigFile); os.IsNotExist(err) {
			return
		}
	}

	// Load config/terminal info and feed metrics (matches edge-monitor's legion_config_loop)
	loadConfigMetrics()
	loadTerminalMetrics()

	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	checkAndRefreshToken()

	logger.Info("token monitoring started, checking every 2m")

	for {
		select {
		case <-shutdownChan:
			logger.Info("token monitoring stopped")
			return
		case <-ticker.C:
			checkAndRefreshToken()
		}
	}
}

// loadConfigMetrics reads oauth_config.json and updates legion_info gauge.
func loadConfigMetrics() {
	if legionMetrics == nil {
		return
	}
	// #nosec G304 -- ConfigFile is initialized from controlled storage path during setupStorage.
	content, err := os.ReadFile(ConfigFile)
	if err != nil {
		return
	}
	var config AppConfig
	if json.Unmarshal(content, &config) != nil {
		return
	}
	if config.LegionBaseURL != "" || config.OrganizationID != "" {
		legionMetrics.SetConfig(config.LegionBaseURL, config.OrganizationID, config.OrganizationName)
		logger.Info("legion config loaded for metrics",
			slog.String("base_url", config.LegionBaseURL),
			slog.String("organization_id", config.OrganizationID),
			slog.String("organization_name", config.OrganizationName),
		)
	}
}

// loadTerminalMetrics reads terminal_entity.json and updates legion_terminal_info gauge.
func loadTerminalMetrics() {
	if legionMetrics == nil {
		return
	}
	// #nosec G304 -- TerminalEntityFile is initialized from controlled storage path during setupStorage.
	content, err := os.ReadFile(TerminalEntityFile)
	if err != nil {
		return
	}
	var entity map[string]interface{}
	if json.Unmarshal(content, &entity) != nil {
		return
	}
	entityID := entityIDFromMap(entity)
	serial := entitySerialNumberFromMap(entity)
	terminalType := ""
	if meta, ok := entity["metadata"].(map[string]interface{}); ok {
		if t, ok := meta["terminal_type"].(string); ok {
			terminalType = t
		}
	}
	if entityID != "" {
		legionMetrics.SetTerminal(entityID, serial, terminalType)
		logger.Info("legion terminal loaded for metrics",
			slog.String("entity_id", entityID),
			slog.String("serial_number", serial),
			slog.String("terminal_type", terminalType),
		)
	}
}

// updateTokenMetrics reads the current token expiry and feeds the metric.
func updateTokenMetrics() {
	if legionMetrics == nil {
		return
	}
	// #nosec G304 -- AccessTokenFile is initialized from controlled storage path during setupStorage.
	content, err := os.ReadFile(AccessTokenFile)
	if err != nil {
		return
	}
	var t StoredToken
	if json.Unmarshal(content, &t) != nil {
		return
	}
	expires, err := time.Parse(time.RFC3339, t.ExpiresAt)
	if err != nil {
		return
	}
	legionMetrics.SetTokenExpiry(float64(expires.Unix()))
}

func checkAndRefreshToken() {
	if shouldRefreshToken() {
		if refreshAccessToken() {
			if legionMetrics != nil {
				legionMetrics.RecordRefreshSuccess()
			}
		} else {
			if legionMetrics != nil {
				legionMetrics.RecordRefreshError()
			}
		}
	} else {
		logger.Info("token valid")
	}
	updateTokenMetrics()
}
