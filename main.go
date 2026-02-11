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
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

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
)

var (
	StoragePath        string
	ConfigFile         string
	AccessTokenFile    string
	RefreshTokenFile   string
	TerminalEntityFile string
	LegionOAuthPath    string

	// Global logger
	logger *log.Logger

	// Shutdown signal
	shutdownChan = make(chan struct{})

	// File permissions (env: LEGION_AUTH_FILE_GID)
	filePermissions os.FileMode = 0640
	fileGID                     = -1
)

func init() {
	if g := os.Getenv("LEGION_AUTH_FILE_GID"); g != "" {
		parsed, err := strconv.Atoi(g)
		if err != nil {
			log.Printf("Warning: LEGION_AUTH_FILE_GID=%q is not a valid integer, ignoring", g)
		} else if parsed < 0 {
			log.Printf("Warning: LEGION_AUTH_FILE_GID=%d must be non-negative, ignoring", parsed)
		} else {
			fileGID = parsed
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
	IntegrationID  string   `json:"integrationId"`
	ClientID       string   `json:"clientId"`
	ClientSecret   string   `json:"clientSecret,omitempty"`
	RedirectURL    string   `json:"redirectUrl"`
	OrganizationID string   `json:"organizationId"`
	LegionBaseURL  string   `json:"legionBaseUrl"`
	Manifest       Manifest `json:"manifest"`
	AccessToken    string   `json:"accessToken,omitempty"`
}

type PagedIntegrations struct {
	Integrations []Integration `json:"integrations"`
	Total        int           `json:"total"`
	Offset       int           `json:"offset"`
}

type EntitySearchResult struct {
	Results    []map[string]interface{} `json:"results"`
	TotalCount interface{}              `json:"total_count"`
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

func inputPrompt(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	text, err := reader.ReadString('\n')
	if err != nil {
		if err == io.EOF {
			fmt.Println()
			os.Exit(0)
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
	logger.Printf("Making %s request to %s", method, urlStr)

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

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
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
		logger.Printf("Failed to create symlink (non-fatal): %v", err)
	}
	return nil
}

func setOwnership(path string) {
	pgUser, err := user.Lookup("pg")
	if err != nil {
		logger.Printf("User 'pg' not found, keeping default ownership")
		return
	}

	uid, err := strconv.Atoi(pgUser.Uid)
	if err != nil {
		logger.Printf("Failed to parse pg user UID: %v", err)
		return
	}
	gid, err := strconv.Atoi(pgUser.Gid)
	if err != nil {
		logger.Printf("Failed to parse pg user GID: %v", err)
		return
	}

	if err := os.Chown(path, uid, gid); err != nil {
		logger.Printf("Insufficient permissions to chown %s: %v", path, err)
		return
	}
	if err := os.Chmod(path, 0755); err != nil {
		logger.Printf("Failed to chmod %s: %v", path, err)
	}

	parent := filepath.Dir(path)
	if _, err := os.Stat(parent); err == nil {
		if err := os.Chown(parent, uid, gid); err != nil {
			logger.Printf("Failed to chown parent %s: %v", parent, err)
		}
		if err := os.Chmod(parent, 0755); err != nil {
			logger.Printf("Failed to chmod parent %s: %v", parent, err)
		}
	}
	logger.Printf("Set ownership of %s and parent to pg user", path)
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
		logger.Printf("Port in use, switching to %s", newURI)
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

func getWellKnownConfig(legionAPIURL string) OAuthConfig {
	wellKnownURL := fmt.Sprintf("%s/v3/.well-known/oauth-authorization-server", legionAPIURL)
	printInfo(fmt.Sprintf("Fetching OAuth configuration from %s", wellKnownURL))

	var config OAuthConfig
	err := makeRequestJSON("GET", wellKnownURL, nil, nil, &config)
	if err != nil || config.TokenEndpoint == "" {
		printWarning("Using fallback configuration")
		return getKeycloakFallbackConfig()
	}

	printSuccess(fmt.Sprintf("Found Keycloak at: %s", config.Issuer))

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

func getOrganizations(legionAPIURL, token string) ([]Organization, error) {
	headers := map[string]string{"Authorization": "Bearer " + token}
	var resp struct {
		Results []Organization `json:"results"`
	}
	err := makeRequestJSON("GET", fmt.Sprintf("%s/v3/me/orgs", legionAPIURL), nil, headers, &resp)
	return resp.Results, err
}

func selectOrganization(orgs []Organization) Organization {
	printColored("\nAvailable organizations:", ColorCyan, false)
	for i, org := range orgs {
		fmt.Printf("  %d. %s (%s)\n", i+1, org.OrganizationName, org.OrganizationID)
	}

	for {
		choice := inputPrompt("\nSelect organization (number): ")
		idx, err := strconv.Atoi(choice)
		if err == nil && idx > 0 && idx <= len(orgs) {
			return orgs[idx-1]
		}
		printError("Invalid selection.")
	}
}

func createManifestInteractively() Manifest {
	printColored("\nIntegration Configuration", ColorCyan, true)

	if _, err := os.Stat("manifest.json"); err == nil {
		use := inputPrompt("Found manifest.json. Use existing? (Y/n): ")
		if use == "" || strings.ToLower(use) == "y" {
			content, _ := os.ReadFile("manifest.json")
			var m Manifest
			if json.Unmarshal(content, &m) == nil {
				return m
			}
		}
	}

	name := inputPrompt("   Name [Portal Integration]: ")
	if name == "" {
		name = "Portal Integration"
	}

	desc := inputPrompt("   Description [OAuth integration...]: ")
	if desc == "" {
		desc = "OAuth integration for portal authentication"
	}

	ver := inputPrompt("   Version [1.0.0]: ")
	if ver == "" {
		ver = "1.0.0"
	}

	redirect := inputPrompt("   Redirect URL [http://localhost:8000/oauth_callback]: ")
	if redirect == "" {
		redirect = "http://localhost:8000/oauth_callback"
	}

	redirect = ensureRedirectUriAvailable(redirect)

	// Ask if they want to use permissions or legacy scopes
	printColored("\nPermission Configuration", ColorCyan, false)
	printInfo("Choose authorization method:")
	fmt.Println("  1. Permissions (Recommended - fine-grained access control)")
	fmt.Println("  2. Legacy Scopes (Deprecated - for backward compatibility)")

	authChoice := inputPrompt("\nSelect (1 or 2) [1]: ")
	if authChoice == "" {
		authChoice = "1"
	}

	var permissions []PermissionRequest
	var scopes []string

	if authChoice == "1" {
		// Use permissions
		printColored("\nSelect permissions to grant:", ColorCyan, false)
		permissions = selectPermissionsWithPresets()
	} else {
		// Use legacy scopes
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

func selectExistingIntegrationPaginated(apiURL, token, orgID string) *Integration {
	printColored("\nExisting Integrations (paged):", ColorCyan, false)
	pageSize := 10
	offset := 0

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
		current := (offset / pageSize) + 1
		totalPages := (total + pageSize - 1) / pageSize
		if totalPages < 1 {
			totalPages = 1
		}

		printInfo(fmt.Sprintf("Page %d of %d (showing %d of %d)", current, totalPages, len(page.Integrations), total))

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
			offset += pageSize
			continue
		}
		if prevOpt > 0 && idx == prevOpt {
			offset -= pageSize
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
			logger.Printf("Server error: %v", err)
		}
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			logger.Printf("Server shutdown error: %v", err)
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
		logger.Printf("Auth request finished (err=%v)", err)
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
func interactiveSetup(createEntity bool) {
	apiURL := os.Getenv("LEGION_API_URL")
	if apiURL == "" {
		apiURL = selectLegionEnvironment()
	}

	oauthCfg := getWellKnownConfig(apiURL)

	printInfo("\nEnter Credentials")
	username := inputPrompt("Username: ")
	password := readPasswordSimple("Password: ")

	token, err := authenticateUser(oauthCfg.TokenEndpoint, username, password)
	if err != nil {
		printError(fmt.Sprintf("Auth failed: %v", err))
		return
	}
	printSuccess("Authenticated!")

	orgs, err := getOrganizations(apiURL, token)
	if err != nil || len(orgs) == 0 {
		printError("No organizations found.")
		return
	}
	org := selectOrganization(orgs)

	manifest := createManifestInteractively()

	printInfo("\nCreating integration...")
	integ, err := createIntegration(apiURL, token, org.OrganizationID, manifest)
	if err != nil {
		var httpErr *HTTPError
		if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusConflict {
			printWarning("Integration exists.")
			integ = selectExistingIntegrationPaginated(apiURL, token, org.OrganizationID)
		} else {
			printError(fmt.Sprintf("Failed: %v", err))
			return
		}
	}

	if integ == nil {
		return
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
			printError(fmt.Sprintf("Failed to regenerate client secret: %v", err))
			return
		}
	}

	redirectURL := ""
	if len(manifest.OAuthConfig.RedirectURLs) > 0 {
		redirectURL = manifest.OAuthConfig.RedirectURLs[0]
	}

	config := AppConfig{
		IntegrationID:  integ.ID,
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		RedirectURL:    redirectURL,
		OrganizationID: org.OrganizationID,
		LegionBaseURL:  apiURL,
		Manifest:       manifest,
	}

	if err := saveJSON(ConfigFile, config); err != nil {
		printError(fmt.Sprintf("CRITICAL: Failed to save configuration: %v", err))
		return
	}

	// Initial User Token Save
	printInfo("\n→ Saving authentication token...")
	if err := saveJSON(AccessTokenFile, StoredToken{
		AccessToken:    token,
		ExpiresAt:      time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		OrganizationID: org.OrganizationID,
	}); err != nil {
		printError(fmt.Sprintf("Failed to save access token: %v", err))
		return
	}

	// Perform Headless
	if performHeadlessOAuthFlow(config, token) {
		// Update config with bridge token
		content, err := os.ReadFile(AccessTokenFile)
		if err != nil {
			printError(fmt.Sprintf("Failed to read access token file: %v", err))
			return
		}
		var t StoredToken
		if err := json.Unmarshal(content, &t); err != nil {
			printError(fmt.Sprintf("Failed to unmarshal access token from %s: %v", AccessTokenFile, err))
			return
		}
		config.AccessToken = t.AccessToken
		if err := saveJSON(ConfigFile, config); err != nil {
			printError(fmt.Sprintf("Failed to update config with bridge token: %v", err))
		}
	}
	if createEntity {
		createTerminalEntity(apiURL, config.OrganizationID, config.IntegrationID, config.AccessToken)
	}
}

var errEntityNotFound = fmt.Errorf("entity not found")

func fetchEntityByName(apiURL, orgID, token, name string) (map[string]interface{}, error) {
	headers := map[string]string{"Authorization": "Bearer " + token, "X-ORG-ID": orgID}

	// Search for entity by name using POST /v3/entities/search
	searchPayload := map[string]interface{}{
		"filters": map[string]string{
			"name": name,
		},
	}

	var result EntitySearchResult
	if err := makeRequestJSON("POST", fmt.Sprintf("%s/v3/entities/search", apiURL), searchPayload, headers, &result); err != nil {
		return nil, fmt.Errorf("failed to search entities: %w", err)
	}

	if len(result.Results) == 0 {
		return nil, errEntityNotFound
	}

	return result.Results[0], nil
}

func createTerminalEntity(apiURL, orgID, integID, token string) {
	printColored("\n→ Creating terminal entity...", ColorCyan, true)

	sn := inputPrompt("Terminal Serial Number: ")
	if sn == "" {
		return
	}

	fmt.Println("Available types: 1. lander, 2. helios, 3. portal")
	typeChoice := inputPrompt("Select type (1-3): ")
	tType := "portal"
	if typeChoice == "1" {
		tType = "lander"
	}
	if typeChoice == "2" {
		tType = "helios"
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

	var resp map[string]interface{}
	err := makeRequestJSON("POST", fmt.Sprintf("%s/v3/entities", apiURL), payload, headers, &resp)
	if err != nil {
		var httpErr *HTTPError
		if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusConflict {
			printWarning("Entity already exists. Fetching existing entity...")
			entityName := strings.ToUpper(sn)
			fetchedEntity, fetchErr := fetchEntityByName(apiURL, orgID, token, entityName)
			if fetchErr != nil {
				printError(fmt.Sprintf("Failed to fetch existing entity: %v", fetchErr))
				printError("Terminal entity setup failed. The entity exists but could not be retrieved.")
				return
			}
			if saveErr := saveJSON(TerminalEntityFile, fetchedEntity); saveErr != nil {
				printError(fmt.Sprintf("Failed to save terminal entity: %v", saveErr))
				printError("Terminal entity setup failed. The entity was retrieved but could not be saved.")
				return
			}
			printSuccess("Retrieved and saved existing terminal entity!")
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

	logger = log.New(os.Stdout, "", log.LstdFlags)

	setupCmd := flag.NewFlagSet("setup", flag.ExitOnError)
	createEntityFlag := setupCmd.Bool("create-entity", false, "Create terminal entity during setup")
	setupStoragePath := setupCmd.String("storage-path", "", "Custom storage path")

	installCmd := flag.NewFlagSet("install-service", flag.ExitOnError)
	installStoragePath := installCmd.String("storage-path", "", "Custom storage path")
	installServiceUser := installCmd.String("service-user", "", "User to run the service as (Linux system-level only)")
	installServiceGroup := installCmd.String("service-group", "", "Group to run the service as (Linux system-level only, default: primary group of service user)")
	installUserLevel := installCmd.Bool("user", false, "Install as user-level service (no sudo required)")

	uninstallCmd := flag.NewFlagSet("uninstall-service", flag.ExitOnError)
	uninstallUserLevel := uninstallCmd.Bool("user", false, "Uninstall user-level service")

	storagePathFlag := flag.String("storage-path", "", "Custom storage path")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [command] [options]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Commands:")
		fmt.Fprintln(os.Stderr, "  setup")
		fmt.Fprintln(os.Stderr, "        Run interactive setup configuration")
		fmt.Fprintln(os.Stderr, "        Flags:")
		fmt.Fprintln(os.Stderr, "          --create-entity  Create terminal entity during setup")
		fmt.Fprintln(os.Stderr, "          --storage-path   Custom storage path")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  install-service")
		fmt.Fprintln(os.Stderr, "        Install as a system or user service (systemd/Launchd)")
		fmt.Fprintln(os.Stderr, "        Flags:")
		fmt.Fprintln(os.Stderr, "          --user           Install as user-level service (no sudo required)")
		fmt.Fprintln(os.Stderr, "          --storage-path   Custom storage path")
		fmt.Fprintln(os.Stderr, "          --service-user   User to run service as (Linux system-level only, default: pg if exists, else root)")
		fmt.Fprintln(os.Stderr, "          --service-group  Group to run service as (Linux system-level only, default: primary group of service user)")
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

			if err := setupStorage(*setupStoragePath); err != nil {

				printError(fmt.Sprintf("Storage setup failed: %v", err))

				os.Exit(1)

			}

			interactiveSetup(*createEntityFlag)

			return

		case "install-service":

			if err := installCmd.Parse(os.Args[2:]); err != nil {
				printError(fmt.Sprintf("Failed to parse install-service flags: %v", err))
				os.Exit(1)
			}
			if *installServiceUser == "" {
				*installServiceUser = install.DefaultServiceUser()
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

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		printWarning("\nShutting down...")
		close(shutdownChan)

		// Force exit after timeout if the main thread is blocked (e.g., input prompt)
		<-time.After(2 * time.Second)
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
		_ = exec.Command("systemctl", daemonReloadCmd...).Run()

		printInfo("Enabling legion-auth service...")
		enableCmd := append(systemctlArgs, "enable", "legion-auth")
		if err := exec.Command("systemctl", enableCmd...).Run(); err != nil {
			return fmt.Errorf("failed to enable service: %w", err)
		}

		printInfo("Starting legion-auth service...")
		restartCmd := append(systemctlArgs, "restart", "legion-auth")
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
		_ = exec.Command("launchctl", "unload", plistPath).Run()

		printInfo("Loading service with launchctl...")
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
		_ = exec.Command("systemctl", stopCmd...).Run()

		// Disable service
		printInfo("Disabling legion-auth service...")
		disableCmd := append(systemctlArgs, "disable", "legion-auth")
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
	printColored("\n» Legion Authentication Service", ColorBlue, true)
	printColored("==================================================", ColorGray, false)
	printInfo(fmt.Sprintf("Storage path: %s", StoragePath))

	if _, err := os.Stat(ConfigFile); os.IsNotExist(err) {
		printInfo("No configuration found. Running setup...")
		interactiveSetup(false)
		// If setup failed or was cancelled, we might exit, but let's check config again
		if _, err := os.Stat(ConfigFile); os.IsNotExist(err) {
			return
		}
	}

	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	checkAndRefreshToken()

	printColored("\n→ Starting token monitoring service...", ColorCyan, true)
	printInfo("Service will run indefinitely. Press Ctrl+C to stop.")

	for {
		select {
		case <-shutdownChan:
			return
		case <-ticker.C:
			checkAndRefreshToken()
		}
	}
}

func checkAndRefreshToken() {
	if shouldRefreshToken() {
		refreshAccessToken()
	} else {
		logger.Println("Token valid.")
	}
}
