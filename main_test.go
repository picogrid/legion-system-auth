package main

import (
	"encoding/json"
	"flag"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	os.Exit(m.Run())
}

// chdirTemp changes to a temp directory and returns a cleanup function
// that restores the original working directory.
func chdirTemp(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWd); err != nil {
			t.Logf("warning: failed to restore working directory: %v", err)
		}
	})
}

// writeFile is a test helper that fatals on error.
func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("writeFile(%s): %v", path, err)
	}
}

func useHTTPClient(t *testing.T, client *http.Client) {
	t.Helper()
	prev := httpClient
	httpClient = client
	t.Cleanup(func() {
		httpClient = prev
	})
}

// ============================================================================
// findOrgByID
// ============================================================================

func TestFindOrgByID_Found(t *testing.T) {
	orgs := []Organization{
		{OrganizationID: "aaa", OrganizationName: "Alpha"},
		{OrganizationID: "bbb", OrganizationName: "Bravo"},
		{OrganizationID: "ccc", OrganizationName: "Charlie"},
	}

	org, ok := findOrgByID(orgs, "bbb")
	if !ok {
		t.Fatal("expected to find org bbb")
	}
	if org.OrganizationName != "Bravo" {
		t.Fatalf("got name %q, want %q", org.OrganizationName, "Bravo")
	}
}

func TestFindOrgByID_NotFound(t *testing.T) {
	orgs := []Organization{
		{OrganizationID: "aaa", OrganizationName: "Alpha"},
	}

	_, ok := findOrgByID(orgs, "zzz")
	if ok {
		t.Fatal("expected not to find org zzz")
	}
}

func TestFindOrgByID_EmptyList(t *testing.T) {
	_, ok := findOrgByID(nil, "anything")
	if ok {
		t.Fatal("expected not to find org in nil list")
	}
}

func TestFindOrgByID_EmptyID(t *testing.T) {
	orgs := []Organization{
		{OrganizationID: "aaa", OrganizationName: "Alpha"},
	}
	_, ok := findOrgByID(orgs, "")
	if ok {
		t.Fatal("expected not to find org with empty ID")
	}
}

func TestFindOrgByID_FirstMatch(t *testing.T) {
	orgs := []Organization{
		{OrganizationID: "dup", OrganizationName: "First"},
		{OrganizationID: "dup", OrganizationName: "Second"},
	}

	org, ok := findOrgByID(orgs, "dup")
	if !ok {
		t.Fatal("expected to find org")
	}
	if org.OrganizationName != "First" {
		t.Fatalf("expected first match, got %q", org.OrganizationName)
	}
}

func TestPaginationStep_UsesResultsLength(t *testing.T) {
	if got := paginationStep(7, 10); got != 7 {
		t.Fatalf("paginationStep(7, 10) = %d, want %d", got, 7)
	}
}

func TestPaginationStep_FallsBackWhenPageEmpty(t *testing.T) {
	if got := paginationStep(0, 10); got != 10 {
		t.Fatalf("paginationStep(0, 10) = %d, want %d", got, 10)
	}
}

func TestGetOrganizationsPage_UsesOffsetAndLimitQueryParams(t *testing.T) {
	var gotOffset, gotLimit string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v3/me/orgs" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		gotOffset = r.URL.Query().Get("offset")
		gotLimit = r.URL.Query().Get("limit")
		if auth := r.Header.Get("Authorization"); auth != "Bearer test-token" {
			t.Fatalf("Authorization header = %q, want %q", auth, "Bearer test-token")
		}

		resp := PagedOrganizations{
			Results:    []Organization{{OrganizationID: "org-1", OrganizationName: "Alpha"}},
			TotalCount: 25,
		}
		next := 3
		resp.Paging.Next = &next
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer server.Close()
	useHTTPClient(t, server.Client())

	page, err := getOrganizationsPage(server.URL, "test-token", 10, 10)
	if err != nil {
		t.Fatalf("getOrganizationsPage returned error: %v", err)
	}

	if gotOffset != "10" {
		t.Fatalf("offset query = %q, want %q", gotOffset, "10")
	}
	if gotLimit != "10" {
		t.Fatalf("limit query = %q, want %q", gotLimit, "10")
	}
	if len(page.Results) != 1 || page.Results[0].OrganizationID != "org-1" {
		t.Fatalf("unexpected page results: %+v", page.Results)
	}
	if page.TotalCount != 25 {
		t.Fatalf("unexpected pagination metadata: %+v", *page)
	}
	if page.Paging.Next == nil || *page.Paging.Next != 3 {
		t.Fatalf("unexpected paging.next: %+v", page.Paging)
	}
}

func TestGetOrganization_UsesOrgHeader(t *testing.T) {
	var gotOrgID string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v3/organizations" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		gotOrgID = r.Header.Get("X-ORG-ID")

		resp := Organization{
			OrganizationID:   "org-59",
			OrganizationName: "Omega",
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer server.Close()
	useHTTPClient(t, server.Client())

	org, err := getOrganization(server.URL, "test-token", "org-59")
	if err != nil {
		t.Fatalf("getOrganization returned error: %v", err)
	}
	if gotOrgID != "org-59" {
		t.Fatalf("X-ORG-ID header = %q, want %q", gotOrgID, "org-59")
	}
	if org.OrganizationID != "org-59" {
		t.Fatalf("OrganizationID = %q, want %q", org.OrganizationID, "org-59")
	}
	if org.OrganizationName != "Omega" {
		t.Fatalf("OrganizationName = %q, want %q", org.OrganizationName, "Omega")
	}
}

// ============================================================================
// getPermissionsForRelation
// ============================================================================

func TestGetPermissionsForRelation_AllResourceTypes(t *testing.T) {
	expectedTypes := []string{"org", "feed", "entity", "integration", "event", "track"}

	for _, relation := range []string{"viewer", "operator", "admin"} {
		perms := getPermissionsForRelation(relation)
		if len(perms) != len(expectedTypes) {
			t.Fatalf("getPermissionsForRelation(%q): got %d permissions, want %d", relation, len(perms), len(expectedTypes))
		}
		for i, perm := range perms {
			if perm.ResourceType != expectedTypes[i] {
				t.Errorf("getPermissionsForRelation(%q)[%d].ResourceType = %q, want %q", relation, i, perm.ResourceType, expectedTypes[i])
			}
			if perm.Relation != relation {
				t.Errorf("getPermissionsForRelation(%q)[%d].Relation = %q, want %q", relation, i, perm.Relation, relation)
			}
			if perm.Description == "" {
				t.Errorf("getPermissionsForRelation(%q)[%d].Description is empty", relation, i)
			}
		}
	}
}

// ============================================================================
// createManifestInteractively — non-interactive (flags and defaults)
// ============================================================================

func TestCreateManifest_AllFlagsSet(t *testing.T) {
	chdirTemp(t)

	opts := setupOpts{
		IntegrationName: "MY-DEVICE",
		Description:     "Test integration",
		Version:         "2.5.0",
		RedirectURL:     "http://127.0.0.1:19876/cb",
		AccessLevel:     "admin",
		NonInteractive:  true,
	}

	m := createManifestInteractively(opts)

	if m.Name != "MY-DEVICE" {
		t.Errorf("Name = %q, want %q", m.Name, "MY-DEVICE")
	}
	if m.Description != "Test integration" {
		t.Errorf("Description = %q, want %q", m.Description, "Test integration")
	}
	if m.Version != "2.5.0" {
		t.Errorf("Version = %q, want %q", m.Version, "2.5.0")
	}
	if len(m.OAuthConfig.RedirectURLs) != 1 || m.OAuthConfig.RedirectURLs[0] != "http://127.0.0.1:19876/cb" {
		t.Errorf("RedirectURLs = %v, want [http://127.0.0.1:19876/cb]", m.OAuthConfig.RedirectURLs)
	}
	// admin access level
	if len(m.OAuthConfig.Permissions) == 0 {
		t.Fatal("expected permissions to be set")
	}
	for _, perm := range m.OAuthConfig.Permissions {
		if perm.Relation != "admin" {
			t.Errorf("expected admin relation, got %q for %s", perm.Relation, perm.ResourceType)
		}
	}
	if len(m.OAuthConfig.Scopes) != 0 {
		t.Errorf("expected no legacy scopes, got %v", m.OAuthConfig.Scopes)
	}
}

func TestCreateManifest_NonInteractiveUsesDefaults(t *testing.T) {
	chdirTemp(t)

	opts := setupOpts{NonInteractive: true}
	m := createManifestInteractively(opts)

	if m.Name != "Portal Integration" {
		t.Errorf("Name = %q, want %q", m.Name, "Portal Integration")
	}
	if m.Description != "OAuth integration for portal authentication" {
		t.Errorf("Description = %q, want default", m.Description)
	}
	if m.Version != "1.0.0" {
		t.Errorf("Version = %q, want %q", m.Version, "1.0.0")
	}
	if len(m.OAuthConfig.RedirectURLs) != 1 || m.OAuthConfig.RedirectURLs[0] == "" {
		t.Errorf("RedirectURLs should have default, got %v", m.OAuthConfig.RedirectURLs)
	}
	// Default access level is operator
	for _, perm := range m.OAuthConfig.Permissions {
		if perm.Relation != "operator" {
			t.Errorf("expected operator relation by default, got %q", perm.Relation)
		}
	}
}

func TestCreateManifest_NonInteractiveUsesExistingManifestJSON(t *testing.T) {
	chdirTemp(t)

	existing := Manifest{
		Name:        "FROM-FILE",
		Version:     "9.9.9",
		Description: "Loaded from manifest.json",
		OAuthConfig: ManifestOAuthConfig{
			RedirectURLs: []string{"http://file.example.com/cb"},
			Permissions: []PermissionRequest{
				{ResourceType: "entity", Relation: "viewer", Description: "test"},
			},
		},
	}
	data, _ := json.MarshalIndent(existing, "", "  ")
	writeFile(t, "manifest.json", data)

	opts := setupOpts{NonInteractive: true}
	m := createManifestInteractively(opts)

	if m.Name != "FROM-FILE" {
		t.Errorf("Name = %q, want %q (from manifest.json)", m.Name, "FROM-FILE")
	}
	if m.Version != "9.9.9" {
		t.Errorf("Version = %q, want %q", m.Version, "9.9.9")
	}
}

func TestCreateManifest_NonInteractiveIgnoresMalformedManifestJSON(t *testing.T) {
	chdirTemp(t)

	writeFile(t, "manifest.json", []byte("{invalid json"))

	opts := setupOpts{NonInteractive: true}
	m := createManifestInteractively(opts)

	// Should fall through to defaults since JSON parse failed
	if m.Version != "1.0.0" {
		t.Errorf("Version = %q, want default %q after malformed manifest.json", m.Version, "1.0.0")
	}
}

func TestCreateManifest_AccessLevelViewer(t *testing.T) {
	chdirTemp(t)

	opts := setupOpts{NonInteractive: true, AccessLevel: "viewer"}
	m := createManifestInteractively(opts)

	for _, perm := range m.OAuthConfig.Permissions {
		if perm.Relation != "viewer" {
			t.Errorf("expected viewer relation, got %q", perm.Relation)
		}
	}
}

func TestCreateManifest_AccessLevelOperator(t *testing.T) {
	chdirTemp(t)

	opts := setupOpts{NonInteractive: true, AccessLevel: "operator"}
	m := createManifestInteractively(opts)

	for _, perm := range m.OAuthConfig.Permissions {
		if perm.Relation != "operator" {
			t.Errorf("expected operator relation, got %q", perm.Relation)
		}
	}
}

func TestCreateManifest_AccessLevelInvalid(t *testing.T) {
	chdirTemp(t)

	opts := setupOpts{NonInteractive: true, AccessLevel: "superuser"}
	m := createManifestInteractively(opts)

	// Should fall back to operator
	for _, perm := range m.OAuthConfig.Permissions {
		if perm.Relation != "operator" {
			t.Errorf("expected operator fallback for invalid access level, got %q", perm.Relation)
		}
	}
}

func TestCreateManifest_FlagOverridesDefaultsWithoutNonInteractive(t *testing.T) {
	chdirTemp(t)

	// Even without --non-interactive, explicit flags should be used
	opts := setupOpts{
		IntegrationName: "EXPLICIT",
		Description:     "explicit desc",
		Version:         "3.0.0",
		RedirectURL:     "http://explicit.example.com/cb",
		AccessLevel:     "admin",
	}
	m := createManifestInteractively(opts)

	if m.Name != "EXPLICIT" {
		t.Errorf("Name = %q, want %q", m.Name, "EXPLICIT")
	}
	if m.Description != "explicit desc" {
		t.Errorf("Description = %q, want %q", m.Description, "explicit desc")
	}
	if m.Version != "3.0.0" {
		t.Errorf("Version = %q, want %q", m.Version, "3.0.0")
	}
}

// ============================================================================
// setupOpts flag parsing
// ============================================================================

func TestSetupFlags_AllFlags(t *testing.T) {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	result := registerSetupFlags(fs)

	args := []string{
		"--storage-path", "/tmp/custom",
		"--api-url", "https://legion.example.com",
		"--username", "admin",
		"--password", "s3cret",
		"--org-id", "org-123",
		"--integration-name", "MY-BOX",
		"--description", "My integration",
		"--version", "2.0.0",
		"--redirect-url", "http://localhost:9999/cb",
		"--access-level", "viewer",
		"--entity-name", "SN-001",
		"--entity-type", "helios",
		"--create-entity",
		"--non-interactive",
	}

	if err := fs.Parse(args); err != nil {
		t.Fatalf("failed to parse flags: %v", err)
	}

	opts := result.Opts

	checks := []struct {
		name string
		got  string
		want string
	}{
		{"StoragePath", result.StoragePath, "/tmp/custom"},
		{"APIURL", opts.APIURL, "https://legion.example.com"},
		{"Username", opts.Username, "admin"},
		{"Password", opts.Password, "s3cret"},
		{"OrgID", opts.OrgID, "org-123"},
		{"IntegrationName", opts.IntegrationName, "MY-BOX"},
		{"Description", opts.Description, "My integration"},
		{"Version", opts.Version, "2.0.0"},
		{"RedirectURL", opts.RedirectURL, "http://localhost:9999/cb"},
		{"AccessLevel", opts.AccessLevel, "viewer"},
		{"EntityName", opts.EntityName, "SN-001"},
		{"EntityType", opts.EntityType, "helios"},
	}

	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("opts.%s = %q, want %q", c.name, c.got, c.want)
		}
	}

	if !opts.NonInteractive {
		t.Error("opts.NonInteractive should be true")
	}
	if !opts.CreateEntity {
		t.Error("opts.CreateEntity should be true")
	}
}

func TestSetupFlags_Defaults(t *testing.T) {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	result := registerSetupFlags(fs)

	// Parse with no arguments
	if err := fs.Parse([]string{}); err != nil {
		t.Fatalf("failed to parse empty flags: %v", err)
	}

	opts := result.Opts

	if result.StoragePath != "" {
		t.Errorf("StoragePath default = %q, want empty", result.StoragePath)
	}
	if opts.APIURL != "" {
		t.Errorf("APIURL default = %q, want empty", opts.APIURL)
	}
	if opts.Username != "" {
		t.Errorf("Username default = %q, want empty", opts.Username)
	}
	if opts.NonInteractive {
		t.Error("NonInteractive default should be false")
	}
	if opts.CreateEntity {
		t.Error("CreateEntity default should be false")
	}
}

func TestSetupFlags_PartialFlags(t *testing.T) {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	result := registerSetupFlags(fs)

	// Only API URL provided — simulates partial non-interactive
	args := []string{"--api-url", "https://legion.example.com"}
	if err := fs.Parse(args); err != nil {
		t.Fatalf("failed to parse flags: %v", err)
	}

	opts := result.Opts

	if opts.APIURL != "https://legion.example.com" {
		t.Errorf("APIURL = %q, want %q", opts.APIURL, "https://legion.example.com")
	}
	if opts.Username != "" {
		t.Errorf("Username = %q, want empty", opts.Username)
	}
	if opts.Password != "" {
		t.Errorf("Password = %q, want empty", opts.Password)
	}
	if opts.NonInteractive {
		t.Error("NonInteractive should be false")
	}
}

// ============================================================================
// applySetupEnvDefaults
// ============================================================================

// setEnvForTest sets an environment variable for the duration of the test
// and restores the original value (or unsets it) via t.Cleanup.
func setEnvForTest(t *testing.T, key, value string) {
	t.Helper()
	old, existed := os.LookupEnv(key)
	if err := os.Setenv(key, value); err != nil {
		t.Fatalf("set env %s: %v", key, err)
	}
	t.Cleanup(func() {
		if existed {
			if err := os.Setenv(key, old); err != nil {
				t.Logf("warning: failed to restore env %s: %v", key, err)
			}
		} else {
			if err := os.Unsetenv(key); err != nil {
				t.Logf("warning: failed to unset env %s: %v", key, err)
			}
		}
	})
}

// unsetEnvForTest removes an environment variable for the duration of the test
// and restores it via t.Cleanup if it was previously set.
func unsetEnvForTest(t *testing.T, key string) {
	t.Helper()
	old, existed := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("unset env %s: %v", key, err)
	}
	t.Cleanup(func() {
		if existed {
			if err := os.Setenv(key, old); err != nil {
				t.Logf("warning: failed to restore env %s: %v", key, err)
			}
		} else {
			if err := os.Unsetenv(key); err != nil {
				t.Logf("warning: failed to unset env %s: %v", key, err)
			}
		}
	})
}

// TestApplySetupEnvDefaults_FillsEmptyFields verifies that all LEGION_AUTH_*
// env vars populate the corresponding empty fields in setupFlagResult.
func TestApplySetupEnvDefaults_FillsEmptyFields(t *testing.T) {
	envVars := map[string]string{
		"LEGION_AUTH_STORAGE_PATH":     "/env/storage",
		"LEGION_AUTH_API_URL":          "https://env.example.com",
		"LEGION_AUTH_USERNAME":         "envuser",
		"LEGION_AUTH_PASSWORD":         "envpass",
		"LEGION_AUTH_ORG_ID":           "env-org",
		"LEGION_AUTH_INTEGRATION_NAME": "env-integration",
		"LEGION_AUTH_DESCRIPTION":      "env description",
		"LEGION_AUTH_VERSION":          "9.0.0",
		"LEGION_AUTH_REDIRECT_URL":     "http://env.example.com/cb",
		"LEGION_AUTH_ACCESS_LEVEL":     "admin",
		"LEGION_AUTH_ENTITY_NAME":      "ENV-SERIAL",
		"LEGION_AUTH_ENTITY_TYPE":      "helios",
		"LEGION_AUTH_CREATE_ENTITY":    "true",
		"LEGION_AUTH_NON_INTERACTIVE":  "1",
	}
	for k, v := range envVars {
		setEnvForTest(t, k, v)
	}

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	r := registerSetupFlags(fs)
	if err := fs.Parse([]string{}); err != nil {
		t.Fatal(err)
	}

	applySetupEnvDefaults(r)

	checks := []struct {
		name string
		got  string
		want string
	}{
		{"StoragePath", r.StoragePath, "/env/storage"},
		{"APIURL", r.Opts.APIURL, "https://env.example.com"},
		{"Username", r.Opts.Username, "envuser"},
		{"Password", r.Opts.Password, "envpass"},
		{"OrgID", r.Opts.OrgID, "env-org"},
		{"IntegrationName", r.Opts.IntegrationName, "env-integration"},
		{"Description", r.Opts.Description, "env description"},
		{"Version", r.Opts.Version, "9.0.0"},
		{"RedirectURL", r.Opts.RedirectURL, "http://env.example.com/cb"},
		{"AccessLevel", r.Opts.AccessLevel, "admin"},
		{"EntityName", r.Opts.EntityName, "ENV-SERIAL"},
		{"EntityType", r.Opts.EntityType, "helios"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
	if !r.Opts.CreateEntity {
		t.Error("CreateEntity should be true from env")
	}
	if !r.Opts.NonInteractive {
		t.Error("NonInteractive should be true from env")
	}
}

// TestApplySetupEnvDefaults_FlagsTakePrecedence verifies that CLI flags are
// not overwritten by environment variables.
func TestApplySetupEnvDefaults_FlagsTakePrecedence(t *testing.T) {
	setEnvForTest(t, "LEGION_AUTH_API_URL", "https://env.example.com")
	setEnvForTest(t, "LEGION_AUTH_USERNAME", "envuser")
	setEnvForTest(t, "LEGION_AUTH_PASSWORD", "envpass")

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	r := registerSetupFlags(fs)
	if err := fs.Parse([]string{
		"--api-url", "https://flag.example.com",
		"--username", "flaguser",
		"--password", "flagpass",
	}); err != nil {
		t.Fatal(err)
	}

	applySetupEnvDefaults(r)

	if r.Opts.APIURL != "https://flag.example.com" {
		t.Errorf("APIURL = %q, want flag value", r.Opts.APIURL)
	}
	if r.Opts.Username != "flaguser" {
		t.Errorf("Username = %q, want flag value", r.Opts.Username)
	}
	if r.Opts.Password != "flagpass" {
		t.Errorf("Password = %q, want flag value", r.Opts.Password)
	}
}

// TestApplySetupEnvDefaults_EmptyEnvIgnored verifies that empty or unset
// environment variables do not populate fields.
func TestApplySetupEnvDefaults_EmptyEnvIgnored(t *testing.T) {
	setEnvForTest(t, "LEGION_AUTH_PASSWORD", "")
	unsetEnvForTest(t, "LEGION_AUTH_USERNAME")

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	r := registerSetupFlags(fs)
	if err := fs.Parse([]string{}); err != nil {
		t.Fatal(err)
	}

	applySetupEnvDefaults(r)

	if r.Opts.Password != "" {
		t.Errorf("Password = %q, want empty (empty env should not set)", r.Opts.Password)
	}
	if r.Opts.Username != "" {
		t.Errorf("Username = %q, want empty (unset env should not set)", r.Opts.Username)
	}
}

// TestApplySetupEnvDefaults_BoolEnvVariants verifies that only "true" and "1"
// enable boolean fields; other values are treated as false.
func TestApplySetupEnvDefaults_BoolEnvVariants(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"true", true},
		{"1", true},
		{"false", false},
		{"0", false},
		{"yes", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run("CREATE_ENTITY="+tt.value, func(t *testing.T) {
			setEnvForTest(t, "LEGION_AUTH_CREATE_ENTITY", tt.value)

			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			r := registerSetupFlags(fs)
			if err := fs.Parse([]string{}); err != nil {
				t.Fatal(err)
			}

			applySetupEnvDefaults(r)

			if r.Opts.CreateEntity != tt.want {
				t.Errorf("CreateEntity = %v, want %v for env value %q", r.Opts.CreateEntity, tt.want, tt.value)
			}
		})

		t.Run("NON_INTERACTIVE="+tt.value, func(t *testing.T) {
			setEnvForTest(t, "LEGION_AUTH_NON_INTERACTIVE", tt.value)

			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			r := registerSetupFlags(fs)
			if err := fs.Parse([]string{}); err != nil {
				t.Fatal(err)
			}

			applySetupEnvDefaults(r)

			if r.Opts.NonInteractive != tt.want {
				t.Errorf("NonInteractive = %v, want %v for env value %q", r.Opts.NonInteractive, tt.want, tt.value)
			}
		})
	}
}

// TestApplySetupEnvDefaults_BoolFlagTrueIgnoresEnv verifies that a boolean
// flag set to true via CLI is not reset by an env var set to "false".
func TestApplySetupEnvDefaults_BoolFlagTrueIgnoresEnv(t *testing.T) {
	setEnvForTest(t, "LEGION_AUTH_CREATE_ENTITY", "false")

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	r := registerSetupFlags(fs)
	if err := fs.Parse([]string{"--create-entity"}); err != nil {
		t.Fatal(err)
	}

	applySetupEnvDefaults(r)

	if !r.Opts.CreateEntity {
		t.Error("CreateEntity should remain true from flag despite env=false")
	}
}

// TestApplySetupEnvDefaults_LegacyLegionAPIURL verifies that the deprecated
// LEGION_API_URL env var is used as a fallback when LEGION_AUTH_API_URL is unset.
func TestApplySetupEnvDefaults_LegacyLegionAPIURL(t *testing.T) {
	unsetEnvForTest(t, "LEGION_AUTH_API_URL")
	setEnvForTest(t, "LEGION_API_URL", "https://legacy.example.com")

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	r := registerSetupFlags(fs)
	if err := fs.Parse([]string{}); err != nil {
		t.Fatal(err)
	}

	applySetupEnvDefaults(r)

	if r.Opts.APIURL != "https://legacy.example.com" {
		t.Errorf("APIURL = %q, want legacy env value", r.Opts.APIURL)
	}
}

// TestApplySetupEnvDefaults_NewAPIURLTakesPrecedenceOverLegacy verifies that
// LEGION_AUTH_API_URL takes precedence over the deprecated LEGION_API_URL.
func TestApplySetupEnvDefaults_NewAPIURLTakesPrecedenceOverLegacy(t *testing.T) {
	setEnvForTest(t, "LEGION_AUTH_API_URL", "https://new.example.com")
	setEnvForTest(t, "LEGION_API_URL", "https://legacy.example.com")

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	r := registerSetupFlags(fs)
	if err := fs.Parse([]string{}); err != nil {
		t.Fatal(err)
	}

	applySetupEnvDefaults(r)

	if r.Opts.APIURL != "https://new.example.com" {
		t.Errorf("APIURL = %q, want new env value over legacy", r.Opts.APIURL)
	}
}

// ============================================================================
// setupOpts zero value = fully interactive
// ============================================================================

func TestSetupOpts_ZeroValueIsInteractive(t *testing.T) {
	var opts setupOpts
	if opts.APIURL != "" {
		t.Error("zero APIURL should be empty")
	}
	if opts.Username != "" {
		t.Error("zero Username should be empty")
	}
	if opts.NonInteractive {
		t.Error("zero NonInteractive should be false")
	}
	if opts.CreateEntity {
		t.Error("zero CreateEntity should be false")
	}
}

// ============================================================================
// Entity type mapping (via createTerminalEntity opts logic)
// ============================================================================

func TestEntityTypeMapping(t *testing.T) {
	isValid := func(s string) bool {
		for _, t := range validEntityTypes {
			if t == s {
				return true
			}
		}
		return false
	}

	t.Run("valid types accepted", func(t *testing.T) {
		for _, name := range []string{"lander", "helios", "portal", "dev-unit"} {
			if !isValid(name) {
				t.Errorf("expected %q to be valid", name)
			}
		}
	})

	t.Run("invalid types rejected", func(t *testing.T) {
		for _, input := range []string{"unknown", "INVALID", "lander2", ""} {
			if isValid(input) {
				t.Errorf("expected %q to be invalid", input)
			}
		}
	})
}

// ============================================================================
// HTTPError
// ============================================================================

func TestHTTPError_ErrorFormat(t *testing.T) {
	err := &HTTPError{StatusCode: 409, Body: "conflict"}
	expected := "HTTP 409: conflict"
	if err.Error() != expected {
		t.Errorf("HTTPError.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestHTTPError_SatisfiesErrorInterface(t *testing.T) {
	httpErr := &HTTPError{StatusCode: 500, Body: "internal"}
	// Verify it satisfies error interface via assignment.
	var err error = httpErr
	if err.Error() == "" {
		t.Error("expected non-empty error string")
	}
}

// ============================================================================
// saveJSON
// ============================================================================

func TestSaveJSON_WritesValidJSON(t *testing.T) {
	// Disable group chown for test (may not have perms)
	origGID := fileGID
	fileGID = -1
	defer func() { fileGID = origGID }()

	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")

	data := map[string]string{"key": "value"}
	if err := saveJSON(path, data); err != nil {
		t.Fatalf("saveJSON failed: %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read written file: %v", err)
	}

	var result map[string]string
	if err := json.Unmarshal(content, &result); err != nil {
		t.Fatalf("written file is not valid JSON: %v", err)
	}
	if result["key"] != "value" {
		t.Errorf("got key=%q, want %q", result["key"], "value")
	}
}

func TestSaveJSON_InvalidPath(t *testing.T) {
	err := saveJSON("/nonexistent/directory/file.json", map[string]string{"a": "b"})
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

func TestSaveJSON_FilePermissions(t *testing.T) {
	origGID := fileGID
	fileGID = -1
	defer func() { fileGID = origGID }()

	dir := t.TempDir()
	path := filepath.Join(dir, "perms.json")

	if err := saveJSON(path, "test"); err != nil {
		t.Fatalf("saveJSON failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	// filePermissions is 0640
	if info.Mode().Perm() != filePermissions {
		t.Errorf("file permissions = %o, want %o", info.Mode().Perm(), filePermissions)
	}
}

// ============================================================================
// PKCE helpers
// ============================================================================

func TestGenerateCodeVerifier_Uniqueness(t *testing.T) {
	v1, err := generateCodeVerifier()
	if err != nil {
		t.Fatalf("generateCodeVerifier failed: %v", err)
	}
	v2, err := generateCodeVerifier()
	if err != nil {
		t.Fatalf("generateCodeVerifier failed: %v", err)
	}
	if v1 == v2 {
		t.Error("expected unique verifiers")
	}
	if len(v1) == 0 {
		t.Error("verifier should not be empty")
	}
}

func TestGenerateCodeChallenge_Deterministic(t *testing.T) {
	verifier := "test-verifier-string"
	c1 := generateCodeChallenge(verifier)
	c2 := generateCodeChallenge(verifier)
	if c1 != c2 {
		t.Error("code challenge should be deterministic for same verifier")
	}
	if len(c1) == 0 {
		t.Error("challenge should not be empty")
	}
}

func TestGenerateCodeChallenge_DifferentInputs(t *testing.T) {
	c1 := generateCodeChallenge("verifier-a")
	c2 := generateCodeChallenge("verifier-b")
	if c1 == c2 {
		t.Error("different verifiers should produce different challenges")
	}
}

func TestGenerateState_Uniqueness(t *testing.T) {
	s1, err := generateState()
	if err != nil {
		t.Fatalf("generateState failed: %v", err)
	}
	s2, err := generateState()
	if err != nil {
		t.Fatalf("generateState failed: %v", err)
	}
	if s1 == s2 {
		t.Error("expected unique states")
	}
}

// ============================================================================
// setupStorage
// ============================================================================

// saveAndRestoreStorageGlobals captures the package-level storage path
// variables before a test and restores them via t.Cleanup.
func saveAndRestoreStorageGlobals(t *testing.T) {
	t.Helper()
	origStoragePath := StoragePath
	origConfigFile := ConfigFile
	origAccessTokenFile := AccessTokenFile
	origRefreshTokenFile := RefreshTokenFile
	origTerminalEntityFile := TerminalEntityFile
	origLegionOAuthPath := LegionOAuthPath
	t.Cleanup(func() {
		StoragePath = origStoragePath
		ConfigFile = origConfigFile
		AccessTokenFile = origAccessTokenFile
		RefreshTokenFile = origRefreshTokenFile
		TerminalEntityFile = origTerminalEntityFile
		LegionOAuthPath = origLegionOAuthPath
	})
}

func TestSetupStorage_CustomPath(t *testing.T) {
	saveAndRestoreStorageGlobals(t)
	dir := t.TempDir()
	custom := filepath.Join(dir, "custom", "auth")

	if err := setupStorage(custom); err != nil {
		t.Fatalf("setupStorage failed: %v", err)
	}

	if StoragePath != custom {
		t.Errorf("StoragePath = %q, want %q", StoragePath, custom)
	}
	if ConfigFile != filepath.Join(custom, "oauth_config.json") {
		t.Errorf("ConfigFile = %q, want %q", ConfigFile, filepath.Join(custom, "oauth_config.json"))
	}

	if _, err := os.Stat(custom); os.IsNotExist(err) {
		t.Error("expected storage directory to be created")
	}
}

func TestSetupStorage_CreatesDirectory(t *testing.T) {
	saveAndRestoreStorageGlobals(t)
	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b", "c")

	if err := setupStorage(nested); err != nil {
		t.Fatalf("setupStorage failed: %v", err)
	}

	if _, err := os.Stat(nested); os.IsNotExist(err) {
		t.Error("expected nested directory to be created")
	}
}

// ============================================================================
// Manifest JSON round-trip
// ============================================================================

func TestManifest_JSONRoundTrip(t *testing.T) {
	m := Manifest{
		Name:        "TEST",
		Version:     "1.0.0",
		Description: "test manifest",
		OAuthConfig: ManifestOAuthConfig{
			Permissions: []PermissionRequest{
				{ResourceType: "entity", Relation: "operator", Description: "entity access"},
			},
			RedirectURLs: []string{"http://localhost:8000/cb"},
		},
	}

	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var m2 Manifest
	if err := json.Unmarshal(data, &m2); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if m2.Name != m.Name || m2.Version != m.Version || m2.Description != m.Description {
		t.Errorf("round-trip mismatch: got %+v", m2)
	}
	if len(m2.OAuthConfig.Permissions) != 1 {
		t.Fatalf("expected 1 permission, got %d", len(m2.OAuthConfig.Permissions))
	}
	if m2.OAuthConfig.Permissions[0].Relation != "operator" {
		t.Errorf("permission relation = %q, want %q", m2.OAuthConfig.Permissions[0].Relation, "operator")
	}
}

func TestManifest_JSONOmitsEmptyScopes(t *testing.T) {
	m := Manifest{
		Name:    "TEST",
		Version: "1.0.0",
		OAuthConfig: ManifestOAuthConfig{
			Permissions: []PermissionRequest{
				{ResourceType: "org", Relation: "viewer", Description: "test"},
			},
		},
	}

	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw failed: %v", err)
	}

	var oauthRaw map[string]json.RawMessage
	if err := json.Unmarshal(raw["oauth_config"], &oauthRaw); err != nil {
		t.Fatalf("unmarshal oauth_config failed: %v", err)
	}

	if _, ok := oauthRaw["scopes"]; ok {
		t.Error("expected scopes to be omitted when nil")
	}
}
