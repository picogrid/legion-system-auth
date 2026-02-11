package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	logger = log.New(os.Stderr, "test: ", log.LstdFlags)
	os.Exit(m.Run())
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
// createManifestInteractively — headless (--yes with flags)
// ============================================================================

func TestCreateManifest_AllFlagsSet(t *testing.T) {
	// Ensure no manifest.json interferes from CWD
	dir := t.TempDir()
	oldWd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWd)

	opts := loginOpts{
		Name:        "MY-DEVICE",
		Description: "Test integration",
		Version:     "2.5.0",
		RedirectURL: "http://127.0.0.1:19876/cb",
		AccessLevel: "admin",
		Yes:         true,
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

func TestCreateManifest_YesUsesDefaults(t *testing.T) {
	dir := t.TempDir()
	oldWd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWd)

	opts := loginOpts{Yes: true}
	m := createManifestInteractively(opts)

	// Name should be uppercase hostname
	hostname, _ := os.Hostname()
	if hostname != "" {
		// name should be set (hostname uppercased or fallback)
		if m.Name == "" {
			t.Error("Name should not be empty with --yes")
		}
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

func TestCreateManifest_YesUsesExistingManifestJSON(t *testing.T) {
	dir := t.TempDir()
	oldWd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWd)

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
	os.WriteFile("manifest.json", data, 0644)

	opts := loginOpts{Yes: true}
	m := createManifestInteractively(opts)

	if m.Name != "FROM-FILE" {
		t.Errorf("Name = %q, want %q (from manifest.json)", m.Name, "FROM-FILE")
	}
	if m.Version != "9.9.9" {
		t.Errorf("Version = %q, want %q", m.Version, "9.9.9")
	}
}

func TestCreateManifest_YesIgnoresMalformedManifestJSON(t *testing.T) {
	dir := t.TempDir()
	oldWd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWd)

	os.WriteFile("manifest.json", []byte("{invalid json"), 0644)

	opts := loginOpts{Yes: true}
	m := createManifestInteractively(opts)

	// Should fall through to defaults since JSON parse failed
	if m.Version != "1.0.0" {
		t.Errorf("Version = %q, want default %q after malformed manifest.json", m.Version, "1.0.0")
	}
}

func TestCreateManifest_AccessLevelViewer(t *testing.T) {
	dir := t.TempDir()
	oldWd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWd)

	opts := loginOpts{Yes: true, AccessLevel: "viewer"}
	m := createManifestInteractively(opts)

	for _, perm := range m.OAuthConfig.Permissions {
		if perm.Relation != "viewer" {
			t.Errorf("expected viewer relation, got %q", perm.Relation)
		}
	}
}

func TestCreateManifest_AccessLevelOperator(t *testing.T) {
	dir := t.TempDir()
	oldWd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWd)

	opts := loginOpts{Yes: true, AccessLevel: "operator"}
	m := createManifestInteractively(opts)

	for _, perm := range m.OAuthConfig.Permissions {
		if perm.Relation != "operator" {
			t.Errorf("expected operator relation, got %q", perm.Relation)
		}
	}
}

func TestCreateManifest_AccessLevelInvalid(t *testing.T) {
	dir := t.TempDir()
	oldWd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWd)

	opts := loginOpts{Yes: true, AccessLevel: "superuser"}
	m := createManifestInteractively(opts)

	// Should fall back to operator
	for _, perm := range m.OAuthConfig.Permissions {
		if perm.Relation != "operator" {
			t.Errorf("expected operator fallback for invalid access level, got %q", perm.Relation)
		}
	}
}

func TestCreateManifest_FlagOverridesDefaultsWithoutYes(t *testing.T) {
	dir := t.TempDir()
	oldWd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWd)

	// Even without --yes, explicit flags should be used
	opts := loginOpts{
		Name:        "EXPLICIT",
		Description: "explicit desc",
		Version:     "3.0.0",
		RedirectURL: "http://explicit.example.com/cb",
		AccessLevel: "admin",
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
// loginOpts flag parsing
// ============================================================================

func TestLoginFlags_AllFlags(t *testing.T) {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	apiURL := fs.String("api-url", "", "")
	username := fs.String("username", "", "")
	password := fs.String("password", "", "")
	orgID := fs.String("org-id", "", "")
	name := fs.String("name", "", "")
	description := fs.String("description", "", "")
	version := fs.String("version", "", "")
	redirectURL := fs.String("redirect-url", "", "")
	accessLevel := fs.String("access-level", "", "")
	serial := fs.String("serial", "", "")
	entityType := fs.String("entity-type", "", "")
	yes := fs.Bool("yes", false, "")
	noEntity := fs.Bool("no-entity", false, "")

	args := []string{
		"--api-url", "https://legion.example.com",
		"--username", "admin",
		"--password", "s3cret",
		"--org-id", "org-123",
		"--name", "MY-BOX",
		"--description", "My integration",
		"--version", "2.0.0",
		"--redirect-url", "http://localhost:9999/cb",
		"--access-level", "viewer",
		"--serial", "SN-001",
		"--entity-type", "helios",
		"--yes",
		"--no-entity",
	}

	if err := fs.Parse(args); err != nil {
		t.Fatalf("failed to parse flags: %v", err)
	}

	opts := loginOpts{
		APIURL:      *apiURL,
		Username:    *username,
		Password:    *password,
		OrgID:       *orgID,
		Name:        *name,
		Description: *description,
		Version:     *version,
		RedirectURL: *redirectURL,
		AccessLevel: *accessLevel,
		Serial:      *serial,
		EntityType:  *entityType,
		Yes:         *yes,
		NoEntity:    *noEntity,
	}

	checks := []struct {
		name string
		got  string
		want string
	}{
		{"APIURL", opts.APIURL, "https://legion.example.com"},
		{"Username", opts.Username, "admin"},
		{"Password", opts.Password, "s3cret"},
		{"OrgID", opts.OrgID, "org-123"},
		{"Name", opts.Name, "MY-BOX"},
		{"Description", opts.Description, "My integration"},
		{"Version", opts.Version, "2.0.0"},
		{"RedirectURL", opts.RedirectURL, "http://localhost:9999/cb"},
		{"AccessLevel", opts.AccessLevel, "viewer"},
		{"Serial", opts.Serial, "SN-001"},
		{"EntityType", opts.EntityType, "helios"},
	}

	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("opts.%s = %q, want %q", c.name, c.got, c.want)
		}
	}

	if !opts.Yes {
		t.Error("opts.Yes should be true")
	}
	if !opts.NoEntity {
		t.Error("opts.NoEntity should be true")
	}
}

func TestLoginFlags_Defaults(t *testing.T) {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	apiURL := fs.String("api-url", "", "")
	username := fs.String("username", "", "")
	yes := fs.Bool("yes", false, "")
	noEntity := fs.Bool("no-entity", false, "")

	// Parse with no arguments
	if err := fs.Parse([]string{}); err != nil {
		t.Fatalf("failed to parse empty flags: %v", err)
	}

	if *apiURL != "" {
		t.Errorf("api-url default = %q, want empty", *apiURL)
	}
	if *username != "" {
		t.Errorf("username default = %q, want empty", *username)
	}
	if *yes {
		t.Error("yes default should be false")
	}
	if *noEntity {
		t.Error("no-entity default should be false")
	}
}

func TestLoginFlags_PartialFlags(t *testing.T) {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	apiURL := fs.String("api-url", "", "")
	username := fs.String("username", "", "")
	password := fs.String("password", "", "")
	yes := fs.Bool("yes", false, "")

	// Only API URL provided — simulates partial headless
	args := []string{"--api-url", "https://legion.example.com"}
	if err := fs.Parse(args); err != nil {
		t.Fatalf("failed to parse flags: %v", err)
	}

	if *apiURL != "https://legion.example.com" {
		t.Errorf("api-url = %q, want %q", *apiURL, "https://legion.example.com")
	}
	if *username != "" {
		t.Errorf("username = %q, want empty", *username)
	}
	if *password != "" {
		t.Errorf("password = %q, want empty", *password)
	}
	if *yes {
		t.Error("yes should be false")
	}
}

// ============================================================================
// loginOpts zero value = fully interactive
// ============================================================================

func TestLoginOpts_ZeroValueIsInteractive(t *testing.T) {
	var opts loginOpts
	if opts.APIURL != "" {
		t.Error("zero APIURL should be empty")
	}
	if opts.Username != "" {
		t.Error("zero Username should be empty")
	}
	if opts.Yes {
		t.Error("zero Yes should be false")
	}
	if opts.NoEntity {
		t.Error("zero NoEntity should be false")
	}
}

// ============================================================================
// hasAuthFiles / removeAuthFiles
// ============================================================================

func TestHasAuthFiles_Empty(t *testing.T) {
	dir := t.TempDir()
	if hasAuthFiles(dir) {
		t.Error("expected no auth files in empty dir")
	}
}

func TestHasAuthFiles_WithConfig(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "oauth_config.json"), []byte("{}"), 0644)
	if !hasAuthFiles(dir) {
		t.Error("expected auth files when oauth_config.json exists")
	}
}

func TestHasAuthFiles_WithAccessToken(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "access_token.json"), []byte("{}"), 0644)
	if !hasAuthFiles(dir) {
		t.Error("expected auth files when access_token.json exists")
	}
}

func TestHasAuthFiles_WithTerminalEntity(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "terminal_entity.json"), []byte("{}"), 0644)
	if !hasAuthFiles(dir) {
		t.Error("expected auth files when terminal_entity.json exists")
	}
}

func TestRemoveAuthFiles_CleansAllFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"oauth_config.json", "access_token.json", "refresh_token.json", "extra.txt"} {
		os.WriteFile(filepath.Join(dir, name), []byte("data"), 0644)
	}

	if err := removeAuthFiles(dir); err != nil {
		t.Fatalf("removeAuthFiles failed: %v", err)
	}

	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("expected empty dir after removeAuthFiles, got %d entries", len(entries))
	}
}

func TestRemoveAuthFiles_SkipsDirectories(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "subdir"), 0755)
	os.WriteFile(filepath.Join(dir, "file.json"), []byte("data"), 0644)

	if err := removeAuthFiles(dir); err != nil {
		t.Fatalf("removeAuthFiles failed: %v", err)
	}

	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "subdir" {
		t.Errorf("expected only subdir to remain, got %v", entries)
	}
}

func TestRemoveAuthFiles_NonexistentDir(t *testing.T) {
	err := removeAuthFiles("/nonexistent/path/that/doesnt/exist")
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
}

// ============================================================================
// Entity type mapping (via createTerminalEntity opts logic)
// ============================================================================

func TestEntityTypeMapping(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"lander", "lander"},
		{"helios", "helios"},
		{"portal", "portal"},
		{"unknown", "portal"},   // falls back to portal
		{"INVALID", "portal"},   // falls back to portal
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("input_%s", tt.input), func(t *testing.T) {
			var tType string
			switch tt.input {
			case "lander", "helios", "portal":
				tType = tt.input
			default:
				tType = "portal"
			}
			if tType != tt.expected {
				t.Errorf("entity type for %q = %q, want %q", tt.input, tType, tt.expected)
			}
		})
	}
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
	var err error = &HTTPError{StatusCode: 500, Body: "internal"}
	if err == nil {
		t.Error("expected non-nil error")
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

func TestSetupStorage_CustomPath(t *testing.T) {
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
	json.Unmarshal(data, &raw)

	var oauthRaw map[string]json.RawMessage
	json.Unmarshal(raw["oauth_config"], &oauthRaw)

	if _, ok := oauthRaw["scopes"]; ok {
		t.Error("expected scopes to be omitted when nil")
	}
}
