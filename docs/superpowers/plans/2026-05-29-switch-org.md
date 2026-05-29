# switch-org Command + Storage Permission Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `legion-auth switch-org` command that re-provisions a device's integration and terminal entity in a new Legion org (reusing an existing terminal where possible, optionally deleting the old org's terminal), and fix a storage-directory permission regression that breaks token refresh after re-running setup.

**Architecture:** `switch-org` is a focused, old-context-aware re-run of setup's provisioning steps. Because stored tokens are integration tokens scoped to the old org and integrations are per-org, it re-authenticates the user (password grant → org-agnostic user token), provisions a new integration + OAuth tokens in the target org, reuses the device's serial/type for the new-org terminal, then best-effort deletes the old org's terminal last. Shared integration-resolution logic is extracted into `resolveIntegration` and reused by both `setup` and `switch-org` (DRY). The permission fix makes `setupStorage` deterministically `chmod` the storage dir regardless of umask or whether the `pg` user exists.

**Tech Stack:** Go 1.24, standard library (`net/http`, `flag`, `encoding/json`), `httptest` for tests. Single-package `main` (`main.go` + `main_test.go`).

---

## File Structure

- `main.go` — all production changes (new `switch-org` dispatch, `switchOrg`, `loadCurrentContext`, `deleteEntity`, `resolveIntegration` extraction, `registerSwitchOrgFlags`, `setupOpts.RemoveOld`, `setupStorage` perm fix). This codebase keeps everything in one `main.go`; follow that pattern.
- `main_test.go` — all new tests, following existing helpers (`useHTTPClient`, `saveAndRestoreStorageGlobals`, `setEnvForTest`, `writeFile`).
- `README.md` — document the new command.
- `docs/superpowers/specs/2026-05-29-switch-org-design.md` — the approved design (already committed).

---

## Task 1: Add `RemoveOld` option, env default, and switch-org flag registration

**Files:**
- Modify: `main.go` (the `setupOpts` struct ~line 220; `applySetupEnvDefaults` ~line 284; add `registerSwitchOrgFlags` after `registerSetupFlags` ~line 263)
- Test: `main_test.go`

- [ ] **Step 1: Add the failing tests**

Add to `main_test.go`. First add `"strings"` to the import block (it is not currently imported). Then add:

```go
func TestSwitchOrgFlags_AllFlags(t *testing.T) {
	fs := flag.NewFlagSet("switch-org", flag.ContinueOnError)
	r := registerSwitchOrgFlags(fs)

	args := []string{
		"--storage-path", "/tmp/custom",
		"--api-url", "https://legion.example.com",
		"--username", "admin",
		"--password", "s3cret",
		"--org-id", "org-999",
		"--entity-name", "SN-7",
		"--entity-type", "lander",
		"--remove-old",
		"--non-interactive",
	}
	if err := fs.Parse(args); err != nil {
		t.Fatalf("failed to parse flags: %v", err)
	}

	o := r.Opts
	if r.StoragePath != "/tmp/custom" {
		t.Errorf("StoragePath = %q, want %q", r.StoragePath, "/tmp/custom")
	}
	if o.APIURL != "https://legion.example.com" {
		t.Errorf("APIURL = %q", o.APIURL)
	}
	if o.Username != "admin" {
		t.Errorf("Username = %q", o.Username)
	}
	if o.Password != "s3cret" {
		t.Errorf("Password = %q", o.Password)
	}
	if o.OrgID != "org-999" {
		t.Errorf("OrgID = %q", o.OrgID)
	}
	if o.EntityName != "SN-7" {
		t.Errorf("EntityName = %q", o.EntityName)
	}
	if o.EntityType != "lander" {
		t.Errorf("EntityType = %q", o.EntityType)
	}
	if !o.RemoveOld {
		t.Error("RemoveOld should be true")
	}
	if !o.NonInteractive {
		t.Error("NonInteractive should be true")
	}
}

func TestApplySetupEnvDefaults_RemoveOld(t *testing.T) {
	setEnvForTest(t, "LEGION_AUTH_REMOVE_OLD", "true")

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	r := registerSwitchOrgFlags(fs)
	if err := fs.Parse([]string{}); err != nil {
		t.Fatal(err)
	}

	applySetupEnvDefaults(r)

	if !r.Opts.RemoveOld {
		t.Error("RemoveOld should be true from LEGION_AUTH_REMOVE_OLD env")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./... -run 'TestSwitchOrgFlags_AllFlags|TestApplySetupEnvDefaults_RemoveOld' -v`
Expected: FAIL — compile error `undefined: registerSwitchOrgFlags` and `r.Opts.RemoveOld undefined`.

- [ ] **Step 3: Add the `RemoveOld` field to `setupOpts`**

In `main.go`, in the `setupOpts` struct (currently ends with `NonInteractive bool`), add a field:

```go
	CreateEntity    bool
	NonInteractive  bool
	RemoveOld       bool // switch-org: delete the old org's terminal entity
}
```

- [ ] **Step 4: Add the env default for `RemoveOld`**

In `applySetupEnvDefaults`, after the existing `envBool(&r.Opts.NonInteractive, "LEGION_AUTH_NON_INTERACTIVE")` line, add:

```go
	envBool(&r.Opts.RemoveOld, "LEGION_AUTH_REMOVE_OLD")
```

- [ ] **Step 5: Add `registerSwitchOrgFlags`**

In `main.go`, immediately after the `registerSetupFlags` function, add:

```go
// registerSwitchOrgFlags registers the flags for the switch-org sub-command.
// It reuses setupFlagResult/setupOpts so switch-org can share setup's helpers
// (authentication, integration resolution, terminal creation). --api-url is
// optional here; it defaults to the LegionBaseURL in the existing config.
func registerSwitchOrgFlags(fs *flag.FlagSet) *setupFlagResult {
	r := &setupFlagResult{}
	fs.StringVar(&r.StoragePath, "storage-path", "", "Custom storage path")
	fs.StringVar(&r.Opts.APIURL, "api-url", "", "Legion API URL (default: stored value)")
	fs.StringVar(&r.Opts.Username, "username", "", "Username for authentication")
	fs.StringVar(&r.Opts.Password, "password", "", "Password for authentication")
	fs.StringVar(&r.Opts.OrgID, "org-id", "", "Target organization ID (skips org selector)")
	fs.StringVar(&r.Opts.EntityName, "entity-name", "", "Terminal entity name / serial number (default: reuse current)")
	fs.StringVar(&r.Opts.EntityType, "entity-type", "", "Terminal type: lander/helios/portal/dev-unit (default: reuse current)")
	fs.BoolVar(&r.Opts.RemoveOld, "remove-old", false, "Delete the terminal entity from the previous org")
	fs.BoolVar(&r.Opts.NonInteractive, "non-interactive", false, "Run without prompts, use flags")
	return r
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./... -run 'TestSwitchOrgFlags_AllFlags|TestApplySetupEnvDefaults_RemoveOld' -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add main.go main_test.go
git commit -m "feat: add switch-org flags and RemoveOld option

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Extract `resolveIntegration` and reuse it in `interactiveSetup`

**Files:**
- Modify: `main.go` (add `resolveIntegration` near `createIntegration` ~line 1160; refactor the tail of `interactiveSetup` ~lines 1728-1842)
- Test: `main_test.go`

- [ ] **Step 1: Add the failing test**

Add to `main_test.go`:

```go
func TestResolveIntegration_CreatesAndReturnsConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v3/integrations" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-ORG-ID") != "org-new" {
			t.Errorf("X-ORG-ID = %q, want org-new", r.Header.Get("X-ORG-ID"))
		}
		if r.Header.Get("Authorization") != "Bearer user-token" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		resp := Integration{
			ID:      "int-1",
			Name:    "MY-DEV",
			Version: "1.0.0",
			OAuthConfig: &IntOAuthCfg{
				ClientID:     "cid",
				ClientSecret: "secret",
				RedirectURLs: []string{"http://localhost:8000/cb"},
			},
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}))
	defer server.Close()
	useHTTPClient(t, server.Client())

	manifest := Manifest{
		Name:    "MY-DEV",
		Version: "1.0.0",
		OAuthConfig: ManifestOAuthConfig{
			RedirectURLs: []string{"http://localhost:8000/cb"},
		},
	}
	org := Organization{OrganizationID: "org-new", OrganizationName: "NewOrg"}

	cfg, err := resolveIntegration(server.URL, "user-token", org, manifest, true)
	if err != nil {
		t.Fatalf("resolveIntegration: %v", err)
	}
	if cfg.IntegrationID != "int-1" {
		t.Errorf("IntegrationID = %q", cfg.IntegrationID)
	}
	if cfg.ClientID != "cid" {
		t.Errorf("ClientID = %q", cfg.ClientID)
	}
	if cfg.ClientSecret != "secret" {
		t.Errorf("ClientSecret = %q", cfg.ClientSecret)
	}
	if cfg.RedirectURL != "http://localhost:8000/cb" {
		t.Errorf("RedirectURL = %q", cfg.RedirectURL)
	}
	if cfg.OrganizationID != "org-new" {
		t.Errorf("OrganizationID = %q", cfg.OrganizationID)
	}
	if cfg.OrganizationName != "NewOrg" {
		t.Errorf("OrganizationName = %q", cfg.OrganizationName)
	}
	if cfg.LegionBaseURL != server.URL {
		t.Errorf("LegionBaseURL = %q, want %q", cfg.LegionBaseURL, server.URL)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestResolveIntegration_CreatesAndReturnsConfig -v`
Expected: FAIL — `undefined: resolveIntegration`.

- [ ] **Step 3: Add `resolveIntegration`**

In `main.go`, immediately after the `createIntegration` function, add:

```go
// resolveIntegration creates (or finds, on conflict) the org's integration and
// returns a fully populated AppConfig ready to persist. Shared by setup and
// switch-org. On a 409 it falls back to finding the integration by name
// (non-interactive) or a paginated picker (interactive). It regenerates the
// client secret when the platform returns an empty or redacted one.
func resolveIntegration(apiURL, token string, org Organization, manifest Manifest, nonInteractive bool) (*AppConfig, error) {
	integ, err := createIntegration(apiURL, token, org.OrganizationID, manifest)
	if err != nil {
		var httpErr *HTTPError
		if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusConflict {
			printWarning("Integration exists.")
			if nonInteractive {
				integ = findIntegrationByName(apiURL, token, org.OrganizationID, manifest.Name)
			} else {
				integ = selectExistingIntegrationPaginated(apiURL, token, org.OrganizationID)
			}
		} else {
			return nil, fmt.Errorf("failed to create integration: %w", err)
		}
	}
	if integ == nil {
		return nil, fmt.Errorf("no integration selected")
	}

	var clientID, clientSecret string
	if integ.OAuthConfig != nil {
		clientID = integ.OAuthConfig.ClientID
		clientSecret = integ.OAuthConfig.ClientSecret
	}

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
			return nil, fmt.Errorf("failed to regenerate client secret: %w", err)
		}
	}

	redirectURL := ""
	if len(manifest.OAuthConfig.RedirectURLs) > 0 {
		redirectURL = manifest.OAuthConfig.RedirectURLs[0]
	}

	return &AppConfig{
		IntegrationID:    integ.ID,
		ClientID:         clientID,
		ClientSecret:     clientSecret,
		RedirectURL:      redirectURL,
		OrganizationID:   org.OrganizationID,
		OrganizationName: org.OrganizationName,
		LegionBaseURL:    apiURL,
		Manifest:         manifest,
	}, nil
}
```

- [ ] **Step 4: Refactor `interactiveSetup` to use it**

In `main.go`, replace the entire tail of `interactiveSetup` — from the line `manifest := createManifestInteractively(opts)` through the function's final `return nil` and closing `}` (currently lines ~1728-1842) — with exactly:

```go
	manifest := createManifestInteractively(opts)

	printInfo("\nCreating integration...")
	cfg, err := resolveIntegration(apiURL, token, org, manifest, opts.NonInteractive)
	if err != nil {
		return err
	}
	config := *cfg

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
```

- [ ] **Step 5: Run the full test suite to verify nothing regressed**

Run: `go build ./... && go test ./... -v`
Expected: PASS (including `TestResolveIntegration_CreatesAndReturnsConfig` and all existing tests). If the build complains about an unused variable, ensure the replacement above was applied verbatim (no leftover `integ`/`clientID` references remain).

- [ ] **Step 6: Commit**

```bash
git add main.go main_test.go
git commit -m "refactor: extract resolveIntegration shared by setup

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Add `deleteEntity`

**Files:**
- Modify: `main.go` (add `deleteEntity` near the other entity helpers, e.g. after `fetchEntityByID` ~line 1938)
- Test: `main_test.go`

- [ ] **Step 1: Add the failing tests**

Add to `main_test.go`:

```go
func TestDeleteEntity_SendsDeleteWithOrgHeader(t *testing.T) {
	var gotMethod, gotPath, gotOrg, gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotOrg = r.Header.Get("X-ORG-ID")
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	useHTTPClient(t, server.Client())

	if err := deleteEntity(server.URL, "old-org", "user-token", "ent-123"); err != nil {
		t.Fatalf("deleteEntity: %v", err)
	}
	if gotMethod != "DELETE" {
		t.Errorf("method = %q, want DELETE", gotMethod)
	}
	if gotPath != "/v3/entities/ent-123" {
		t.Errorf("path = %q, want /v3/entities/ent-123", gotPath)
	}
	if gotOrg != "old-org" {
		t.Errorf("X-ORG-ID = %q, want old-org", gotOrg)
	}
	if gotAuth != "Bearer user-token" {
		t.Errorf("Authorization = %q, want Bearer user-token", gotAuth)
	}
}

func TestDeleteEntity_ReturnsErrorOnFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	}))
	defer server.Close()
	useHTTPClient(t, server.Client())

	if err := deleteEntity(server.URL, "old-org", "user-token", "ent-123"); err == nil {
		t.Fatal("expected error on 403, got nil")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./... -run TestDeleteEntity -v`
Expected: FAIL — `undefined: deleteEntity`.

- [ ] **Step 3: Add `deleteEntity`**

In `main.go`, after `fetchEntityByID`, add:

```go
// deleteEntity removes an entity from the given organization. Used by switch-org
// to clean up the terminal entity left behind in the previous org. The caller's
// token must be authorized for orgID (a user token works across orgs via the
// X-ORG-ID header). Assumes DELETE /v3/entities/{id}; adjust if the platform
// uses a different deletion route/semantics.
func deleteEntity(apiURL, orgID, token, entityID string) error {
	headers := map[string]string{"Authorization": "Bearer " + token, "X-ORG-ID": orgID}
	_, err := makeRequest("DELETE", fmt.Sprintf("%s/v3/entities/%s", apiURL, url.PathEscape(entityID)), nil, headers)
	return err
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run TestDeleteEntity -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add main.go main_test.go
git commit -m "feat: add deleteEntity for old-org terminal cleanup

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Add `switchContext` and `loadCurrentContext`

**Files:**
- Modify: `main.go` (add the type + function near `interactiveSetup`, e.g. just before `func switchOrg` will live; place after `interactiveSetup`)
- Test: `main_test.go`

- [ ] **Step 1: Add the failing tests**

Add to `main_test.go`:

```go
func TestLoadCurrentContext_ReadsConfigAndEntity(t *testing.T) {
	saveAndRestoreStorageGlobals(t)
	dir := t.TempDir()
	ConfigFile = filepath.Join(dir, "oauth_config.json")
	TerminalEntityFile = filepath.Join(dir, "terminal_entity.json")

	cfg := AppConfig{
		OrganizationID:   "org-old",
		OrganizationName: "OldOrg",
		LegionBaseURL:    "https://legion.example.com",
		Manifest:         Manifest{Name: "DEV", Version: "1.0.0"},
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	writeFile(t, ConfigFile, data)

	entity := map[string]interface{}{
		"id": "ent-old",
		"metadata": map[string]interface{}{
			"serial_number": "sn-1",
			"terminal_type": "lander",
		},
	}
	edata, _ := json.MarshalIndent(entity, "", "  ")
	writeFile(t, TerminalEntityFile, edata)

	ctx, err := loadCurrentContext()
	if err != nil {
		t.Fatalf("loadCurrentContext: %v", err)
	}
	if ctx.OrgID != "org-old" {
		t.Errorf("OrgID = %q", ctx.OrgID)
	}
	if ctx.OrgName != "OldOrg" {
		t.Errorf("OrgName = %q", ctx.OrgName)
	}
	if ctx.APIURL != "https://legion.example.com" {
		t.Errorf("APIURL = %q", ctx.APIURL)
	}
	if ctx.EntityID != "ent-old" {
		t.Errorf("EntityID = %q", ctx.EntityID)
	}
	if ctx.Serial != "sn-1" {
		t.Errorf("Serial = %q", ctx.Serial)
	}
	if ctx.Type != "lander" {
		t.Errorf("Type = %q", ctx.Type)
	}
	if ctx.Manifest.Name != "DEV" {
		t.Errorf("Manifest.Name = %q", ctx.Manifest.Name)
	}
}

func TestLoadCurrentContext_MissingConfigErrors(t *testing.T) {
	saveAndRestoreStorageGlobals(t)
	dir := t.TempDir()
	ConfigFile = filepath.Join(dir, "does-not-exist.json")
	TerminalEntityFile = filepath.Join(dir, "terminal_entity.json")

	if _, err := loadCurrentContext(); err == nil {
		t.Fatal("expected error when config missing")
	}
}

func TestLoadCurrentContext_NoEntityFileStillOK(t *testing.T) {
	saveAndRestoreStorageGlobals(t)
	dir := t.TempDir()
	ConfigFile = filepath.Join(dir, "oauth_config.json")
	TerminalEntityFile = filepath.Join(dir, "terminal_entity.json")

	cfg := AppConfig{OrganizationID: "org-old", LegionBaseURL: "https://x"}
	data, _ := json.Marshal(cfg)
	writeFile(t, ConfigFile, data)

	ctx, err := loadCurrentContext()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.EntityID != "" {
		t.Errorf("EntityID = %q, want empty", ctx.EntityID)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./... -run TestLoadCurrentContext -v`
Expected: FAIL — `undefined: loadCurrentContext`.

- [ ] **Step 3: Add `switchContext` and `loadCurrentContext`**

In `main.go`, after the `interactiveSetup` function, add:

```go
// switchContext captures the device's current org/integration/terminal identity,
// read before switch-org overwrites the stored config. It supplies the old-org
// IDs needed for cleanup and the serial/type reused for the new-org terminal.
type switchContext struct {
	OrgID    string
	OrgName  string
	APIURL   string
	Manifest Manifest
	EntityID string
	Serial   string
	Type     string
}

// loadCurrentContext reads the existing oauth_config.json (required) and
// terminal_entity.json (optional) into a switchContext. It returns an error if
// no configuration exists, meaning setup has not been run yet.
func loadCurrentContext() (*switchContext, error) {
	// #nosec G304 -- ConfigFile is initialized from the controlled storage path during setupStorage.
	content, err := os.ReadFile(ConfigFile)
	if err != nil {
		return nil, fmt.Errorf("no existing configuration found at %s (run 'legion-auth setup' first): %w", ConfigFile, err)
	}
	var config AppConfig
	if err := json.Unmarshal(content, &config); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", ConfigFile, err)
	}

	ctx := &switchContext{
		OrgID:    config.OrganizationID,
		OrgName:  config.OrganizationName,
		APIURL:   config.LegionBaseURL,
		Manifest: config.Manifest,
	}

	if entity, err := loadCachedTerminalEntity(); err == nil {
		ctx.EntityID = entityIDFromMap(entity)
		ctx.Serial = entitySerialNumberFromMap(entity)
		if meta, ok := entity["metadata"].(map[string]interface{}); ok {
			if t, ok := meta["terminal_type"].(string); ok {
				ctx.Type = t
			}
		}
	}

	return ctx, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run TestLoadCurrentContext -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add main.go main_test.go
git commit -m "feat: add loadCurrentContext for switch-org

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Implement the `switchOrg` orchestrator

**Files:**
- Modify: `main.go` (add `switchOrg` after `loadCurrentContext`)
- Test: `main_test.go`

- [ ] **Step 1: Add the failing tests**

These cover the pre-network logic (validation + same-org no-op), which is the deterministically testable part. Add to `main_test.go`:

```go
func TestSwitchOrg_NonInteractiveRequiresFlags(t *testing.T) {
	saveAndRestoreStorageGlobals(t)
	dir := t.TempDir()
	ConfigFile = filepath.Join(dir, "oauth_config.json")
	TerminalEntityFile = filepath.Join(dir, "terminal_entity.json")
	cfg := AppConfig{OrganizationID: "org-old", LegionBaseURL: "https://legion.example.com"}
	data, _ := json.Marshal(cfg)
	writeFile(t, ConfigFile, data)

	// Missing --password.
	err := switchOrg(setupOpts{NonInteractive: true, OrgID: "org-new", Username: "u"})
	if err == nil {
		t.Fatal("expected error for missing flags")
	}
	if !strings.Contains(err.Error(), "--password") {
		t.Errorf("error = %v, want it to mention --password", err)
	}
}

func TestSwitchOrg_SameOrgIsNoop(t *testing.T) {
	saveAndRestoreStorageGlobals(t)
	dir := t.TempDir()
	ConfigFile = filepath.Join(dir, "oauth_config.json")
	TerminalEntityFile = filepath.Join(dir, "terminal_entity.json")
	cfg := AppConfig{OrganizationID: "org-old", OrganizationName: "OldOrg", LegionBaseURL: "https://legion.example.com"}
	data, _ := json.Marshal(cfg)
	writeFile(t, ConfigFile, data)

	// Target equals current org → early no-op, no network, no error.
	err := switchOrg(setupOpts{NonInteractive: true, OrgID: "org-old", Username: "u", Password: "p"})
	if err != nil {
		t.Fatalf("expected no-op success, got %v", err)
	}
}

func TestSwitchOrg_MissingConfigErrors(t *testing.T) {
	saveAndRestoreStorageGlobals(t)
	dir := t.TempDir()
	ConfigFile = filepath.Join(dir, "missing.json")
	TerminalEntityFile = filepath.Join(dir, "terminal_entity.json")

	err := switchOrg(setupOpts{NonInteractive: true, OrgID: "org-new", Username: "u", Password: "p"})
	if err == nil {
		t.Fatal("expected error when no existing config")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./... -run TestSwitchOrg_ -v`
Expected: FAIL — `undefined: switchOrg`.

- [ ] **Step 3: Implement `switchOrg`**

In `main.go`, after `loadCurrentContext`, add:

```go
// switchOrg re-provisions the device into a new organization. It re-authenticates
// the user (org-agnostic token), provisions an integration + OAuth tokens in the
// target org, reuses the device's serial/type for the new-org terminal, and
// finally (best-effort) deletes the terminal left behind in the old org.
func switchOrg(opts setupOpts) error {
	ctx, err := loadCurrentContext()
	if err != nil {
		return err
	}

	// Non-interactive validation. --api-url is optional (defaults to stored value).
	if opts.NonInteractive {
		var missing []string
		if opts.OrgID == "" {
			missing = append(missing, "--org-id")
		}
		if opts.Username == "" {
			missing = append(missing, "--username")
		}
		if opts.Password == "" {
			missing = append(missing, "--password")
		}
		if len(missing) > 0 {
			return fmt.Errorf("--non-interactive requires flags: %s", strings.Join(missing, ", "))
		}
	}

	// Validate --entity-type early if provided.
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

	// Early no-op guard when the target org is specified up front.
	if opts.OrgID != "" && opts.OrgID == ctx.OrgID {
		printSuccess(fmt.Sprintf("Already configured for organization %s (%s). Nothing to do.", ctx.OrgName, ctx.OrgID))
		return nil
	}

	apiURL := opts.APIURL
	if apiURL == "" {
		apiURL = ctx.APIURL
	}
	if apiURL == "" {
		return fmt.Errorf("no Legion API URL available (pass --api-url)")
	}

	oauthCfg := getWellKnownConfig(apiURL, opts.NonInteractive)

	// Authenticate the user (token is org-agnostic; org is chosen per request).
	var username string
	if opts.Username != "" {
		username = opts.Username
	} else {
		printInfo("\nEnter Credentials")
		username = inputPrompt("Username: ")
	}

	var token string
	if opts.Username != "" && opts.Password != "" {
		token, err = authenticateUser(oauthCfg.TokenEndpoint, username, opts.Password)
		if err != nil {
			return fmt.Errorf("auth failed: %w", err)
		}
	} else {
		for {
			password := readPasswordSimple("Password: ")
			token, err = authenticateUser(oauthCfg.TokenEndpoint, username, password)
			if err == nil {
				break
			}
			printError(fmt.Sprintf("Auth failed: %v", err))
			printInfo("Please try again (Ctrl+C to abort)")
		}
	}
	printSuccess("Authenticated!")

	// Resolve the target organization.
	var newOrg Organization
	if opts.OrgID != "" {
		newOrg, err = getOrganization(apiURL, token, opts.OrgID)
		if err != nil {
			return fmt.Errorf("failed to fetch organization %q: %w", opts.OrgID, err)
		}
		printSuccess(fmt.Sprintf("Switching to organization: %s (%s)", newOrg.OrganizationName, newOrg.OrganizationID))
	} else {
		newOrg, err = selectOrganization(apiURL, token)
		if err != nil {
			return err
		}
	}

	if newOrg.OrganizationID == ctx.OrgID {
		printSuccess(fmt.Sprintf("Already configured for organization %s (%s). Nothing to do.", ctx.OrgName, ctx.OrgID))
		return nil
	}

	// Provision the integration in the new org, reusing the existing manifest.
	manifest := ctx.Manifest
	if manifest.Name == "" {
		manifest = createManifestInteractively(opts)
	}

	printInfo("\nProvisioning integration in new organization...")
	cfg, err := resolveIntegration(apiURL, token, newOrg, manifest, opts.NonInteractive)
	if err != nil {
		return err
	}
	config := *cfg

	if err := saveJSON(ConfigFile, config); err != nil {
		return fmt.Errorf("critical: failed to save configuration: %w", err)
	}

	// Seed the access token file with the user token for the headless OAuth flow.
	if err := saveJSON(AccessTokenFile, StoredToken{
		AccessToken:    token,
		ExpiresAt:      time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		OrganizationID: newOrg.OrganizationID,
	}); err != nil {
		return fmt.Errorf("failed to save access token: %w", err)
	}

	if performHeadlessOAuthFlow(config, token) {
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

	// Provision the terminal in the new org, reusing the device's identity.
	if opts.EntityName == "" {
		opts.EntityName = ctx.Serial
	}
	if opts.EntityType == "" {
		opts.EntityType = ctx.Type
	}
	// Clear the cached entity so createTerminalEntity resolves freshly by serial
	// number within the new org (reuse if present, create if absent).
	_ = os.Remove(TerminalEntityFile)

	entityToken := config.AccessToken
	if entityToken == "" {
		entityToken = token
		printWarning("Headless OAuth token unavailable; using initial user token for entity creation.")
	}
	createTerminalEntity(apiURL, newOrg.OrganizationID, config.IntegrationID, entityToken, opts)

	// Old-org cleanup, performed last and best-effort so a failure never leaves
	// the device stranded between orgs.
	if ctx.EntityID != "" && ctx.OrgID != "" && ctx.OrgID != newOrg.OrganizationID {
		removeOld := opts.RemoveOld
		if !opts.NonInteractive {
			choice := strings.ToLower(strings.TrimSpace(inputPrompt(fmt.Sprintf(
				"Delete the terminal entity from the previous org %s? (y/N): ", ctx.OrgName))))
			removeOld = choice == "y" || choice == "yes"
		}
		if removeOld {
			printInfo(fmt.Sprintf("Removing terminal entity %s from previous org %s...", ctx.EntityID, ctx.OrgName))
			if err := deleteEntity(apiURL, ctx.OrgID, token, ctx.EntityID); err != nil {
				printWarning(fmt.Sprintf("Failed to delete old terminal entity (continuing): %v", err))
			} else {
				printSuccess("Removed terminal entity from previous org.")
			}
		} else {
			printInfo("Leaving the previous org's terminal entity in place.")
		}
	}

	printSuccess(fmt.Sprintf("Switched to organization %s (%s).", newOrg.OrganizationName, newOrg.OrganizationID))
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run TestSwitchOrg_ -v`
Expected: PASS (all three).

- [ ] **Step 5: Commit**

```bash
git add main.go main_test.go
git commit -m "feat: implement switchOrg orchestrator

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Wire `switch-org` into the command dispatch + usage

**Files:**
- Modify: `main.go` (`main` function: flag set registration ~line 2240; `flag.Usage` ~line 2251; the `switch os.Args[1]` block ~line 2295)

- [ ] **Step 1: Register the switch-org flag set**

In `main`, after the `installCmd`/`uninstallCmd` flag-set declarations (just before `storagePathFlag := flag.String(...)`), add:

```go
	switchCmd := flag.NewFlagSet("switch-org", flag.ExitOnError)
	switchFlags := registerSwitchOrgFlags(switchCmd)
```

- [ ] **Step 2: Add the dispatch case**

In the `switch os.Args[1]` block, after the `case "setup":` block (just before `case "install-service":`), add:

```go
		case "switch-org":

			if err := switchCmd.Parse(os.Args[2:]); err != nil {
				printError(fmt.Sprintf("Failed to parse switch-org flags: %v", err))
				os.Exit(1)
			}
			applySetupEnvDefaults(switchFlags)

			if err := setupStorage(switchFlags.StoragePath); err != nil {
				printError(fmt.Sprintf("Storage setup failed: %v", err))
				os.Exit(1)
			}

			if err := switchOrg(switchFlags.Opts); err != nil {
				printError(err.Error())
				os.Exit(1)
			}

			return
```

- [ ] **Step 3: Add usage text**

In `flag.Usage`, after the `setup` command's flag lines (just before the `fmt.Fprintln(os.Stderr, "")` that precedes `install-service`), add:

```go
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  switch-org")
		fmt.Fprintln(os.Stderr, "        Switch the device to a different organization")
		fmt.Fprintln(os.Stderr, "        Flags:")
		fmt.Fprintln(os.Stderr, "          --org-id         Target organization ID (skips org selector)")
		fmt.Fprintln(os.Stderr, "          --username       Username for authentication")
		fmt.Fprintln(os.Stderr, "          --password       Password for authentication")
		fmt.Fprintln(os.Stderr, "          --api-url        Legion API URL (default: stored value)")
		fmt.Fprintln(os.Stderr, "          --entity-name    Terminal serial number (default: reuse current)")
		fmt.Fprintln(os.Stderr, "          --entity-type    Terminal type: lander/helios/portal/dev-unit (default: reuse current)")
		fmt.Fprintln(os.Stderr, "          --remove-old     Delete the terminal entity from the previous org")
		fmt.Fprintln(os.Stderr, "          --storage-path   Custom storage path")
		fmt.Fprintln(os.Stderr, "          --non-interactive Run without prompts, use flags")
```

- [ ] **Step 4: Build and verify the command is wired**

Run: `go build -o legion-auth main.go && ./legion-auth 2>&1 | grep -A1 switch-org`
Expected: usage output includes the `switch-org` command line.

Run: `go test ./... ` 
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add main.go
git commit -m "feat: wire switch-org command into CLI dispatch

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Fix the storage directory permission regression

**Files:**
- Modify: `main.go` (`setupStorage` ~lines 519-523, immediately after `os.MkdirAll`)
- Test: `main_test.go`

- [ ] **Step 1: Add the failing test**

Add `"syscall"` to the `main_test.go` import block, then add:

```go
func TestSetupStorage_DirPermissionsUnderRestrictiveUmask(t *testing.T) {
	saveAndRestoreStorageGlobals(t)

	// Simulate a device whose umask would otherwise strip group/other bits.
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)

	dir := t.TempDir()
	custom := filepath.Join(dir, "picogrid", "auth")

	if err := setupStorage(custom); err != nil {
		t.Fatalf("setupStorage failed: %v", err)
	}

	info, err := os.Stat(custom)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Errorf("storage dir perm = %o, want 0750 (group must be able to traverse)", info.Mode().Perm())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestSetupStorage_DirPermissionsUnderRestrictiveUmask -v`
Expected: FAIL — `storage dir perm = 700, want 0750` (the dir is left at the umask-restricted mode).

- [ ] **Step 3: Add the unconditional chmod in `setupStorage`**

In `main.go`, in `setupStorage`, the current block is:

```go
	// Create directory
	if err := os.MkdirAll(StoragePath, 0755); err != nil {
		return fmt.Errorf("failed to create storage path %s: %w", StoragePath, err)
	}

	setOwnership(StoragePath)
```

Replace it with:

```go
	// Create directory
	if err := os.MkdirAll(StoragePath, 0755); err != nil {
		return fmt.Errorf("failed to create storage path %s: %w", StoragePath, err)
	}

	// Ensure the directory is traversable by the service group regardless of the
	// process umask or whether the pg user exists. setOwnership early-returns
	// before its own chmod when pg is absent or chown fails, which previously left
	// the directory at a restrictive umask mode (e.g. 0700) and broke token reads
	// by the daemon after re-running setup.
	// #nosec G302 -- directory needs the execute bit for the service user/group to traverse.
	if err := os.Chmod(StoragePath, 0750); err != nil {
		logger.Warn("failed to chmod storage path", slog.String("path", StoragePath), slog.String("error", err.Error()))
	}
	if os.Geteuid() == 0 {
		parent := filepath.Dir(StoragePath)
		// #nosec G302 -- parent directory needs the execute bit for traversal to the storage path.
		if err := os.Chmod(parent, 0755); err != nil {
			logger.Warn("failed to chmod parent of storage path", slog.String("path", parent), slog.String("error", err.Error()))
		}
	}

	setOwnership(StoragePath)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./... -run TestSetupStorage_DirPermissionsUnderRestrictiveUmask -v`
Expected: PASS

- [ ] **Step 5: Run the full suite (existing setupStorage tests must still pass)**

Run: `go test ./... -run TestSetupStorage -v`
Expected: PASS (`CustomPath`, `CreatesDirectory`, and the new umask test).

- [ ] **Step 6: Commit**

```bash
git add main.go main_test.go
git commit -m "fix: enforce traversable storage dir mode regardless of umask

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Document the command and run final checks

**Files:**
- Modify: `README.md` (after the "Initial Setup" section ~line 82)

- [ ] **Step 1: Add a Switch Organization section to the README**

In `README.md`, after the `### 1. Initial Setup` section and before `### 2. Install as a Service (Recommended)`, insert (and renumber the subsequent headings if you wish, or leave as-is):

````markdown
### Switching Organizations

To move a device to a different organization, re-authenticate and re-provision in
the target org:

```bash
legion-auth switch-org
```

This re-authenticates you, creates (or reuses) an integration in the target org,
re-runs the OAuth flow, and provisions the device's terminal entity in the new
org — reusing the existing terminal (matched by serial number) when it already
exists there. You will be prompted whether to delete the terminal entity from the
previous org.

**Options:**
- `--org-id <id>`: Target organization (skips the selector)
- `--api-url <url>`: Legion API URL (defaults to the stored value)
- `--entity-name` / `--entity-type`: Override the reused terminal serial/type
- `--remove-old`: Delete the previous org's terminal entity (non-interactive)
- `--non-interactive`: Run unattended (requires `--org-id`, `--username`, `--password`)

**Example (unattended fleet switch):**
```bash
legion-auth switch-org --non-interactive \
  --org-id org-123 --username svc --password "$PG_PASS" --remove-old
```
````

- [ ] **Step 2: Run the full quality suite**

Run: `go build ./... && go vet ./... && go test ./... -race`
Expected: build succeeds, vet clean, all tests PASS.

Optionally, if the tools are installed: `make check` (runs fmt, vet, lint, security, test). The `#nosec G302` annotations added in Task 7 keep gosec clean.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document switch-org command

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:**
- §1 dedicated subcommand + flags + env parity + precondition + non-interactive validation → Tasks 1, 5, 6 ✓
- §2 flow (capture old context → guard → auth → resolve org → provision integration → OAuth → terminal reuse-by-serial → old-org cleanup last, warn-and-continue) → Task 5 ✓
- §3 `deleteEntity`, `loadCurrentContext`, `switchOrg`, plus `resolveIntegration` extraction (DRY) → Tasks 2, 3, 4, 5 ✓
- §4 permission fix (unconditional `chmod 0750` on storage dir, parent traversal when root) → Task 7 ✓
- §5 testing (flag/env parsing, no-op guard, old-context capture, deleteEntity shape + failure, perm under restrictive umask) → Tasks 1, 3, 4, 5, 7 ✓
- Delete endpoint assumption (`DELETE /v3/entities/{id}`) flagged as revisable → Task 3 ✓

**Placeholder scan:** No TBD/TODO; every code step contains complete code.

**Type consistency:** `setupOpts.RemoveOld`, `switchContext{OrgID,OrgName,APIURL,Manifest,EntityID,Serial,Type}`, `resolveIntegration(apiURL, token string, org Organization, manifest Manifest, nonInteractive bool) (*AppConfig, error)`, `deleteEntity(apiURL, orgID, token, entityID string) error`, and `switchOrg(opts setupOpts) error` are used consistently across all tasks. The `interactiveSetup` refactor dereferences the `*AppConfig` (`config := *cfg`) so the rest of the function continues to use a value `config` exactly as before.

**Note on terminal reuse:** `switchOrg` removes the stale `terminal_entity.json` before calling `createTerminalEntity`, so the existing serial-number resolution path (`resolveEntityBySerialNumber`) handles "terminal already exists in new org → reuse" cleanly without the misleading "cached entity no longer exists" prompt.
