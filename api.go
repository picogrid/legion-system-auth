package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultAdminBindAddr   = "127.0.0.1:8100"
	maxJSONBodyBytes       = 1 << 20
	adminReadHeaderTimeout = 5 * time.Second
)

type AdminAPI struct {
	mu            sync.Mutex
	configureMu   sync.Mutex
	bindAddr      string
	server        *http.Server
	monitorCancel context.CancelFunc
	monitorDone   chan struct{}
}

type configureRequest struct {
	APIURL          string `json:"api_url"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	OrgID           string `json:"org_id"`
	IntegrationName string `json:"integration_name"`
	AccessLevel     string `json:"access_level"`
	CreateEntity    bool   `json:"create_entity"`
	EntityName      string `json:"entity_name"`
	EntityType      string `json:"entity_type"`
}

type configuredState struct {
	Config         AppConfig
	AccessToken    StoredToken
	RefreshToken   *StoredToken
	TerminalEntity map[string]interface{}
}

func NewAdminAPI(bindAddr string) *AdminAPI {
	if bindAddr == "" {
		bindAddr = defaultAdminBindAddr
	}

	api := &AdminAPI{bindAddr: bindAddr}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/configure", api.handleConfigure)

	api.server = &http.Server{
		Addr:              bindAddr,
		Handler:           mux,
		ReadHeaderTimeout: adminReadHeaderTimeout,
	}

	return api
}

func (a *AdminAPI) ListenAndServe() error {
	logger.Info("admin api listening", slog.String("bind_addr", a.bindAddr))
	return a.server.ListenAndServe()
}

func (a *AdminAPI) StartMonitoring() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.startMonitoringLocked()
}

func (a *AdminAPI) Shutdown(ctx context.Context) error {
	a.mu.Lock()
	server := a.server
	cancel, done := a.takeMonitorLocked()
	a.mu.Unlock()

	stopMonitor(cancel, done)
	if server == nil {
		return nil
	}
	return server.Shutdown(ctx)
}

func (a *AdminAPI) startMonitoringLocked() {
	if a.monitorCancel != nil || !configExists() {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	a.monitorCancel = cancel
	a.monitorDone = done

	go func() {
		defer close(done)
		runTokenMonitoring(ctx)
	}()
}

func (a *AdminAPI) takeMonitorLocked() (context.CancelFunc, chan struct{}) {
	cancel := a.monitorCancel
	done := a.monitorDone
	a.monitorCancel = nil
	a.monitorDone = nil
	return cancel, done
}

func (a *AdminAPI) handleConfigure(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	var req configureRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeAPIError(w, http.StatusUnprocessableEntity, "invalid_request", err.Error())
		return
	}

	if err := validateConfigureRequest(req); err != nil {
		writeAPIError(w, http.StatusUnprocessableEntity, "invalid_request", err.Error())
		return
	}

	if !a.configureMu.TryLock() {
		writeAPIError(w, http.StatusConflict, "configure_in_progress", "another configure request is already running")
		return
	}
	defer a.configureMu.Unlock()

	apiURL := strings.TrimRight(req.APIURL, "/")

	oauthCfg, err := fetchWellKnownConfig(apiURL)
	if err != nil {
		writeAPIError(w, http.StatusBadGateway, "cannot_reach_auth_server", err.Error())
		return
	}

	userToken, err := authenticateUser(oauthCfg.TokenEndpoint, req.Username, req.Password)
	if err != nil {
		var httpErr *HTTPError
		if errors.As(err, &httpErr) && (httpErr.StatusCode == http.StatusUnauthorized || httpErr.StatusCode == http.StatusBadRequest) {
			writeAPIError(w, http.StatusUnauthorized, "auth_failed", "invalid credentials")
			return
		}
		writeAPIError(w, http.StatusBadGateway, "auth_failed", err.Error())
		return
	}

	orgs, err := getOrganizations(apiURL, userToken)
	if err != nil {
		writeAPIError(w, http.StatusBadGateway, "cannot_list_organizations", err.Error())
		return
	}

	org, ok := findOrgByID(orgs, req.OrgID)
	if !ok {
		writeAPIError(w, http.StatusForbidden, "org_access_denied", fmt.Sprintf("user cannot access organization %q", req.OrgID))
		return
	}

	opts := setupOpts{
		IntegrationName: req.IntegrationName,
		AccessLevel:     req.AccessLevel,
		EntityName:      req.EntityName,
		EntityType:      req.EntityType,
		CreateEntity:    req.CreateEntity,
		NonInteractive:  true,
	}

	manifest := defaultManifestFromOpts(opts)

	state, err := prepareConfiguredState(apiURL, userToken, org, manifest, opts, false)
	if err != nil {
		writeSetupError(w, err)
		return
	}

	a.mu.Lock()
	cancel, done := a.takeMonitorLocked()
	a.mu.Unlock()
	stopMonitor(cancel, done)

	if err := commitConfiguredState(state); err != nil {
		a.mu.Lock()
		a.startMonitoringLocked()
		a.mu.Unlock()
		writeAPIError(w, http.StatusInternalServerError, "commit_failed", err.Error())
		return
	}

	a.mu.Lock()
	a.startMonitoringLocked()
	a.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"configured":     true,
		"org_id":         state.Config.OrganizationID,
		"integration_id": state.Config.IntegrationID,
	})
}

func validateConfigureRequest(req configureRequest) error {
	switch {
	case req.APIURL == "":
		return errors.New("api_url is required")
	case req.Username == "" || req.Password == "":
		return errors.New("username and password are required")
	case req.OrgID == "":
		return errors.New("org_id is required")
	case req.CreateEntity && req.EntityName == "":
		return errors.New("entity_name is required when create_entity is true")
	case req.CreateEntity && req.EntityType == "":
		return errors.New("entity_type is required when create_entity is true")
	}
	opts := setupOpts{AccessLevel: req.AccessLevel, EntityType: req.EntityType}
	return validateSetupOptionValues(opts)
}

func defaultManifestFromOpts(opts setupOpts) Manifest {
	relation := firstNonEmpty(opts.AccessLevel, "operator")
	switch relation {
	case "viewer", "operator", "admin":
	default:
		relation = "operator"
	}
	redirect := firstNonEmpty(opts.RedirectURL, "http://localhost:8000/oauth_callback")
	redirect = ensureRedirectUriAvailable(redirect)
	return Manifest{
		Name:        firstNonEmpty(opts.IntegrationName, "Portal Integration"),
		Version:     firstNonEmpty(opts.Version, "1.0.0"),
		Description: firstNonEmpty(opts.Description, "OAuth integration for portal authentication"),
		OAuthConfig: ManifestOAuthConfig{
			Permissions:  getPermissionsForRelation(relation),
			RedirectURLs: []string{redirect},
		},
	}
}

func writeSetupError(w http.ResponseWriter, err error) {
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		switch httpErr.StatusCode {
		case http.StatusUnauthorized:
			writeAPIError(w, http.StatusUnauthorized, "upstream_unauthorized", httpErr.Error())
		case http.StatusForbidden:
			writeAPIError(w, http.StatusForbidden, "upstream_forbidden", httpErr.Error())
		case http.StatusConflict:
			writeAPIError(w, http.StatusConflict, "upstream_conflict", httpErr.Error())
		default:
			writeAPIError(w, http.StatusBadGateway, "upstream_error", httpErr.Error())
		}
		return
	}
	writeAPIError(w, http.StatusInternalServerError, "configure_failed", err.Error())
}

func stopMonitor(cancel context.CancelFunc, done chan struct{}) {
	if cancel == nil {
		return
	}
	cancel()
	<-done
}

func writeAPIError(w http.ResponseWriter, status int, code, detail string) {
	writeJSON(w, status, map[string]string{
		"error":  code,
		"detail": detail,
	})
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	body, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain a single JSON object")
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func configExists() bool {
	return fileExists(ConfigFile)
}

func loadAccessToken() (StoredToken, error) {
	// #nosec G304 -- AccessTokenFile is initialized from controlled storage path during setupStorage.
	content, err := os.ReadFile(AccessTokenFile)
	if err != nil {
		return StoredToken{}, err
	}

	var token StoredToken
	if err := json.Unmarshal(content, &token); err != nil {
		return StoredToken{}, err
	}
	return token, nil
}

func currentTokenStatus() (bool, string) {
	token, err := loadAccessToken()
	if err != nil || token.ExpiresAt == "" {
		return false, ""
	}

	expiresAt, err := time.Parse(time.RFC3339, token.ExpiresAt)
	if err != nil {
		return false, ""
	}
	return time.Until(expiresAt) > 0, expiresAt.Format(time.RFC3339)
}

func prepareConfiguredState(apiURL, userToken string, org Organization, manifest Manifest, opts setupOpts, verbose bool) (configuredState, error) {
	if verbose {
		printInfo("\nCreating integration...")
	}

	integ, err := createIntegration(apiURL, userToken, org.OrganizationID, manifest)
	if err != nil {
		var httpErr *HTTPError
		if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusConflict {
			if verbose && !opts.NonInteractive {
				printWarning("Integration exists.")
				integ = selectExistingIntegrationPaginated(apiURL, userToken, org.OrganizationID)
			} else {
				integ = findIntegrationByName(apiURL, userToken, org.OrganizationID, manifest.Name)
			}
		} else {
			return configuredState{}, fmt.Errorf("failed to create integration: %w", err)
		}
	}

	if integ == nil {
		return configuredState{}, errors.New("no integration selected")
	}

	clientID := ""
	clientSecret := ""
	if integ.OAuthConfig != nil {
		clientID = integ.OAuthConfig.ClientID
		clientSecret = integ.OAuthConfig.ClientSecret
	}

	if len(integ.Manifest) > 0 {
		var storedManifest Manifest
		if err := json.Unmarshal(integ.Manifest, &storedManifest); err == nil {
			manifest = storedManifest
		}
	}

	if clientID == "" {
		cfg, err := getIntegrationOAuthConfig(apiURL, userToken, org.OrganizationID, integ.ID)
		if err == nil {
			clientID = cfg.ClientID
			clientSecret = cfg.ClientSecret
		}
	}

	if clientID == "" {
		return configuredState{}, errors.New("integration oauth client_id is missing")
	}

	if clientSecret == "" || clientSecret == "[REDACTED]" {
		clientSecret, err = regenerateClientSecret(apiURL, userToken, org.OrganizationID, integ.ID)
		if err != nil {
			return configuredState{}, fmt.Errorf("failed to regenerate client secret: %w", err)
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

	integrationToken, err := performHeadlessOAuthFlow(config, userToken, verbose)
	if err != nil {
		return configuredState{}, err
	}

	config.AccessToken = integrationToken.AccessToken
	state := configuredState{
		Config:      config,
		AccessToken: *integrationToken,
	}

	if integrationToken.RefreshToken != "" {
		refreshToken := StoredToken{
			RefreshToken:   integrationToken.RefreshToken,
			OrganizationID: org.OrganizationID,
		}
		state.RefreshToken = &refreshToken
	}

	if opts.CreateEntity {
		createEntityToken := config.AccessToken
		if createEntityToken == "" {
			createEntityToken = userToken
		}

		entity, err := resolveOrCreateTerminalEntity(apiURL, config.OrganizationID, config.IntegrationID, createEntityToken, opts)
		if err != nil {
			return configuredState{}, err
		}
		state.TerminalEntity = entity
	}

	return state, nil
}

func resolveOrCreateTerminalEntity(apiURL, orgID, integID, token string, opts setupOpts) (map[string]interface{}, error) {
	cachedEntity, cacheErr := loadCachedTerminalEntity()
	if cacheErr == nil {
		cachedID := entityIDFromMap(cachedEntity)
		if cachedID == "" {
			if !confirmRecreateEntity("Cached terminal entity is missing an id.", opts.NonInteractive) {
				return nil, errors.New("terminal entity setup cancelled")
			}
		} else {
			resolved, fetchErr := fetchEntityByID(apiURL, orgID, token, cachedID)
			if fetchErr != nil {
				if errors.Is(fetchErr, errEntityNotFound) {
					if !confirmRecreateEntity("Cached terminal entity no longer exists on server.", opts.NonInteractive) {
						return nil, errors.New("terminal entity setup cancelled")
					}
				} else {
					return nil, fmt.Errorf("failed to validate cached terminal entity id %s: %w", cachedID, fetchErr)
				}
			} else {
				return resolved, nil
			}
		}
	}

	if !errors.Is(cacheErr, errEntityNotFound) {
		if !confirmRecreateEntity(fmt.Sprintf("Cached terminal entity is unreadable: %v", cacheErr), opts.NonInteractive) {
			return nil, errors.New("terminal entity setup cancelled")
		}
	}

	sn := opts.EntityName
	if sn == "" {
		if opts.NonInteractive {
			return nil, errors.New("--entity-name is required when using create_entity")
		}
		sn = inputPrompt("Terminal Serial Number: ")
		if sn == "" {
			return nil, errors.New("terminal serial number is required")
		}
	}

	tType := opts.EntityType
	if tType == "" {
		if opts.NonInteractive {
			return nil, errors.New("--entity-type is required when using create_entity")
		}
		fmt.Println("Available types:")
		for i, t := range validEntityTypes {
			fmt.Printf("  %d. %s\n", i+1, t)
		}
		typeChoice := inputPrompt(fmt.Sprintf("Select type (1-%d): ", len(validEntityTypes)))
		idx, err := strconv.Atoi(typeChoice)
		if err != nil || idx < 1 || idx > len(validEntityTypes) {
			return nil, fmt.Errorf("invalid terminal type selection %q", typeChoice)
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

	existing, _, resolveErr := resolveEntityBySerialNumber(apiURL, orgID, token, sn)
	if resolveErr == nil {
		return existing, nil
	}
	if !errors.Is(resolveErr, errEntityNotFound) {
		return nil, fmt.Errorf("failed to verify existing terminal entity: %w", resolveErr)
	}

	var resp map[string]interface{}
	err := makeRequestJSON("POST", fmt.Sprintf("%s/v3/entities", apiURL), payload, headers, &resp)
	if err == nil {
		return resp, nil
	}

	var httpErr *HTTPError
	if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusConflict {
		fetchedEntity, fetchErr := fetchEntityBySerialNumberWithRetry(apiURL, orgID, token, sn, 5, 200*time.Millisecond, true)
		if fetchErr != nil {
			if errors.Is(fetchErr, errEntityNotFound) {
				return nil, errors.New("entity create conflicted, but no terminal entity was found with this serial number")
			}
			return nil, fmt.Errorf("failed to resolve conflicting entity by serial number: %w", fetchErr)
		}
		return fetchedEntity, nil
	}

	return nil, fmt.Errorf("failed to create terminal entity: %w", err)
}

func commitConfiguredState(state configuredState) (err error) {
	type commitFile struct {
		data    any
		path    string
		temp    string
		remove  bool
		created bool
		backup  string
	}

	files := []commitFile{
		{path: ConfigFile, data: state.Config},
		{path: AccessTokenFile, data: state.AccessToken},
		{path: RefreshTokenFile, data: state.RefreshToken, remove: state.RefreshToken == nil},
		{path: TerminalEntityFile, data: state.TerminalEntity, remove: state.TerminalEntity == nil},
	}

	rollback := func() {
		for i := range files {
			if files[i].created && fileExists(files[i].path) {
				_ = os.Remove(files[i].path)
			}
			if files[i].backup != "" && fileExists(files[i].backup) {
				_ = os.Rename(files[i].backup, files[i].path)
			}
			if files[i].temp != "" && fileExists(files[i].temp) {
				_ = os.Remove(files[i].temp)
			}
		}
	}
	defer func() {
		if err != nil {
			rollback()
			return
		}
		for i := range files {
			if files[i].backup != "" {
				_ = os.Remove(files[i].backup)
			}
			if files[i].temp != "" && fileExists(files[i].temp) {
				_ = os.Remove(files[i].temp)
			}
		}
	}()

	for i := range files {
		if files[i].remove {
			continue
		}
		if files[i].temp, err = writeTempJSONFile(files[i].path, files[i].data); err != nil {
			return err
		}
	}

	for i := range files {
		if !fileExists(files[i].path) {
			continue
		}
		files[i].backup = fmt.Sprintf("%s.bak.%d", files[i].path, time.Now().UnixNano())
		if err = os.Rename(files[i].path, files[i].backup); err != nil {
			return fmt.Errorf("failed to back up %s: %w", files[i].path, err)
		}
	}

	for i := range files {
		if files[i].remove {
			continue
		}
		if err = os.Rename(files[i].temp, files[i].path); err != nil {
			return fmt.Errorf("failed to commit %s: %w", files[i].path, err)
		}
		files[i].created = true
		files[i].temp = ""
	}

	return nil
}

func writeTempJSONFile(path string, data interface{}) (string, error) {
	tempPath := filepath.Join(filepath.Dir(path), fmt.Sprintf(".%s.tmp.%d", filepath.Base(path), time.Now().UnixNano()))
	if err := saveJSON(tempPath, data); err != nil {
		return "", err
	}
	return tempPath, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
