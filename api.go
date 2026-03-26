package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultAdminBindAddr = "127.0.0.1:8100"
	adminTLSCertFileName = "admin_api.crt"
	adminTLSKeyFileName  = "admin_api.key"
	maxJSONBodyBytes     = 1 << 20
)

type AdminAPI struct {
	mu            sync.Mutex
	bindAddr      string
	legionAPIURL  string
	certPath      string
	keyPath       string
	server        *http.Server
	monitorCancel context.CancelFunc
	monitorDone   chan struct{}
	loginLimiter  *loginRateLimiter
}

type loginRequest struct {
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

type loginRateLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	limit   int
	window  time.Duration
	entries map[string][]time.Time
}

func newLoginRateLimiter(limit int, window time.Duration) *loginRateLimiter {
	return &loginRateLimiter{
		now:     time.Now,
		limit:   limit,
		window:  window,
		entries: make(map[string][]time.Time),
	}
}

func (l *loginRateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	cutoff := now.Add(-l.window)
	times := l.entries[key][:0]
	for _, ts := range l.entries[key] {
		if ts.After(cutoff) {
			times = append(times, ts)
		}
	}
	if len(times) == 0 {
		delete(l.entries, key)
	} else {
		l.entries[key] = times
	}
	if len(times) >= l.limit {
		return false
	}
	l.entries[key] = append(times, now)
	return true
}

func NewAdminAPI(bindAddr, legionAPIURL string) (*AdminAPI, error) {
	if bindAddr == "" {
		bindAddr = defaultAdminBindAddr
	}
	if err := validateAdminBindAddr(bindAddr); err != nil {
		return nil, err
	}

	certPath, keyPath, err := ensureAdminTLSFiles(bindAddr)
	if err != nil {
		return nil, err
	}

	api := &AdminAPI{
		bindAddr:     bindAddr,
		legionAPIURL: strings.TrimRight(legionAPIURL, "/"),
		certPath:     certPath,
		keyPath:      keyPath,
		loginLimiter: newLoginRateLimiter(5, time.Minute),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/status", api.handleStatus)
	mux.HandleFunc("/api/v1/login", api.handleLogin)
	mux.HandleFunc("/api/v1/logout", api.handleLogout)

	api.server = &http.Server{
		Addr:    bindAddr,
		Handler: mux,
	}

	return api, nil
}

func (a *AdminAPI) ListenAndServe() error {
	logger.Info("admin api listening",
		slog.String("bind_addr", a.bindAddr),
		slog.String("cert_path", a.certPath),
	)
	return a.server.ListenAndServeTLS(a.certPath, a.keyPath)
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

func (a *AdminAPI) currentLegionAPIURL() string {
	if cfg, err := loadAppConfig(); err == nil && cfg.LegionBaseURL != "" {
		return strings.TrimRight(cfg.LegionBaseURL, "/")
	}
	return a.legionAPIURL
}

func (a *AdminAPI) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	if !configExists() {
		writeJSON(w, http.StatusOK, map[string]bool{"configured": false})
		return
	}

	if _, err := loadAppConfig(); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "invalid_config", err.Error())
		return
	}

	tokenValid, tokenExpiresAt := currentTokenStatus()
	resp := map[string]interface{}{
		"configured":       true,
		"token_valid":      tokenValid,
		"token_expires_at": tokenExpiresAt,
	}
	if tokenExpiresAt == "" {
		delete(resp, "token_expires_at")
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *AdminAPI) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	apiURL := a.currentLegionAPIURL()
	if apiURL == "" {
		writeAPIError(w, http.StatusServiceUnavailable, "legion_api_url_not_configured", "daemon legion api url is not configured")
		return
	}

	clientIP := remoteIP(r.RemoteAddr)
	if !a.loginLimiter.allow(clientIP) {
		writeAPIError(w, http.StatusTooManyRequests, "rate_limited", "too many login attempts")
		return
	}

	var req loginRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeAPIError(w, http.StatusUnprocessableEntity, "invalid_request", err.Error())
		return
	}
	if req.Username == "" || req.Password == "" {
		writeAPIError(w, http.StatusUnprocessableEntity, "invalid_request", "username and password are required")
		return
	}

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

	if req.OrgID == "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{"orgs": orgs})
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
	if err := validateLoginRequest(opts); err != nil {
		writeAPIError(w, http.StatusUnprocessableEntity, "invalid_request", err.Error())
		return
	}

	org, ok := findOrgByID(orgs, req.OrgID)
	if !ok {
		writeAPIError(w, http.StatusForbidden, "org_access_denied", fmt.Sprintf("user cannot access organization %q", req.OrgID))
		return
	}

	// Hold the lock across the full login+configure flow so callers see at most one
	// in-flight configuration operation, including OAuth, entity creation, and monitor restarts.
	if !a.mu.TryLock() {
		writeAPIError(w, http.StatusConflict, "login_in_progress", "another login request is already configuring the device")
		return
	}
	defer a.mu.Unlock()

	state, err := prepareConfiguredState(apiURL, userToken, org, defaultManifestFromOpts(opts), opts, false)
	if err != nil {
		writeSetupError(w, err)
		return
	}

	stopMonitor(a.takeMonitorLocked())

	if err := commitConfiguredState(state); err != nil {
		a.startMonitoringLocked()
		writeAPIError(w, http.StatusInternalServerError, "commit_failed", err.Error())
		return
	}

	a.startMonitoringLocked()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":        true,
		"org_id":         state.Config.OrganizationID,
		"integration_id": state.Config.IntegrationID,
	})
}

func (a *AdminAPI) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	if !a.mu.TryLock() {
		writeAPIError(w, http.StatusConflict, "logout_in_progress", "another request is updating device auth state")
		return
	}
	defer a.mu.Unlock()

	stopMonitor(a.takeMonitorLocked())

	if err := clearConfiguredState(); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "logout_failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func validateLoginRequest(opts setupOpts) error {
	if err := validateSetupOptionValues(opts); err != nil {
		return err
	}
	if !opts.CreateEntity {
		return nil
	}
	if opts.EntityName == "" {
		return errors.New("entity_name is required when create_entity is true")
	}
	if opts.EntityType == "" {
		return errors.New("entity_type is required when create_entity is true")
	}
	return nil
}

func stopMonitor(cancel context.CancelFunc, done chan struct{}) {
	if cancel == nil {
		return
	}
	cancel()
	<-done
}

func writeSetupError(w http.ResponseWriter, err error) {
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		switch {
		case httpErr.StatusCode == http.StatusUnauthorized || httpErr.StatusCode == http.StatusForbidden:
			writeAPIError(w, http.StatusUnauthorized, "upstream_unauthorized", httpErr.Error())
		case httpErr.StatusCode == http.StatusConflict:
			writeAPIError(w, http.StatusConflict, "upstream_conflict", httpErr.Error())
		default:
			writeAPIError(w, http.StatusBadGateway, "upstream_error", httpErr.Error())
		}
		return
	}

	writeAPIError(w, http.StatusInternalServerError, "configure_failed", err.Error())
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
	if decoder.More() {
		return errors.New("request body must contain a single JSON object")
	}
	return nil
}

func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil || host == "" {
		return remoteAddr
	}
	return host
}

func validateAdminBindAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid admin bind address %q: %w", addr, err)
	}
	if host == "" {
		return errors.New("admin bind address must include a specific host")
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		return errors.New("admin bind address must not use a wildcard host")
	}
	if strings.EqualFold(host, "0.0.0.0") || host == "::" {
		return errors.New("admin bind address must not use a wildcard host")
	}
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 {
		return fmt.Errorf("invalid admin bind port %q", port)
	}
	return nil
}

func ensureAdminTLSFiles(bindAddr string) (string, string, error) {
	certPath := filepath.Join(StoragePath, adminTLSCertFileName)
	keyPath := filepath.Join(StoragePath, adminTLSKeyFileName)
	if fileExists(certPath) && fileExists(keyPath) {
		return certPath, keyPath, nil
	}

	host, _, err := net.SplitHostPort(bindAddr)
	if err != nil {
		return "", "", err
	}

	certPEM, keyPEM, err := generateSelfSignedCert(host)
	if err != nil {
		return "", "", err
	}
	if err := writeFileWithPermissions(certPath, certPEM, 0640); err != nil {
		return "", "", err
	}
	if err := writeFileWithPermissions(keyPath, keyPEM, 0600); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

func generateSelfSignedCert(host string) ([]byte, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now().Add(-time.Hour)
	notAfter := notBefore.Add(5 * 365 * 24 * time.Hour)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, host)
	}
	if host != "localhost" {
		template.DNSNames = append(template.DNSNames, "localhost")
		template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"))
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	return certPEM, keyPEM, nil
}

func writeFileWithPermissions(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("failed to write file %s: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("failed to set file permissions for %s: %w", path, err)
	}
	if fileGID >= 0 {
		if err := os.Chown(path, -1, fileGID); err != nil {
			return fmt.Errorf("failed to set group ownership on %s: %w", path, err)
		}
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

func clearConfiguredState() error {
	paths := []string{ConfigFile, AccessTokenFile, RefreshTokenFile, TerminalEntityFile}
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func loadAppConfig() (AppConfig, error) {
	content, err := os.ReadFile(ConfigFile)
	if err != nil {
		return AppConfig{}, err
	}

	var cfg AppConfig
	if err := json.Unmarshal(content, &cfg); err != nil {
		return AppConfig{}, err
	}
	return cfg, nil
}

func loadStoredToken(path string) (StoredToken, error) {
	content, err := os.ReadFile(path)
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
	token, err := loadStoredToken(AccessTokenFile)
	if err != nil || token.ExpiresAt == "" {
		return false, ""
	}

	expiresAt, err := time.Parse(time.RFC3339, token.ExpiresAt)
	if err != nil {
		return false, ""
	}
	return time.Until(expiresAt) > 0, expiresAt.Format(time.RFC3339)
}

func defaultManifestFromOpts(opts setupOpts) Manifest {
	name := opts.IntegrationName
	if name == "" {
		name = "Portal Integration"
	}

	description := opts.Description
	if description == "" {
		description = "OAuth integration for portal authentication"
	}

	version := opts.Version
	if version == "" {
		version = "1.0.0"
	}

	redirectURL := opts.RedirectURL
	if redirectURL == "" {
		redirectURL = "http://localhost:8000/oauth_callback"
	}
	redirectURL = ensureRedirectUriAvailable(redirectURL)

	relation := firstNonEmpty(opts.AccessLevel, "operator")
	switch relation {
	case "viewer", "operator", "admin":
	default:
		relation = "operator"
	}

	return Manifest{
		Name:        name,
		Version:     version,
		Description: description,
		OAuthConfig: ManifestOAuthConfig{
			Permissions:  getPermissionsForRelation(relation),
			RedirectURLs: []string{redirectURL},
		},
	}
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
		path    string
		temp    string
		remove  bool
		created bool
		backup  string
	}

	files := []commitFile{
		{path: ConfigFile},
		{path: AccessTokenFile},
		{path: RefreshTokenFile, remove: state.RefreshToken == nil},
		{path: TerminalEntityFile, remove: state.TerminalEntity == nil},
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

	if files[0].temp, err = writeTempJSONFile(ConfigFile, state.Config); err != nil {
		return err
	}
	if files[1].temp, err = writeTempJSONFile(AccessTokenFile, state.AccessToken); err != nil {
		return err
	}
	if state.RefreshToken != nil {
		if files[2].temp, err = writeTempJSONFile(RefreshTokenFile, *state.RefreshToken); err != nil {
			return err
		}
	}
	if state.TerminalEntity != nil {
		if files[3].temp, err = writeTempJSONFile(TerminalEntityFile, state.TerminalEntity); err != nil {
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
