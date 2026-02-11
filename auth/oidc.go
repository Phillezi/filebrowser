package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const MethodOIDCAuth settings.AuthMethod = "oidc"

type OIDCAuthConfig struct {
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURL  string `json:"redirect_url"`
}

type OIDCAuth struct {
	config   OIDCAuthConfig        `json:"-"`
	provider *oidc.Provider        `json:"-"`
	verifier *oidc.IDTokenVerifier `json:"-"`
	oauth2   *oauth2.Config        `json:"-"`
}

// Ensure OIDCAuth implements Auther
var _ Auther = &OIDCAuth{}

// NewOIDCAuthFromConfig creates runtime object from JSON-serializable config
func NewOIDCAuthFromConfig(cfg OIDCAuthConfig) (*OIDCAuth, error) {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to create provider: %w", err)
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})

	oauth2Config := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	return &OIDCAuth{
		config:   cfg,
		provider: provider,
		verifier: verifier,
		oauth2:   oauth2Config,
	}, nil
}

// MarshalJSON stores only the serializable config
func (oa *OIDCAuth) MarshalJSON() ([]byte, error) {
	return json.Marshal(oa.config)
}

// UnmarshalJSON reconstructs runtime objects from serialized config
func (oa *OIDCAuth) UnmarshalJSON(data []byte) error {
	var cfg OIDCAuthConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	newOA, err := NewOIDCAuthFromConfig(cfg)
	if err != nil {
		return err
	}
	*oa = *newOA
	return nil
}

func NewOIDCAuth(issuer, clientID, clientSecret, redirectURL string) (*OIDCAuth, error) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})

	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	return &OIDCAuth{
		config: OIDCAuthConfig{
			Issuer:       issuer,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
		},
		provider: provider,
		verifier: verifier,
		oauth2:   oauth2Config,
	}, nil
}

var _ Auther = &OIDCAuth{}

func (oa *OIDCAuth) Auth(r *http.Request, usr users.Store, stg *settings.Settings, srv *settings.Server) (*users.User, error) {
	ctx := r.Context()

	log.Println("oidc auth called")

	// 1. Check session cookie for token
	cookie, err := r.Cookie("oidc_token")
	if err != nil {
		log.Printf("no OIDC token: %s", err.Error())
		return nil, fmt.Errorf("no OIDC token: %w", errors.Join(err, os.ErrPermission))
	}

	rawIDToken := cookie.Value

	// 2. Verify ID token
	idToken, err := oa.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.Printf("invalid ID token: %s", err.Error())
		return nil, fmt.Errorf("invalid ID token: %w", errors.Join(err, os.ErrPermission))
	}

	// 3. Extract claims
	var claims struct {
		Sub          string  `json:"sub"`
		Name         *string `json:"name,omitempty"`
		PrefUsername *string `json:"preferred_username,omitempty"`
		Email        *string `json:"email,omitempty"`
	}
	if err := idToken.Claims(&claims); err != nil {
		log.Printf("cannot parse claims: %s", err.Error())
		return nil, fmt.Errorf("cannot parse claims: %w", err)
	}

	var username string
	if claims.PrefUsername != nil {
		username = *claims.PrefUsername
	} else if claims.Email != nil {
		username = *claims.Email
	} else {
		username = claims.Sub
	}

	sub := claims.Sub

	scopeSuffix := sub
	if stg.Auth.OIDC != nil && strings.TrimSpace(stg.Auth.OIDC.UserScope) != "" {
		renderedScope, err := RenderAndValidatePath(stg.Auth.OIDC.UserScope, map[string]any{
			"Sub": sub,
		})
		if err != nil {
			log.Printf("[ERR] could not render userscope string, falling back to using the sub as the userScope")
		} else {
			scopeSuffix = renderedScope
		}
	}

	scope := filepath.Join(srv.Root, scopeSuffix)

	// 4. Find or create user in File Browser DB
	u, err := usr.Get(scope, username)
	if err != nil {
		// user not found => create
		pwd, err := users.RandomPwd(stg.MinimumPasswordLength)
		if err != nil {
			return nil, err
		}
		password, err := users.ValidateAndHashPwd(pwd, stg.MinimumPasswordLength)
		if err != nil {
			return nil, err
		}
		u = &users.User{
			Username: username,
			Password: password,
			Scope:    scopeSuffix,
			// default permissions
			Perm: stg.Defaults.Perm,
		}
		if err := usr.Save(u); err != nil {
			return nil, fmt.Errorf("cannot create user: %w", err)
		}

		if _, err := stg.MakeUserDir(username, scopeSuffix, srv.Root); err != nil {
			return nil, err
		}
	}

	return u, nil
}

func (oa *OIDCAuth) LoginPage() bool {
	return true
}

func (oa *OIDCAuth) CallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Check for OIDC error
		if errStr := r.URL.Query().Get("error"); errStr != "" {
			desc := r.URL.Query().Get("error_description")
			http.Error(w, errStr+": "+desc, http.StatusUnauthorized)
			return
		}

		// Get authorization code
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			return
		}

		// Get PKCE verifier from cookie
		pkceCookie, err := r.Cookie("oidc_pkce")
		if err != nil {
			http.Error(w, "missing pkce verifier", http.StatusBadRequest)
			return
		}

		verifier := pkceCookie.Value

		// Exchange code for token with PKCE
		token, err := oa.oauth2.Exchange(
			ctx,
			code,
			oauth2.SetAuthURLParam("code_verifier", verifier),
		)
		if err != nil {
			http.Error(w, "token exchange failed: "+err.Error(), 500)
			return
		}

		// Clear PKCE cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "oidc_pkce",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

		// Extract ID token
		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "no id_token in response", 500)
			return
		}

		// Verify ID token
		idToken, err := oa.verifier.Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(w, "invalid id token: "+err.Error(), http.StatusUnauthorized)
			return
		}

		_ = idToken // TODO: extract sub, email, roles

		// Set session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "oidc_token",
			Value:    rawIDToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   false, // true in prod
			SameSite: http.SameSiteLaxMode,
			MaxAge:   3600,
		})

		http.Redirect(w, r, "/login?oidc=done", http.StatusFound)
	})
}

func (oa *OIDCAuth) LoginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state := generateState()

		verifier, challenge, err := generatePKCE()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "error generating PKCE, err: %s", err.Error())
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "oidc_pkce",
			Value:    verifier,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

		url := oa.oauth2.AuthCodeURL(state,
			oauth2.SetAuthURLParam("code_challenge", challenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)

		http.Redirect(w, r, url, http.StatusFound)
	})
}

func (oa *OIDCAuth) LogoutHandler(postLogoutRedirectURI string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read id_token before deleting
		var idToken string

		if cookie, err := r.Cookie("oidc_token"); err == nil {
			idToken = cookie.Value
		}

		// Clear local cookies
		clearCookie := func(name string) {
			http.SetCookie(w, &http.Cookie{
				Name:     name,
				Value:    "",
				Path:     "/",
				HttpOnly: true,
				MaxAge:   -1,
				SameSite: http.SameSiteLaxMode,
			})
		}

		clearCookie("oidc_token")
		clearCookie("oidc_pkce")

		// If no token => just redirect locally
		if idToken == "" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		logoutURL := oa.config.Issuer + "/protocol/openid-connect/logout"
		redirectURI := url.QueryEscape(postLogoutRedirectURI)

		u := fmt.Sprintf(
			"%s?client_id=%s&id_token_hint=%s&post_logout_redirect_uri=%s",
			logoutURL,
			url.QueryEscape(oa.config.ClientID),
			url.QueryEscape(idToken),
			redirectURI,
		)

		http.Redirect(w, r, u, http.StatusFound)
	})
}

func generateState() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func generatePKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)

	_, err = rand.Read(b)
	if err != nil {
		return "", "", err
	}

	verifier = base64.RawURLEncoding.EncodeToString(b)

	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])

	return verifier, challenge, nil
}

// RenderAndValidatePath renders a Go template and validates it as a safe filesystem path.
func RenderAndValidatePath(tmpl string, vars map[string]any) (string, error) {
	t, err := template.New("path").
		Option("missingkey=error").
		Parse(tmpl)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, vars); err != nil {
		return "", err
	}

	rendered := strings.TrimSpace(buf.String())

	if rendered == "" {
		return "", errors.New("rendered path is empty")
	}

	clean := filepath.Clean(rendered)

	if strings.Contains(clean, "..") {
		return "", errors.New("path traversal detected (.. not allowed)")
	}

	if filepath.IsAbs(clean) {
		return "", errors.New("absolute paths are not allowed")
	}

	if strings.ContainsAny(clean, `<>:"|?*`) {
		return "", errors.New("path contains invalid characters")
	}

	return clean, nil
}
