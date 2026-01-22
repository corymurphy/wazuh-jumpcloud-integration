package pkg

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	defaultBaseURL  = "https://console.jumpcloud.com"
	defaultTokenUrl = "https://admin-oauth.id.jumpcloud.com/oauth2/token"
)

// Valid JumpCloud service types are:
// all: Logs from all services.
// directory: Logs activity in the Admin Portal and User Portal, including admin changes in the directory and admin/user authentications to the Admin Portal and User Portal.
// ldap: Logs user authentications to LDAP, including LDAP Bind and Search event types.
// mdm: Logs MDM command results.
// password_manager: Logs activity related to JumpCloud password manager.
// radius: Logs user authentications to RADIUS, used for Wi-Fi and VPNs.
// software: Logs application activity when software is added, removed, or changed on a macOS, Windows, or Linux device. Events are logged based on changes to an application version during each device check-in.
// sso: Logs user authentications to SAML applications.
// systems: Logs user authentications to MacOS, Windows, and Linux systems, including agent-related events on lockout, password changes, and File Disk Encryption key updates.

// JumpCloudAPI can be used to interact with the JumpCloud API
type JumpCloudAPI struct {
	baseURL  string
	tokenURL string
	orgID    string

	apiKey string

	clientID         string
	clientSecret     string
	serviceAccount   bool
	accessToken      string
	accessTokenExpry int64

	client *http.Client
}

// NewJumpCloudAPIOptions are the options for creating a new JumpCloudAPI object
type NewJumpCloudAPIOptions struct {
	BaseURL  string
	TokenURL string

	OrgID string

	APIKey string

	ClientID     string
	ClientSecret string

	ServiceAccount bool
}

// NewJumpCloudAPI returns a new JumpCloudAPI object, if you do not provide a base URL, it will default to the JumpCloud API
func NewJumpCloudAPI(options NewJumpCloudAPIOptions) *JumpCloudAPI {
	a := JumpCloudAPI{
		apiKey:         options.APIKey,
		baseURL:        options.BaseURL,
		orgID:          options.OrgID,
		tokenURL:       options.TokenURL,
		clientID:       options.ClientID,
		clientSecret:   options.ClientSecret,
		serviceAccount: false,
		client:         &http.Client{Timeout: 15 * time.Second},
	}
	if options.BaseURL == "" {
		a.baseURL = defaultBaseURL
	}
	if options.TokenURL == "" {
		a.tokenURL = defaultTokenUrl
	}
	if a.clientID != "" && a.clientSecret != "" {
		a.serviceAccount = true
	}
	return &a
}

// GetEventsSinceTime returns all JumpCloud events since the given time
func (a *JumpCloudAPI) GetEventsSinceTime(startTime time.Time) (*JumpCloudEvents, error) {
	// JumpCloud API requires a time in RFC3339 format
	starterTime := startTime.Format(time.RFC3339)
	payload := strings.NewReader(fmt.Sprintf(`{"service": ["all"], "start_time": "%v", "limit": 10000}`, starterTime))

	req, err := a.CreateAuthenticatedRequest("POST", fmt.Sprintf("%s/insights/directory/v1/events", a.baseURL), payload)

	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Add("Content-Type", "application/json")
	if a.orgID != "" {
		req.Header.Add("x-org-id", a.orgID)
	}
	res, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %v", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v | %v | %v", res.Status, res.StatusCode, err)
	}
	// JumpCloud API returns a 200 even if there are no events
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("error response from JumpCloud: %v | %v | %v", res.Status, res.StatusCode, string(body))
	}
	events, err := decodeJumpCloudEvents(body)
	if err != nil {
		return nil, fmt.Errorf("error decoding JumpCloud response: %v", err)
	}
	return &events, nil
}

type JumpCloudEvents struct {
	LDAP      []JumpCloudLDAPEvent      `json:"ldap_events"`
	Systems   []JumpCloudSystemEvent    `json:"systems"`
	Directory []JumpCloudDirectoryEvent `json:"directory"`
	Radius    []JumpCloudRadiusEvent    `json:"radius"`
	SSO       []JumpCloudSSOEvent       `json:"sso"`
	Admin     []JumpCloudAdminEvent     `json:"admin"`
}

type BaseJumpCloudEvent struct {
	Service string `json:"service"`
}

type OAuth2TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}

func (c *JumpCloudAPI) CreateAuthenticatedRequest(method string, path string, body io.Reader) (*http.Request, error) {

	authReq, err := http.NewRequest(method, path, body)
	if !c.serviceAccount {
		authReq.Header.Set("x-api-key", c.apiKey)
		return authReq, nil
	}

	if c.accessToken != "" && c.accessTokenExpry+5 > time.Now().Unix() {
		authReq.Header.Set("Authorization", "Bearer "+c.accessToken)
		return authReq, nil
	}

	bearer := base64.StdEncoding.EncodeToString(
		[]byte(c.clientID + ":" + c.clientSecret),
	)

	data := url.Values{}
	data.Set("scope", "api")
	data.Set("grant_type", "client_credentials")

	req, err := http.NewRequest("POST", defaultTokenUrl, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Basic "+bearer)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API error: %s", resp.Status)
	}

	var response OAuth2TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	claims := &jwt.MapClaims{}
	parser := jwt.NewParser()

	_, _, err = parser.ParseUnverified(response.AccessToken, claims)
	if err != nil {
		return nil, fmt.Errorf("unable to decode jwt %w", err)
	}

	exp, ok := (*claims)["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("token does not contain exp")
	}

	expiry := time.Unix(int64(exp), 0)

	c.accessTokenExpry = expiry.Unix()
	c.accessToken = response.AccessToken

	authReq.Header.Set("Authorization", "Bearer "+response.AccessToken)

	return authReq, nil
}

// decodeJumpCloudEvents decodes the raw JumpCloud API response into a JumpCloudEvents object that contains events
// of the varying types
func decodeJumpCloudEvents(raw []byte) (JumpCloudEvents, error) {
	finished := JumpCloudEvents{}
	generic := []map[string]interface{}{}
	err := json.Unmarshal(raw, &generic)
	if err != nil {
		return JumpCloudEvents{}, err
	}
	var events []BaseJumpCloudEvent
	err = json.Unmarshal(raw, &events)
	for i, x := range events {
		fmt.Println(x.Service)
		switch x.Service {
		case "ldap":
			b, err := json.Marshal(generic[i])
			if err != nil {
				fmt.Printf("Error marshalling LDAP generic event - will continue: %v\n", err)
				continue
			}
			var e JumpCloudLDAPEvent
			err = json.Unmarshal(b, &e)
			if err != nil {
				fmt.Printf("Error unmarshalling LDAP detailed event - will continue: %v\n", err)
				continue
			}
			finished.LDAP = append(finished.LDAP, e)
		case "systems":
			b, err := json.Marshal(generic[i])
			if err != nil {
				fmt.Printf("Error marshalling Systems generic event - will continue: %v\n", err)
				continue
			}
			var e JumpCloudSystemEvent
			err = json.Unmarshal(b, &e)
			if err != nil {
				fmt.Printf("Error unmarshalling Systems detailed event - will continue: %v\n", err)
				continue
			}
			finished.Systems = append(finished.Systems, e)
		case "directory":
			b, err := json.Marshal(generic[i])
			if err != nil {
				fmt.Printf("Error marshalling Directory generic event - will continue: %v\n", err)
				continue
			}
			var e JumpCloudDirectoryEvent
			err = json.Unmarshal(b, &e)
			if err != nil {
				fmt.Printf("Error unmarshalling Directory detailed event - will continue: %v\n", err)
				continue
			}
			finished.Directory = append(finished.Directory, e)
		case "radius":
			b, err := json.Marshal(generic[i])
			if err != nil {
				fmt.Printf("Error marshalling Radius generic event - will continue: %v\n", err)
				continue
			}
			var e JumpCloudRadiusEvent
			err = json.Unmarshal(b, &e)
			if err != nil {
				fmt.Printf("Error unmarshalling Radius detailed event - will continue: %v\n", err)
				continue
			}
			finished.Radius = append(finished.Radius, e)
		case "sso":
			b, err := json.Marshal(generic[i])
			if err != nil {
				fmt.Printf("Error marshalling SSO generic event - will continue: %v\n", err)
				continue
			}
			var e JumpCloudSSOEvent
			err = json.Unmarshal(b, &e)
			if err != nil {
				fmt.Printf("Error unmarshalling SSO detailed event - will continue: %v\n", err)
				continue
			}
			finished.SSO = append(finished.SSO, e)
		case "admin":
			b, err := json.Marshal(generic[i])
			if err != nil {
				fmt.Printf("Error marshalling Admin generic event - will continue: %v\n", err)
				continue
			}
			var e JumpCloudAdminEvent
			err = json.Unmarshal(b, &e)
			if err != nil {
				fmt.Printf("Error unmarshalling Admin detailed event - will continue: %v\n", err)
				continue
			}
			finished.Admin = append(finished.Admin, e)

		}
	}
	return finished, nil
}
