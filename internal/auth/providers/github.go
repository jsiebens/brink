package providers

import (
	"context"
	"fmt"
	"github.com/google/go-github/v39/github"
	"github.com/jsiebens/brink/internal/config"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/oauth2"
	gh "golang.org/x/oauth2/github"
	"strconv"
)

func NewGitHubProvider(c *config.Provider) (AuthProvider, error) {
	defaultScopes := []string{"read:org"}
	return &GitHubProvider{
		clientID:     c.ClientID,
		clientSecret: c.ClientSecret,
		scopes:       append(defaultScopes, c.Scopes...),
	}, nil
}

type GitHubProvider struct {
	clientID     string
	clientSecret string
	scopes       []string
}

func (p *GitHubProvider) GetLoginURL(redirectURI, state string) string {
	oauth2Config := oauth2.Config{
		ClientID:     p.clientID,
		ClientSecret: p.clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     gh.Endpoint,
		Scopes:       p.scopes,
	}

	return oauth2Config.AuthCodeURL(state, oauth2.ApprovalForce)
}

func (p *GitHubProvider) Exchange(redirectURI, code string) (*Identity, error) {
	oauth2Config := oauth2.Config{
		ClientID:     p.clientID,
		ClientSecret: p.clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     gh.Endpoint,
		Scopes:       p.scopes,
	}

	ctx := context.Background()
	oauth2Token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	ts := oauth2.StaticTokenSource(oauth2Token)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	user, _, err := client.Users.Get(ctx, "")
	if err != nil {
		return nil, err
	}

	var raw = make(map[string]interface{})

	decoderConfig := &mapstructure.DecoderConfig{
		Result:  &raw,
		TagName: "json",
	}

	decoder, _ := mapstructure.NewDecoder(decoderConfig)
	if err := decoder.Decode(user); err != nil {
		return nil, err
	}

	orgs, err := p.getOrganizations(ctx, client)
	if err != nil {
		return nil, err
	}

	teams, err := p.getTeams(ctx, client)
	if err != nil {
		return nil, err
	}

	return &Identity{
		UserID:   strconv.FormatInt(*user.ID, 10),
		Username: *user.Login,
		Attr: map[string]interface{}{
			"provider":      "github",
			"user":          raw,
			"teams":         teams,
			"organizations": orgs,
		},
	}, nil
}

func (p *GitHubProvider) ExchangeIDToken(rawIdToken string) (*Identity, error) {
	return nil, fmt.Errorf("unsupported operation")
}

func (p *GitHubProvider) IsInteractive() bool {
	return true
}

func (p *GitHubProvider) getTeams(ctx context.Context, client *github.Client) ([]string, error) {
	var result []string
	var page = 0
	for {
		teams, response, err := client.Teams.ListUserTeams(ctx, &github.ListOptions{Page: page, PerPage: 100})
		if err != nil {
			return nil, err
		}
		for _, team := range teams {
			result = append(result, fmt.Sprintf("%s:%s", *team.Organization.Login, *team.Slug))
		}
		if response.NextPage == 0 {
			break
		} else {
			page = response.NextPage
		}
	}
	return result, nil
}

func (p *GitHubProvider) getOrganizations(ctx context.Context, client *github.Client) ([]string, error) {
	var result []string
	var page = 0
	for {
		organizations, response, err := client.Organizations.List(ctx, "", &github.ListOptions{Page: page, PerPage: 100})
		if err != nil {
			return nil, err
		}
		for _, org := range organizations {
			result = append(result, *org.Login)
		}
		if response.NextPage == 0 {
			break
		} else {
			page = response.NextPage
		}
	}
	return result, nil
}
