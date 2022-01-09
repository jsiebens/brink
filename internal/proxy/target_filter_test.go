package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidator(t *testing.T) {

	rule, err := parseTargetFilter("192.1.5.0/24:80,443,8000-8080")
	if err != nil {
		t.Fail()
		return
	}

	assert.True(t, rule.validate("192.1.5.4", 80))
	assert.True(t, rule.validate("192.1.5.4", 443))
	assert.True(t, rule.validate("192.1.5.4", 8001))
	assert.False(t, rule.validate("192.1.5.100", 22))
	assert.False(t, rule.validate("192.2.5.100", 80))
}

type validation struct {
	host           string
	port           uint64
	expectedResult bool
}

func TestParseRule(t *testing.T) {

	testCases := []struct {
		name        string
		rule        string
		valid       bool
		validations []validation
	}{
		{
			name:  "wildcards",
			rule:  "*:*",
			valid: true,
			validations: []validation{
				{host: "192.1.5.10", port: 80, expectedResult: true},
			},
		},
		{
			name:  "wildcard ports",
			rule:  "192.1.5.0/24:*",
			valid: true,
			validations: []validation{
				{host: "192.1.5.10", port: 80, expectedResult: true},
				{host: "192.1.5.10", port: 8080, expectedResult: true},
				{host: "192.1.6.10", port: 8080, expectedResult: false},
			},
		},
		{
			name:  "wildcard hosts",
			rule:  "*:80",
			valid: true,
			validations: []validation{
				{host: "192.1.5.10", port: 80, expectedResult: true},
				{host: "192.1.5.10", port: 8080, expectedResult: false},
				{host: "192.1.6.10", port: 80, expectedResult: true},
			},
		},
		{
			name:  "single ip",
			rule:  "192.1.5.10:80",
			valid: true,
			validations: []validation{
				{host: "192.1.5.10", port: 80, expectedResult: true},
			},
		},
		{
			name:  "single port",
			rule:  "192.1.5.0/24:80",
			valid: true,
			validations: []validation{
				{host: "192.1.5.10", port: 80, expectedResult: true},
				{host: "192.1.5.10", port: 22, expectedResult: false},
			},
		},
		{
			name:  "port range",
			rule:  "192.1.5.0/24:8000-8080",
			valid: true,
			validations: []validation{
				{host: "192.1.5.10", port: 8000, expectedResult: true},
				{host: "192.1.5.10", port: 8080, expectedResult: true},
				{host: "192.1.5.10", port: 8050, expectedResult: true},
				{host: "192.1.5.10", port: 7999, expectedResult: false},
				{host: "192.1.5.10", port: 8081, expectedResult: false},
			},
		},
		{
			name:  "single port and port ranges",
			rule:  "192.1.5.0/24:80,8000-8080,9000-9005,443",
			valid: true,
			validations: []validation{
				{host: "192.1.5.10", port: 80, expectedResult: true},
				{host: "192.1.5.10", port: 443, expectedResult: true},
				{host: "192.1.5.10", port: 8000, expectedResult: true},
				{host: "192.1.5.10", port: 8050, expectedResult: true},
				{host: "192.1.5.10", port: 8080, expectedResult: true},
				{host: "192.1.5.10", port: 9000, expectedResult: true},
				{host: "192.1.5.10", port: 9005, expectedResult: true},
				{host: "192.1.5.10", port: 7999, expectedResult: false},
				{host: "192.1.5.10", port: 8081, expectedResult: false},
			},
		},
		{
			name:  "lookup",
			rule:  "127.0.0.1:80",
			valid: true,
			validations: []validation{
				{host: "localhost", port: 80, expectedResult: true},
				{host: "unknown", port: 80, expectedResult: false},
			},
		},
		{
			name:  "lookup",
			rule:  "192.1.5.10:*",
			valid: true,
			validations: []validation{
				{host: "localhost", port: 80, expectedResult: false},
			},
		},
		{
			name:  "lookup",
			rule:  "localhost:*",
			valid: true,
			validations: []validation{
				{host: "localhost", port: 80, expectedResult: true},
				{host: "127.0.0.1", port: 80, expectedResult: true},
			},
		},
		{
			name:  "globs",
			rule:  "*.localtest.me:*",
			valid: true,
			validations: []validation{
				//{host: "localhost", port: 80, expectedResult: false},
				//{host: "127.0.0.1", port: 80, expectedResult: false},
				{host: "api.localtest.me", port: 80, expectedResult: true},
			},
		},
		{name: "invalid", rule: "192.1.5.10:", valid: false},
		{name: "invalid", rule: "192.1.5.10:az", valid: false},
		{name: "invalid", rule: "192.1.5.10:80-", valid: false},
		{name: "invalid", rule: "192.1.5.10:-80", valid: false},
		{name: "invalid", rule: "unknown:80", valid: false},
		{name: "invalid", rule: "", valid: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rule, err := parseTargetFilter(tc.rule)
			if err != nil && tc.valid {
				t.Fail()
				return
			}

			for _, v := range tc.validations {
				validate := rule.validate(v.host, v.port)
				assert.Equal(t, v.expectedResult, validate, tc.rule, v.host, v.port)
			}
		})
	}
}

func TestParseRuleLookup(t *testing.T) {
	rule, err := parseTargetFilter("127.0.0.1/32:0-60000")
	if err != nil {
		t.Fail()
		return
	}

	assert.True(t, rule.validate("localhost", 22))
}

func TestParseRuleLookupIP(t *testing.T) {
	rule, err := parseTargetFilter("127.0.0.1:0-60000")
	if err != nil {
		t.Fail()
		return
	}

	assert.True(t, rule.validate("localhost", 22))
}

func TestParseRuleLookupInvalid(t *testing.T) {
	rule, err := parseTargetFilter("192.1.5.4/32:0-60000")
	if err != nil {
		t.Fail()
		return
	}

	assert.False(t, rule.validate("localhost", 22))
}

func TestParseRuleWildcards(t *testing.T) {
	rule, err := parseTargetFilter("*:*")
	if err != nil {
		t.Fail()
		return
	}

	assert.True(t, rule.validate("localhost", 22))
	assert.True(t, rule.validate("192.1.5.4", 80))
}

func TestParseRuleWildcardHost(t *testing.T) {
	rule, err := parseTargetFilter("*:80")
	if err != nil {
		t.Fail()
		return
	}

	assert.False(t, rule.validate("localhost", 22))
	assert.True(t, rule.validate("192.1.5.4", 80))
}

func TestParseRuleWildcardPorts(t *testing.T) {
	rule, err := parseTargetFilter("127.0.0.1/32:*")
	if err != nil {
		t.Fail()
		return
	}

	assert.True(t, rule.validate("localhost", 22))
	assert.False(t, rule.validate("192.1.5.4", 80))
}
