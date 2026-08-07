package caddyprotector

import (
	"fmt"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
)

func normalizeRuleValue(kind, raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("%s darf nicht leer sein", kind)
	}
	return strings.ToLower(value), nil
}

func (bb *CaddyProtector) compileRequestRules() error {
	pathRules := make([]compiledStringRule, 0, len(bb.DenyPathPrefixes))
	queryRules := make([]compiledStringRule, 0, len(bb.DenyQuerySubstrings))
	headerRules := make([]compiledHeaderRule, 0, len(bb.DenyHeaderSubstrings))

	for _, raw := range bb.DenyPathPrefixes {
		value, err := normalizeRuleValue("deny_path_prefix", raw)
		if err != nil {
			return err
		}
		pathRules = append(pathRules, compiledStringRule{Value: value, Source: configRuleSource})
	}
	for _, raw := range bb.DenyQuerySubstrings {
		value, err := normalizeRuleValue("deny_query_substring", raw)
		if err != nil {
			return err
		}
		queryRules = append(queryRules, compiledStringRule{Value: value, Source: configRuleSource})
	}
	for i, rule := range bb.DenyHeaderSubstrings {
		name := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(rule.Name))
		if name == "" {
			return fmt.Errorf("deny_header_substring header-name darf nicht leer sein")
		}
		needle, err := normalizeRuleValue("deny_header_substring", rule.Needle)
		if err != nil {
			return err
		}
		bb.DenyHeaderSubstrings[i] = HeaderSubstringRule{Name: name, Needle: strings.TrimSpace(rule.Needle)}
		headerRules = append(headerRules, compiledHeaderRule{Name: name, Needle: needle, Source: configRuleSource})
	}

	bb.compiledPathRules = pathRules
	bb.compiledQueryRules = queryRules
	bb.compiledHeaderRules = headerRules
	return nil
}

func (bb *CaddyProtector) matchRequestRules(r *http.Request) (requestRuleMatch, bool) {
	pathValue := r.URL.EscapedPath()
	if pathValue == "" {
		pathValue = r.URL.Path
	}
	pathValues := []string{strings.ToLower(pathValue)}
	if unescaped, err := url.PathUnescape(pathValue); err == nil && unescaped != pathValue {
		pathValues = append(pathValues, strings.ToLower(unescaped))
	}
	for _, rule := range bb.compiledPathRules {
		for _, value := range pathValues {
			if strings.HasPrefix(value, rule.Value) {
				return requestRuleMatch{Source: rule.Source, Type: "path_prefix"}, true
			}
		}
	}

	rawQuery := strings.ToLower(r.URL.RawQuery)
	decodedQuery := ""
	if r.URL.RawQuery != "" {
		if unescaped, err := url.QueryUnescape(r.URL.RawQuery); err == nil {
			decodedQuery = strings.ToLower(unescaped)
		}
	}
	for _, rule := range bb.compiledQueryRules {
		if strings.Contains(rawQuery, rule.Value) || (decodedQuery != "" && strings.Contains(decodedQuery, rule.Value)) {
			return requestRuleMatch{Source: rule.Source, Type: "query_substring"}, true
		}
	}

	for _, rule := range bb.compiledHeaderRules {
		for _, value := range r.Header.Values(rule.Name) {
			if strings.Contains(strings.ToLower(value), rule.Needle) {
				return requestRuleMatch{Source: rule.Source, Type: "header_substring", HeaderName: rule.Name}, true
			}
		}
	}

	return requestRuleMatch{}, false
}
