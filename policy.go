package rbac

import (
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

var knownVerbs = map[string]struct{}{
	"list":   struct{}{},
	"get":    struct{}{},
	"create": struct{}{},
	"update": struct{}{},
	"patch":  struct{}{},
}

type Policy struct {
	Resources     []string
	ResourceNames []string
	Verbs         []string
}

type Policies []*Policy

func (this *Policy) AddResourceNames(names ...string) error {
	var invalid []string

	for _, name := range names {
		// Checking to make sure pattern given in 'name' is valid. Thus, the string
		// provided to match it against is useless.
		if _, err := filepath.Match(name, "useless"); err != nil {
			invalid = append(invalid, name)
			continue
		}

		this.ResourceNames = append(this.ResourceNames, name)
	}

	if len(invalid) != 0 {
		return errors.New("invalid name(s): " + strings.Join(invalid, ", "))
	}

	return nil
}

func (this *Policy) AddVerbs(verbs ...string) error {
	var unknown []string

	for _, verb := range verbs {
		if _, ok := knownVerbs[verb]; !ok {
			unknown = append(unknown, verb)
			continue
		}

		this.Verbs = append(this.Verbs, verbs...)
	}

	if len(unknown) != 0 {
		return errors.New("unknown verb(s): " + strings.Join(unknown, ", "))
	}

	return nil
}

func (this Policy) ResourceNameAllowed(name string) bool {
	for _, n := range this.ResourceNames {
		if n == "*" {
			return true
		}

		if matched, _ := filepath.Match(n, name); matched {
			return true
		}
	}

	return false
}

func (this Policy) VerbAllowed(verb string) bool {
	for _, v := range this.Verbs {
		if v == "*" || v == verb {
			return true
		}
	}

	return false
}

func (this Policies) AddResourceNames(names ...string) error {
	var invalid []string

	for _, policy := range this {
		if err := policy.AddResourceNames(names...); err != nil {
			invalid = append(invalid, err.Error())
		}
	}

	if len(invalid) != 0 {
		return errors.New(strings.Join(invalid, ", "))
	}

	return nil
}

func (this Policies) ResourceNameAllowed(name string) bool {
	for _, policy := range this {
		if policy.ResourceNameAllowed(name) {
			return true
		}
	}

	return false
}

func (this Policies) VerbAllowed(verb string) bool {
	for _, policy := range this {
		if policy.VerbAllowed(verb) {
			return true
		}
	}

	return false
}
