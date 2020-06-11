package rbac

import (
	"errors"
	"path/filepath"
	"strings"
)

type Role struct {
	Name           string              `json:"name"`
	Policies       Policies            `json:"policies"`
	MappedPolicies map[string]Policies `json:"mapped_policies,omitempty"`
	ResourceNames  []string            `json:"resource_names,omitempty"`
}

func NewRole(name string, policies ...*Policy) *Role {
	role := &Role{
		Name:           name,
		MappedPolicies: make(map[string]Policies),
	}

	role.AddPolicies(policies...)

	names := make(map[string]struct{})

	for _, p := range role.Policies {
		for _, n := range p.ResourceNames {
			names[n] = struct{}{}
		}
	}

	for n := range names {
		role.ResourceNames = append(role.ResourceNames, n)
	}

	return role
}

func (this *Role) AddPolicies(policies ...*Policy) error {
	this.Policies = append(this.Policies, policies...)

	var invalid []string

	for _, policy := range policies {
		for _, resource := range policy.Resources {
			// Checking to make sure pattern given in 'resource' is valid. Thus, the
			// string provided to match it against is useless.
			if _, err := filepath.Match(resource, "useless"); err != nil {
				invalid = append(invalid, resource)
				continue
			}

			mapped := this.MappedPolicies[resource]
			mapped = append(mapped, policy)
			this.MappedPolicies[resource] = mapped
		}
	}

	if len(invalid) != 0 {
		return errors.New("invalid resource(s): " + strings.Join(invalid, ", "))
	}

	return nil
}

func (this Role) PoliciesForResource(resource string) Policies {
	var policies Policies

	for r, p := range this.MappedPolicies {
		if matched, _ := filepath.Match(r, resource); matched {
			policies = append(policies, p...)
			continue
		}
	}

	return policies
}

func (this Role) Allowed(resource, verb string, names ...string) bool {
	for _, policy := range this.PoliciesForResource(resource) {
		if policy.VerbAllowed(verb) {
			if len(names) == 0 {
				return true
			}

			for _, n := range names {
				if policy.ResourceNameAllowed(n) {
					return true
				}
			}
		}
	}

	return false
}
