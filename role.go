package rbac

// maps role names to Role definitions
var roles = make(map[string]Role)

type Role struct {
	Name           string
	Policies       Policies
	MappedPolicies map[string]Policies
}

func NewRole(name string) Role {
	role := Role{
		Name:           name,
		MappedPolicies: make(map[string]Policies),
	}

	roles[name] = role
	return role
}

func AddPoliciesToRole(name string, policies ...*Policy) Role {
	role, ok := roles[name]
	if !ok {
		role = NewRole(name)
	}

	role.Policies = append(role.Policies, policies...)

	for _, policy := range policies {
		for _, resource := range policy.Resources {
			mapped := role.MappedPolicies[resource]
			mapped = append(mapped, policy)
			role.MappedPolicies[resource] = mapped
		}
	}

	roles[name] = role
	return role
}
