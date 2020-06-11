package rbac

// map a user to multiple roles
var bindings = make(map[string][]*Role)

func BindUserToRole(user string, role *Role) {
	roles := bindings[user]
	roles = append(roles, role)
	bindings[user] = roles
}

func UserPolicies(user string) Policies {
	var policies Policies

	for _, role := range bindings[user] {
		policies = append(policies, role.Policies...)
	}

	return policies
}

func UserPoliciesForResource(user, resource string) Policies {
	var policies Policies

	for _, role := range bindings[user] {
		for r, p := range role.MappedPolicies {
			if r == "*" || r == resource {
				policies = append(policies, p...)
			}
		}
	}

	return policies
}

func AllowedForUser(user, resource, verb string, names ...string) bool {
	for _, policy := range UserPoliciesForResource(user, resource) {
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
