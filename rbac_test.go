package rbac

import (
	"testing"
)

/*
version: v0
kind: Role
metadata:
	name: Admin
spec:
	policies:
	- resources:
		- "*"
		resourceNames:
		- "*"
		verbs:
		- "*"

version: v0
kind: Role
metadata:
	name: Viewer
spec:
	policies:
	- resources:
		- vms
		resourceNames:
		- foo_*
		- bar_fish
		verbs:
		- list
	- resources:
		- vms/screenshot
		- vms/vnc
		resourceNames:
		- foo_*
		- bar_fish
		verbs:
		- get
*/

func TestAdmin(t *testing.T) {
	user := "admin@foo.com"

	policies := Policies([]*Policy{
		{
			Resources:     []string{"*", "*/*"},
			ResourceNames: []string{"*"},
			Verbs:         []string{"*"},
		},
	})

	role := NewRole("Admin", policies...)
	BindUserToRole(user, role)

	if !AllowedForUser(user, "foobar/start", "update") {
		t.Fatal("expected admin to be able to start foobar")
	}
}

func TestViewer(t *testing.T) {
	user := "viewer@foo.com"

	policies := Policies([]*Policy{
		{
			Resources: []string{"vms"},
			Verbs:     []string{"list"},
		},
		{
			Resources: []string{"vms/screenshot", "vms/vnc"},
			Verbs:     []string{"get"},
		},
	})

	policies.AddResourceNames("foo_*_sucka")

	role := NewRole("Viewer", policies...)
	BindUserToRole(user, role)

	if AllowedForUser(user, "foobar/start", "update") {
		t.Fatal("didn't expect viewer to be able to start foobar")
	}

	if !AllowedForUser(user, "vms/vnc", "get", "foo_bar_sucka") {
		t.Fatal("expected VM viewer to be able to access VNC for foo_bar_sucka")
	}
}
