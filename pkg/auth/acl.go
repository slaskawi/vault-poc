package auth

import (
	"fmt"
	"sort"
	"strings"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
)

// ACLManager object.
type ACLManager struct{}

// NewACLManager creates a new ACLManager object.
func NewACLManager() *ACLManager {
	return &ACLManager{}
}

// CanPerform determines if the requested action is allowed to be performed based on its ACLs.
// An error is returned if the action is not allowed to peformed.
func (m *ACLManager) CanPerform(acls []*apiv1.ACL, perm apiv1.Permission, path string) error {
	if len(acls) == 0 {
		return ErrForbidden
	}

	permissions, err := m.CalculatePermissions(acls, path)
	if err != nil {
		return err
	}

	for _, p := range permissions {
		if p == perm {
			return nil
		}
	}

	return ErrForbidden
}

// ValidateACLs validates that a given ACLs are configured properly.
func (m *ACLManager) ValidateACLs(acls []*apiv1.ACL) error {
	for _, acl := range acls {
		if acl == nil {
			return fmt.Errorf("acl cannot be nil")
		}
		if len(acl.Path) == 0 {
			return fmt.Errorf("acl path cannot be empty")
		}
		if idx := strings.Index(acl.Path, "*"); idx > -1 && idx < len(acl.Path)-1 {
			return fmt.Errorf("the `*` wildcard can only be used at the end of an acl path: %s", acl.Path)
		}
		if len(acl.Permissions) == 0 {
			return fmt.Errorf("acl has no permissions: %s", acl.Path)
		}
		for _, perm := range acl.Permissions {
			if perm == apiv1.Permission_DENY && len(acl.Permissions) > 1 {
				return fmt.Errorf("a DENY permission cannot be mixed with other permissions: %s", acl.Path)
			}
		}
	}
	return nil
}

// CalculatePermissions calculates the permissions for the given ACLs and path.
func (m *ACLManager) CalculatePermissions(acls []*apiv1.ACL, path string) ([]apiv1.Permission, error) {
	if err := m.ValidateACLs(acls); err != nil {
		return nil, err
	}

	// sort the ACLs by shortest path first
	sort.Slice(acls, func(i, j int) bool {
		return len(acls[i].Path) < len(acls[j].Path) && acls[i].Path < acls[j].Path
	})

	path = strings.TrimPrefix(path, "/")
	noPermissions := []apiv1.Permission{}
	permissions := noPermissions

	for _, acl := range acls {
		p := strings.TrimPrefix(acl.Path, "/")

		if path == p {
			if acl.Permissions[0] == apiv1.Permission_DENY {
				permissions = noPermissions
			} else {
				permissions = acl.Permissions
			}
			break
		}

		if strings.HasSuffix(p, "*") && strings.HasPrefix(path, p[:len(p)-1]) {
			if acl.Permissions[0] == apiv1.Permission_DENY {
				permissions = noPermissions
			} else {
				permissions = acl.Permissions
			}
		}
	}

	return permissions, nil
}
