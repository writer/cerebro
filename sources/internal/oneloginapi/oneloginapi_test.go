package oneloginapi

import "testing"

func TestLiteralAttributesAreStatic(t *testing.T) {
	families := map[string]map[string]string{
		FamilyPrivileges: {
			"capability": "identity_admin",
			"is_admin":   "true",
			"role_type":  "privilege",
		},
		FamilyMappings: {
			"policy_id":   "user_mappings",
			"policy_name": "User mappings",
			"policy_type": "user_mapping",
		},
		FamilyUserApps: {
			"subject_type": "user",
		},
		FamilyUserPrivileges: {
			"capability":   "identity_admin",
			"is_admin":     "true",
			"role_type":    "privilege",
			"subject_type": "user",
		},
		FamilyDelegatedPrivileges: {
			"capability":   "identity_admin",
			"is_admin":     "true",
			"role_type":    "privilege",
			"subject_type": "user",
		},
		FamilyMFADevices: {
			"subject_type": "user",
		},
		FamilyRoleUsers: {
			"member_type": "user",
		},
		FamilyRoleAdmins: {
			"capability":   "identity_admin",
			"is_admin":     "true",
			"member_type":  "user",
			"role_type":    "admin_role",
			"subject_type": "user",
		},
		FamilyRoleApps: {
			"subject_type": "group",
		},
		FamilyAppUsers: {
			"subject_type": "user",
		},
		FamilyAppRules: {
			"policy_name": "OneLogin app rules",
			"policy_type": "app_rule",
		},
		FamilyPrivilegeUsers: {
			"capability":   "identity_admin",
			"is_admin":     "true",
			"role_type":    "privilege",
			"subject_type": "user",
		},
		FamilyPrivilegeRoles: {
			"capability":   "identity_admin",
			"is_admin":     "true",
			"role_type":    "privilege",
			"subject_type": "group",
		},
	}

	byName := map[string]struct {
		attributes       map[string]string
		staticAttributes map[string]string
	}{}
	for _, family := range Families() {
		byName[family.Name] = struct {
			attributes       map[string]string
			staticAttributes map[string]string
		}{attributes: family.Attributes, staticAttributes: family.StaticAttributes}
	}
	for familyName, expected := range families {
		family, ok := byName[familyName]
		if !ok {
			t.Fatalf("family %q missing", familyName)
		}
		for key, want := range expected {
			if got := family.staticAttributes[key]; got != want {
				t.Fatalf("%s StaticAttributes[%s] = %q, want %q", familyName, key, got, want)
			}
			if got := family.attributes[key]; got == want {
				t.Fatalf("%s Attributes[%s] = %q, want literal in StaticAttributes only", familyName, key, got)
			}
		}
	}
}
