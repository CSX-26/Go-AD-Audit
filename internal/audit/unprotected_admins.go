package audit

import (
	"github.com/go-ldap/ldap/v3"
)

func AuditUnprotectedAdmins(conn *ldap.Conn, baseDN string) ([]AuditFinding, error) {

	privilegedGroups := []string{
		"CN=Domain Admins,CN=Users," + baseDN,
		"CN=Enterprise Admins,CN=Users," + baseDN,
		"CN=Administrators,CN=Builtin," + baseDN,
		"CN=Account Operators,CN=Builtin," + baseDN,
		"CN=Backup Operators,CN=Builtin," + baseDN,
		"CN=Server Operators,CN=Builtin," + baseDN,
	}

	findings := []AuditFinding{}

	for _, groupDN := range privilegedGroups {

		searchRequest := ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(&(objectCategory=person)(objectClass=user)" +
				"(memberOf=" + ldap.EscapeFilter(groupDN) + ")" +
				"(!(adminCount=1)))",
			[]string{
				"cn",
				"sAMAccountName",
				"adminCount",
			},
			nil,
		)

		result, err := conn.Search(searchRequest)
		if err != nil {
			return nil, err
		}

		for _, entry := range result.Entries {
			findings = append(findings, AuditFinding{
				CheckID:  "UNPROTECTED_ADMIN",
				Severity: "High",
				DN:       entry.DN,
				Account:  entry.GetAttributeValue("sAMAccountName"),
				Details:  "Privileged account without adminCount=1 (not protected by AdminSDHolder)",
			})
		}
	}

	return findings, nil
}
