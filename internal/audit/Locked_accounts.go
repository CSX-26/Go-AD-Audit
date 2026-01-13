package audit

import (
	"github.com/go-ldap/ldap/v3"
)

func AuditLockedAccounts(conn *ldap.Conn, baseDN string) ([]AuditFinding, error) {

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectCategory=person)(objectClass=user)(lockoutTime>=1))",
		[]string{"cn", "sAMAccountName"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	findings := []AuditFinding{}

	for _, entry := range result.Entries {
		findings = append(findings, AuditFinding{
			CheckID:  "LOCKED_ACCOUNT",
			Severity: "Medium",
			DN:       entry.DN,
			Account:  entry.GetAttributeValue("sAMAccountName"),
			Details:  "Account is Locked",
		})
	}

	return findings, nil
}
