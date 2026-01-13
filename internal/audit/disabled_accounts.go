package audit

import (
	"github.com/go-ldap/ldap/v3"
)

func AuditDisabledAccounts(conn *ldap.Conn, baseDN string) ([]AuditFinding, error) {

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2)(!(sAMAccountName=krbtgt)))",
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
			CheckID:  "DISABLED_ACCOUNT",
			Severity: "Medium",
			DN:       entry.DN,
			Account:  entry.GetAttributeValue("sAMAccountName"),
			Details:  "Account is disabled",
		})
	}

	return findings, nil
}
