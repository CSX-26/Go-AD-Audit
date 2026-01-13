package audit

import (
	"github.com/go-ldap/ldap/v3"
)

func AuditASREPUsers(conn *ldap.Conn, baseDN string) ([]AuditFinding, error) {

	filter := "(&(objectCategory=person)(objectClass=user)" +
		"(!(userAccountControl:1.2.840.113556.1.4.803:=2))" +
		"(userAccountControl:1.2.840.113556.1.4.803:=4194304))"

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{
			"cn",
			"sAMAccountName",
			"userAccountControl",
		},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	findings := []AuditFinding{}

	for _, entry := range result.Entries {

		findings = append(findings, AuditFinding{
			CheckID:  "ASREP_ROASTABLE_ACCOUNT",
			Severity: "High",
			DN:       entry.DN,
			Account:  entry.GetAttributeValue("sAMAccountName"),
			Details:  "Kerberos pre-authentication is disabled (AS-REP Roastable)",
		})
	}

	return findings, nil
}
