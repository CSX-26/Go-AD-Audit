package audit

import (
	"fmt"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func AuditInactiveAccounts(conn *ldap.Conn, baseDN string,InactiveDaysThreshold int) ([]AuditFinding, error) {

	thresholdTime := time.Now().AddDate(0, 0, -InactiveDaysThreshold)
	fileTime := (thresholdTime.Unix() + 11644473600) * 10000000

	filter := fmt.Sprintf(
		"(&(objectCategory=person)(objectClass=user)(lastLogonTimestamp<=%d))",
		fileTime,
	)

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{
			"dn",
			"sAMAccountName",
			"lastLogonTimestamp",
			"adminCount",
		},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	findings := []AuditFinding{}

	for _, entry := range result.Entries {

		severity := "Medium"
		if entry.GetAttributeValue("adminCount") == "1" {
			severity = "High"
		}

		findings = append(findings, AuditFinding{
			CheckID:  "INACTIVE_ACCOUNT",
			Severity: severity,
			DN:       entry.DN,
			Account:  entry.GetAttributeValue("sAMAccountName"),
			Details: fmt.Sprintf(
				"Account inactive for more than %d days",
				InactiveDaysThreshold,
			),
		})
	}

	return findings, nil
}
