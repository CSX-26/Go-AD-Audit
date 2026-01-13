package audit

import (
	"fmt"
	"strconv"

	"github.com/go-ldap/ldap/v3"
)

func AuditWeakPasswordFlags(conn *ldap.Conn, baseDN string) ([]AuditFinding, error) {

	filter := "(&(objectCategory=person)(objectClass=user)" +
		"(|" +
		"(userAccountControl:1.2.840.113556.1.4.803:=32)" +
		"(userAccountControl:1.2.840.113556.1.4.803:=128)" +
		"(userAccountControl:1.2.840.113556.1.4.803:=65536)" +
		"))"

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

		uacStr := entry.GetAttributeValue("userAccountControl")
		uacInt, err := strconv.Atoi(uacStr)
		if err != nil {
			continue
		}

		flags := []string{}

		if uacInt&32 != 0 {
			flags = append(flags, "PASSWD_NOTREQD")
		}
		if uacInt&128 != 0 {
			flags = append(flags, "ENCRYPTED_TEXT_PASSWORD_ALLOWED")
		}
		if uacInt&65536 != 0 {
			flags = append(flags, "PASSWORD_NEVER_EXPIRES")
		}

		if len(flags) == 0 {
			continue
		}

		findings = append(findings, AuditFinding{
			CheckID:  "WEAK_PASSWORD_FLAGS",
			Severity: "High",
			DN:       entry.DN,
			Account:  entry.GetAttributeValue("sAMAccountName"),
			Details:  fmt.Sprintf("Weak password flags set: %v", flags),
		})
	}

	return findings, nil
}
