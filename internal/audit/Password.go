package audit
import (
	"github.com/go-ldap/ldap/v3"
)

func ListPasswordNeverExpiresAccounts(conn *ldap.Conn,baseDN string,) ([]AuditFinding, error){
	searchRequest := ldap.NewSearchRequest(
        baseDN,
        ldap.ScopeWholeSubtree,
        ldap.NeverDerefAliases,
        0,
        0,
        false,
        "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))",
        []string{"cn", "sAMAccountName"},
        nil,
    )
    result, err := conn.Search(searchRequest)
    if err != nil {
        return nil, err
    }
    findings := []AuditFinding{}

    for _, entry := range result.Entries {
        finding := AuditFinding{
            CheckID:  "PASSWORD_NEVER_EXPIRES",
            Severity: "High",
            DN:       entry.DN,
            Account:  entry.GetAttributeValue("sAMAccountName"),
            Details:  "Password is set to never expire",
        }
        findings = append(findings, finding)
    }

    return findings, nil
}

