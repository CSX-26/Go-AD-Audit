package audit

import (
	"github.com/go-ldap/ldap/v3"

)

type AuditFinding struct {
    CheckID   string
    Severity  string
    DN        string
    Account   string
    Details   string
}
type User struct {
    DN   string
    CN  string
    Account   string
}      

func ListUsers(conn *ldap.Conn, baseDN string) ([]User, error){
    searchRequest := ldap.NewSearchRequest(
        baseDN,                            
        ldap.ScopeWholeSubtree,           
        ldap.NeverDerefAliases,           
        0,                                
        0,                                
        false,                            
        "(&(objectCategory=person)(objectClass=user))", 
        []string{"cn", "sAMAccountName"}, 
        nil,                              
    )

    result, err := conn.Search(searchRequest)
    if err != nil {
        return nil,err
    }
    findingsUser := []User{}

    for _, entry := range result.Entries {
        findingUser :=User{
            DN: entry.DN,
            CN: entry.GetAttributeValue("cn"),
            Account: entry.GetAttributeValue("sAMAccountName"),
        }
        findingsUser = append(findingsUser, findingUser)
    }

    return findingsUser,nil
}
func ListProtectedAccounts(conn *ldap.Conn, baseDN string) ([]AuditFinding, error){
    searchRequest := ldap.NewSearchRequest(
        baseDN,                            
        ldap.ScopeWholeSubtree,           
        ldap.NeverDerefAliases,           
        0,                                
        0,                                
        false,                            
        "(&(objectCategory=person)(adminCount=1))", 
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
            CheckID:  "PROTECTED_ACCOUNT",
			Severity: "High",
			DN:       entry.DN,
			Account:  entry.GetAttributeValue("sAMAccountName"),
			Details:  "Account is protected by AdminSDHolder (adminCount=1).\n Verify current group membership.",
        }
		findings = append(findings, finding)
    }

	return findings,nil

}