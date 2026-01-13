package main

import (
	"fmt"
	"go-ad-audit/config"
	"go-ad-audit/internal/audit"
	"go-ad-audit/internal/ldapclient"
	"go-ad-audit/internal/reporter"
)

func main() {

	appConfig, err := config.Load("../config/config.yaml")
	if err != nil {
		fmt.Println("Failed to load config:", err)
		return
	}

	cfg := ldapclient.Config{
		Host:     appConfig.LDAP.Host,
		Port:     appConfig.LDAP.Port,
		Username: appConfig.LDAP.Username,
		Password: appConfig.LDAP.Password,
	}

	conn, err := ldapclient.ClientConnect(cfg)
	if err != nil {
		fmt.Println("LDAP connection failed:", err)
		return
	}
	defer conn.Close()

	fmt.Println("LDAP connection successful")

	baseDN := "DC=Domain,DC=local"

	findings, err := audit.ListProtectedAccounts(conn, baseDN)
	if err != nil {
		fmt.Println("LDAP Listing Protected Accounts failed:", err)
	}

	Passwordfindings, err := audit.ListPasswordNeverExpiresAccounts(conn, baseDN)
	if err != nil {
		fmt.Println("LDAP Listing Password Never Expires failed:", err)
	}

	disabledfindings, err := audit.AuditDisabledAccounts(conn, baseDN)
	if err != nil {
		fmt.Println("LDAP Listing Disabled Accounts failed:", err)
	}

	Lockedfindings, err := audit.AuditLockedAccounts(conn, baseDN)
	if err != nil {
		fmt.Println("LDAP Listing Locked Accounts failed:", err)
	}

	inactiveFindings, err := audit.AuditInactiveAccounts(conn, baseDN, appConfig.Audit.InactiveDays)
	if err != nil {
		fmt.Println("LDAP Listing Inactive Accounts failed:", err)
	}

	asrepFindings, err := audit.AuditASREPUsers(conn, baseDN)
	if err != nil {
		fmt.Println("LDAP AS-REP audit failed:", err)
	}

	weakPwdFindings, err := audit.AuditWeakPasswordFlags(conn, baseDN)
	if err != nil {
		fmt.Println("LDAP Weak Password Flags audit failed:", err)
	}

	UNPROTECTED_ADMIN, err := audit.AuditUnprotectedAdmins(conn, baseDN)
	if err != nil {
		fmt.Println("LDAP UNPROTECTED_ADMIN audit failed:", err)
	}

	Allfinds := []audit.AuditFinding{}
	Allfinds = append(Allfinds, Lockedfindings...)
	Allfinds = append(Allfinds, disabledfindings...)
	Allfinds = append(Allfinds, Passwordfindings...)
	Allfinds = append(Allfinds, findings...)
	Allfinds = append(Allfinds, inactiveFindings...)
	Allfinds = append(Allfinds, asrepFindings...)
	Allfinds = append(Allfinds, weakPwdFindings...)
	Allfinds = append(Allfinds, UNPROTECTED_ADMIN...)

	err = reporter.GenerateHTMLReport(
		Allfinds,
		appConfig.Report.Output,
	)
	if err != nil {
		fmt.Println("Failed to generate HTML report:", err)
		return
	}

	fmt.Println("HTML report generated:", appConfig.Report.Output)
}
