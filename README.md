# Go AD Audit 🛡️

**Go AD Audit** is a lightweight Active Directory security auditing tool written in **Go**.
It connects to Active Directory via **LDAP** and performs multiple security checks to detect
common misconfigurations and risky account settings. Results are exported into a clean **HTML security report**.

---

## 🚀 Features

### Account Audits
- Disabled Accounts
- Locked Accounts
- Inactive Accounts
- Password Never Expires
- Weak Password Flags
- AS-REP Roastable Accounts

### Privileged Audits
- Protected Accounts (adminCount = 1)
- Unprotected Admin Accounts

### Reporting
- HTML security report
- Severity levels (High / Medium / Low)

---

## 🏗️ Project Structure

```
go-ad-audit/
├── cmd/
│   └── main.go
├── config/
│   ├── config.yaml
│   └── config.example.yaml
├── internal/
│   ├── audit/
│   ├── ldapclient/
│   └── reporter/
├── outputs/
│   └── ad-audit-report.html
├── go.mod
└── README.md
```

---

## ⚙️ Configuration

Copy example config:

```
cp config/config.example.yaml config/config.yaml
```

Example:

```yaml
ldap:
  host: "192.168.1.10"
  port: 636
  username: "DOMAIN\\username"
  password: "password"
  base_dn: "DC=Domain,DC=local"

report:
  output: "outputs/ad-audit-report.html"
```

---

## ▶️ Usage

```
go run .\main.go
```

---

## ⚠️ Disclaimer

For authorized environments only.
