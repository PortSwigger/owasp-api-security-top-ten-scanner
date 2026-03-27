# Quick Start Guide - Advanced API Security Scanner

## 🚀 5-Minute Setup

### 1. Build the Extension
```bash
cd burp-api-scanner
mvn clean package
```

### 2. Load in Burp Suite
- Open Burp Suite Professional
- Extensions → Add → Select: `target/burp-api-scanner-1.0.0-jar-with-dependencies.jar`

### 3. Verify Loaded
- Check for "API Scanner" tab
- Console should show: "Extension loaded successfully!"

## 🎯 Quick Test

### Test Against Sample API

1. **Start the vulnerable API server:**
```bash
cd .. # back to claude directory
npm install
node server.js
```

2. **Configure Burp Proxy:**
   - Set browser/tool to proxy through Burp (127.0.0.1:8080)

3. **Make test requests:**
```bash
# Test GET
curl -x http://127.0.0.1:8080 http://localhost:3000/api/users

# Test POST
curl -x http://127.0.0.1:8080 -X POST http://localhost:3000/api/users \
  -H "Content-Type: application/json" \
  -d '{"name":"Test User","email":"test@example.com"}'

# Test with ID
curl -x http://127.0.0.1:8080 http://localhost:3000/api/users/1
```

4. **Check "API Scanner" tab:**
   - Should show discovered endpoints
   - Should show HTTP methods observed

5. **Run active scan:**
   - Right-click any request in Proxy history
   - "Actively scan this request"
   - Check "Issues" tab for findings

## 🔍 What You'll See

### API Scanner Tab
```
API Scanning Statistics
══════════════════════
Discovered Endpoints: 3
Total API Requests:   8

Active Checks:
  ✓ HTTP Method Fuzzing
  ✓ BOLA
  ✓ Broken Authentication
  ...
```

### Issues Tab (Example Findings)
```
[High] HTTP Method DELETE Allowed on API Endpoint
  → /api/users/123 accepts DELETE (undocumented)

[High] Broken Object Level Authorization (BOLA)
  → Can access /api/users/999 by changing ID

[Medium] Missing Security Headers
  → X-Content-Type-Options, X-Frame-Options missing

[Info] OPTIONS Method Discloses Allowed Methods
  → Allow: GET, POST, PUT, DELETE, PATCH
```

## 🎓 Understanding the Key Feature

### HTTP Method Fuzzing Example

**Your OpenAPI spec says:**
```yaml
/api/users/{id}:
  get:
    summary: Get user by ID
```

**Standard scanners test:** Only GET

**This extension tests:**
```
✓ GET    /api/users/123 → 200 OK (documented)
⚠️ POST   /api/users/123 → 405 Method Not Allowed (good)
⚠️ PUT    /api/users/123 → 200 OK (VULNERABILITY! undocumented)
⚠️ DELETE /api/users/123 → 200 OK (VULNERABILITY! undocumented)
⚠️ PATCH  /api/users/123 → 200 OK (VULNERABILITY! undocumented)
ℹ️ OPTIONS /api/users/123 → 200 OK (info disclosure)
⚠️ TRACE  /api/users/123 → 200 OK (XST vulnerability!)
```

**Result:** Found 4 undocumented methods that the API specification didn't mention!

## 📊 Reading the Results

### Severity Levels

**Critical:**
- Command Injection
- JWT 'none' algorithm bypass

**High:**
- BOLA (unauthorized data access)
- SSRF with confirmed access
- Dangerous HTTP methods working
- API accessible without authentication
- Mass assignment (privilege escalation)

**Medium:**
- Unexpected HTTP methods
- Excessive data exposure
- Reflected XSS

**Low/Information:**
- Missing security headers
- CORS misconfigurations
- Method disclosure

## 🛠️ Common Workflows

### Workflow 1: Scan Known API
```
1. Import OpenAPI/Postman collection to Burp
2. Send all requests through proxy
3. Review "API Scanner" tab for discovered endpoints
4. Right-click → "Actively scan selected items"
5. Review Issues tab
```

### Workflow 2: Scan During Manual Testing
```
1. Browse application normally through Burp proxy
2. Extension auto-discovers API calls
3. Passive checks run automatically
4. Manually trigger active scans on interesting endpoints
5. Review findings
```

### Workflow 3: Target Specific Endpoint
```
1. Send interesting request to Repeater
2. Right-click → "Actively scan this request"
3. Extension tests all methods + vulnerabilities
4. Review detailed findings in Issues tab
```

## 🎯 Testing Checklist

After scanning, verify you've tested:

- [ ] All API endpoints discovered and listed
- [ ] Active scan completed (check Issues tab)
- [ ] Method fuzzing results reviewed
- [ ] High severity issues triaged
- [ ] BOLA tests run on ID-based endpoints
- [ ] Authentication mechanisms analyzed (JWT, API keys)
- [ ] Mass assignment tested on POST/PUT/PATCH
- [ ] Injection payloads tested
- [ ] Security headers reviewed

## 📝 Reporting Findings

Each issue includes:

1. **Issue Name:** Clear vulnerability description
2. **Severity:** Critical/High/Medium/Low/Info
3. **Confidence:** Certain/Firm/Tentative
4. **Details:** What was found and how
5. **Background:** Why it's a vulnerability
6. **Request/Response:** Proof of concept

Export from Burp:
- Issues → Select all → Right-click → "Report selected issues"
- Choose format (HTML/XML)

## ⚡ Pro Tips

1. **Focus on BOLA endpoints:** Any endpoint with IDs in the path
2. **Pay attention to 200 responses:** On undocumented methods
3. **Test authenticated endpoints:** Some vulns only appear when authenticated
4. **Check response bodies:** Not just status codes
5. **Use Repeater:** For detailed manual validation of findings

## 🐛 Troubleshooting

### Extension not appearing?
- Check Extensions → Errors tab
- Verify Java 11+ is installed
- Rebuild: `mvn clean package`

### No endpoints discovered?
- Verify proxy is configured correctly
- Check Proxy → HTTP history for requests
- Ensure endpoints match API patterns (/api/, /v1/, .json, /graphql)

### Active scan not running?
- Right-click the actual request (not just URL)
- Check Scanner → Scan queue
- Review Extensions → Output for errors

### No issues found?
- This is good! But verify:
  - Active scan completed fully
  - Tested authenticated endpoints with valid credentials
  - Checked endpoints with IDs (for BOLA testing)

## 📚 Next Steps

1. **Read full README.md** for detailed feature documentation
2. **Check BUILD_INSTRUCTIONS.md** if build issues occur
3. **Review OWASP API Security Top 10** for context
4. **Test on authorized targets only!**

## ⚠️ Legal Reminder

**Only test APIs you have explicit authorization to test.**

This tool generates attack traffic that may:
- Trigger security alerts
- Violate terms of service
- Be illegal without authorization

Always obtain written permission before testing.

---

**Happy API Hunting! 🔒**
