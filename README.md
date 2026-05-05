# Advanced API Security Scanner - Burp Suite Extension

A comprehensive Burp Suite extension (BApp) specifically designed for API security testing with focus on HTTP method fuzzing and OWASP API Security Top 10 2023 vulnerabilities.

**✅ Compatible with:**
- Burp Suite Professional (Interactive mode with UI)
- Burp Suite Enterprise Edition (Headless DAST mode)

> **For Burp DAST users:** See [BURP_ENTERPRISE_GUIDE.md](BURP_ENTERPRISE_GUIDE.md) for detailed integration instructions.

## 🎯 Key Features

### 1. **HTTP Method Fuzzing** (Primary Feature)
- **Automatically tests ALL HTTP methods** on every discovered API endpoint
- Tests: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE, CONNECT
- **Does not rely on collection file specifications** - discovers undocumented methods
- Identifies dangerous method exposures (PUT, DELETE on unprotected endpoints)
- Detects Cross-Site Tracing (XST) via TRACE method
- Reports OPTIONS disclosure vulnerabilities

### 2. **OWASP API Security Top 10 2023 - Complete Coverage**

#### API1:2023 - Broken Object Level Authorization
- Tests for insecure direct object references (BOLA/IDOR)
- ID manipulation testing (sequential, common values)
- Unauthenticated access attempts to protected resources
- ID enumeration vulnerability detection
- **Status:** ✅ Full Active + Passive Detection

#### API2:2023 - Broken Authentication
- JWT vulnerability detection:
  - `alg: none` bypass attempts
  - Weak symmetric algorithms (HS256, HS384, HS512)
  - Missing expiration claims
  - Long-lived tokens (>24 hours)
- Basic Auth detection over HTTP
- API key transmitted over insecure channels
- **Status:** ✅ Full Active + Passive Detection

#### API3:2023 - Broken Object Property Level Authorization
- **Information Exposure:**
  - Identifies sensitive fields in responses (passwords, tokens, keys)
  - Detects large unbounded responses (>100 items)
  - Flags responses with excessive fields (>20 fields)
- **Mass Assignment:**
  - Attempts to inject sensitive fields: `isAdmin`, `role`, `permissions`
  - Tests privilege escalation via property manipulation
  - Multiple field injection testing
- **Status:** ✅ Full Active + Passive Detection

#### API4:2023 - Unrestricted Resource Consumption
- Missing rate limiting header detection
- Large response size analysis (>5MB)
- Resource-intensive endpoint identification
- Denial of Service risk assessment
- **Status:** ⚠️ Passive Detection Only

#### API5:2023 - Broken Function Level Authorization
- **HTTP Method Fuzzing** (Primary Feature)
- Tests ALL HTTP methods: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE, CONNECT
- Discovers undocumented methods that bypass security
- Identifies dangerous method exposures (PUT, DELETE on unprotected endpoints)
- Cross-Site Tracing (XST) via TRACE method
- **Status:** ✅ Full Active Detection

#### API6:2023 - Unrestricted Access to Sensitive Business Flows
- Detects sensitive business endpoints (purchase, payment, booking)
- Checks for missing anti-automation mechanisms
- CAPTCHA/CSRF protection analysis
- Business logic abuse risk assessment
- **Status:** ⚠️ Passive Detection Only

#### API7:2023 - Server Side Request Forgery
- SSRF detection via URL parameter fuzzing
- Internal network access testing (127.0.0.1, localhost)
- Cloud metadata endpoint probing (AWS: 169.254.169.254, GCP)
- File protocol testing (file:///)
- Blind SSRF detection
- **Status:** ✅ Full Active Detection

#### API8:2023 - Security Misconfiguration
- **Configuration Issues:**
  - Missing security headers (X-Content-Type-Options, CSP, HSTS)
  - Information disclosure headers (Server, X-Powered-By)
  - CORS misconfigurations (wildcard, reflected origins)
  - HTTP vs HTTPS usage
  - Verbose error messages
- **Injection Vulnerabilities:**
  - SQL Injection (error-based, multiple payloads)
  - NoSQL Injection (MongoDB, authentication bypass)
  - Command Injection (OS command execution)
  - XSS (reflected in API responses)
- **Status:** ✅ Full Active + Passive Detection

#### API9:2023 - Improper Inventory Management
- Deprecated API version detection (v0, v1, old, legacy)
- Debug endpoint exposure (/debug, /test, /dev, /swagger, /api-docs)
- API version disclosure in headers
- Internal endpoint exposure
- **Status:** ⚠️ Passive Detection Only

#### API10:2023 - Unsafe Consumption of APIs
- Third-party API integration detection
- Webhook endpoint identification
- Validation indicator analysis
- Supply chain security assessment
- **Status:** ⚠️ Passive Detection Only

## 🚀 Installation

### Method 1: Build from Source

1. **Prerequisites:**
   - Java 11 or higher
   - Maven 3.6+
   - Burp Suite Professional

2. **Build the extension:**
```bash
cd burp-api-scanner
mvn clean package
```

3. **Load in Burp Suite:**
   - Open Burp Suite
   - Go to Extensions → Installed → Add
   - Select `target/burp-api-scanner-1.0.0-jar-with-dependencies.jar`

### Method 2: Download Pre-built JAR

Download the latest release JAR and load it directly in Burp Suite Extensions tab.

## 📖 Usage

### Basic Workflow

1. **Configure Burp Proxy:**
   - Set up your browser/API client to proxy through Burp
   - Ensure "Intercept is off" for passive scanning

2. **Browse or Test Your API:**
   - Make requests to your API endpoints
   - The extension automatically discovers and analyzes all API traffic

3. **View Discovered Endpoints:**
   - Navigate to the "API Scanner" tab in Burp
   - View all discovered endpoints, methods, and request counts
   - Auto-refreshes every 5 seconds

4. **Run Active Scans:**
   - Right-click any API request in Proxy/Target
   - Select "Actively scan this request"
   - The extension will:
     - Test all HTTP methods on the endpoint
     - Run OWASP API Top 10 vulnerability checks
     - Report findings in Burp's Issues tab

5. **Review Findings:**
   - Check Burp's "Issues" tab for discovered vulnerabilities
   - Each issue includes:
     - Detailed description
     - Proof of concept (request/response)
     - Severity rating
     - Remediation advice

### Key Advantage: Method Fuzzing

**Unlike standard API scanners**, this extension doesn't just test the methods specified in OpenAPI/Swagger documentation:

```
Example: API doc says: GET /api/users/123

Standard scanner tests: GET /api/users/123 ✓

This extension tests:
  GET    /api/users/123 ✓
  POST   /api/users/123 ⚠️  (might work!)
  PUT    /api/users/123 ⚠️  (might allow updates!)
  DELETE /api/users/123 ⚠️  (might delete user!)
  PATCH  /api/users/123 ⚠️  (might modify!)
  TRACE  /api/users/123 ⚠️  (XST vulnerability!)
  OPTIONS /api/users/123 ℹ️  (method disclosure)
```

This discovers **undocumented methods** that may bypass security controls.

## 🔍 What Gets Scanned

### Automatic API Detection
The extension automatically identifies API endpoints:
- Paths containing `/api/`
- Versioned paths (`/v1/`, `/v2/`, etc.)
- JSON endpoints (`.json`)
- GraphQL endpoints (`/graphql`)

### Passive Checks (No Active Requests)
- Security header analysis
- Information disclosure detection
- CORS configuration review
- Response data exposure analysis

### Active Checks (Sends Test Requests)
- HTTP method fuzzing
- BOLA testing (ID manipulation)
- Mass assignment attempts
- Injection payload testing
- SSRF probe requests

## 📊 UI Features

### API Scanner Tab

The extension adds a dedicated tab with:

1. **Statistics Panel:**
   - Discovered endpoint count
   - Total API request count
   - Active check status

2. **Endpoint Table:**
   - Discovered API hosts
   - Normalized endpoint paths
   - Observed HTTP methods
   - Request counts per endpoint
   - Sortable columns

3. **Controls:**
   - Manual refresh button
   - Clear table function
   - Auto-refresh toggle (5-second interval)

## 🛡️ Security Testing Coverage

### ✅ Complete OWASP API Security Top 10 2023 Coverage

| OWASP Category | Detection Status | Implementation |
|----------------|------------------|----------------|
| **API1:2023** - Broken Object Level Authorization | ✅ Complete | Active + Passive |
| **API2:2023** - Broken Authentication | ✅ Complete | Active + Passive |
| **API3:2023** - Broken Object Property Level Authorization | ✅ Complete | Active + Passive |
| **API4:2023** - Unrestricted Resource Consumption | ⚠️ Basic | Passive Only |
| **API5:2023** - Broken Function Level Authorization | ✅ Complete | Active (Method Fuzzing) |
| **API6:2023** - Unrestricted Access to Sensitive Business Flows | ⚠️ Basic | Passive Only |
| **API7:2023** - Server Side Request Forgery | ✅ Complete | Active |
| **API8:2023** - Security Misconfiguration | ✅ Complete | Active + Passive |
| **API9:2023** - Improper Inventory Management | ⚠️ Basic | Passive Only |
| **API10:2023** - Unsafe Consumption of APIs | ⚠️ Basic | Passive Only |

**Legend:**
- ✅ **Complete**: Full active + passive detection with comprehensive checks
- ⚠️ **Basic**: Passive detection with heuristics (limited to observable patterns)

### Critical/High Severity Issues Detected:
- ✅ BOLA - Unauthorized data access via ID manipulation
- ✅ Authentication bypass (JWT 'none' algorithm)
- ✅ Mass assignment leading to privilege escalation
- ✅ SQL/NoSQL/Command Injection
- ✅ SSRF with cloud metadata access
- ✅ Dangerous HTTP methods (PUT/DELETE) on unprotected endpoints
- ✅ CORS wildcard with credentials
- ✅ API accessible over HTTP

### Medium Severity Issues Detected:
- ✅ Unexpected HTTP methods enabled
- ✅ Excessive data exposure in API responses
- ✅ Long-lived JWT tokens (>24 hours)
- ✅ Reflected XSS in API responses
- ✅ ID enumeration vulnerabilities
- ✅ Missing rate limiting on resource-intensive endpoints
- ✅ Business flow endpoints without anti-automation

### Low/Information Severity Issues Detected:
- ✅ Missing security headers
- ✅ Information disclosure headers
- ✅ CORS misconfigurations
- ✅ OPTIONS method disclosure
- ✅ Verbose error messages
- ✅ Deprecated API versions
- ✅ Debug endpoints exposed
- ✅ Third-party API integration risks

## 🔧 Configuration

The extension works out-of-the-box with sensible defaults. Configuration options:

- **Auto-refresh interval**: 5 seconds (adjustable in UI)
- **Scan scope**: Follows Burp's scope settings
- **Issue reporting**: All findings go to Burp's Issues tab

## 📝 Example Vulnerabilities Found

### Example 1: Undocumented DELETE Method
```
Issue: HTTP Method DELETE Allowed on API Endpoint
Severity: High
Endpoint: https://api.example.com/api/users/123

Original documented method: GET
Tested method: DELETE
Response: 200 OK

Impact: Attacker can delete any user by guessing IDs
```

### Example 2: BOLA via ID Manipulation
```
Issue: Broken Object Level Authorization (BOLA)
Severity: High
Endpoint: https://api.example.com/api/orders/456

Original request: GET /api/orders/456 (user's order)
Modified request: GET /api/orders/123 (different user's order)
Response: 200 OK with full order details

Impact: Attacker can access any user's orders
```

### Example 3: Mass Assignment
```
Issue: Mass Assignment Vulnerability
Severity: High
Endpoint: https://api.example.com/api/users

Original request body:
  {"name": "John", "email": "john@example.com"}

Modified request body:
  {"name": "John", "email": "john@example.com", "isAdmin": true}

Response: 200 OK with "isAdmin": true in response

Impact: User can escalate to admin privileges
```

## 🏗️ Architecture

```
BurpExtender (Main)
├── ApiScanner (Orchestrator)
│   ├── MethodFuzzingCheck *KEY FEATURE*
│   ├── BrokenObjectAuthCheck (BOLA)
│   ├── BrokenAuthCheck (JWT, tokens)
│   ├── MassAssignmentCheck
│   ├── ExcessiveDataExposureCheck
│   ├── InjectionCheck (SQL/NoSQL/Command/XSS)
│   ├── SsrfCheck
│   └── SecurityMisconfigCheck
├── ScannerTab (UI)
└── CustomScanIssue (Reporting)
```

## 📚 References

- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x00-header/)
- [Burp Extender API Documentation](https://portswigger.net/burp/extender/api/)
- [HTTP Method Definitions (RFC 7231)](https://tools.ietf.org/html/rfc7231#section-4)

## 🤝 Contributing

Contributions welcome! Areas for enhancement:
- Additional OWASP API Security checks
- GraphQL-specific testing
- Rate limiting detection
- API versioning analysis
- Enhanced timing-based injection detection

## 📄 License

MIT License - See LICENSE file for details

## ⚠️ Disclaimer

This tool is designed for **authorized security testing only**. Always obtain proper authorization before testing any API or application you don't own. Unauthorized testing may be illegal.

## 🐛 Known Limitations

- JWT signature verification requires valid tokens
- Timing-based injection detection is simplified
- Collaborator integration not yet implemented for out-of-band detection
- GraphQL introspection is basic

## 📞 Support

For issues, questions, or feature requests, please open an issue on the GitHub repository.

---

**Built for security professionals by security professionals** 🔒
