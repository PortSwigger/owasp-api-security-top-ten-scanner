# Burp Suite Enterprise Edition (DAST) Integration Guide

## 🎯 Overview

This extension is **fully compatible** with both:
- ✅ **Burp Suite Professional** (Interactive scanning with UI)
- ✅ **Burp Suite Enterprise Edition** (Automated/headless DAST scanning)

The extension automatically detects the environment and adjusts accordingly.

---

## 📦 Extension File

**Location:**
```
/Users/rob.cornes/claude/burp-api-scanner/target/burp-api-scanner-1.0.0-jar-with-dependencies.jar
```

---

## 🚀 Installation in Burp Suite Enterprise Edition

### Method 1: Via Web UI (Recommended)

1. **Log in to Burp Suite Enterprise**
   - Navigate to your Burp Enterprise web interface
   - Go to **Settings** → **Extensions**

2. **Upload Extension**
   - Click **Add extension**
   - Select file: `burp-api-scanner-1.0.0-jar-with-dependencies.jar`
   - Click **Upload**

3. **Enable Extension**
   - Find "Advanced API Security Scanner" in the list
   - Toggle **Enabled** to ON
   - Save changes

### Method 2: Via Configuration File

If managing extensions via configuration:

```yaml
extensions:
  - name: "Advanced API Security Scanner"
    path: "/path/to/burp-api-scanner-1.0.0-jar-with-dependencies.jar"
    enabled: true
```

---

## 🔧 Scan Configuration

### Creating a Scan with the Extension

1. **Create New Scan**
   - Go to **Scans** → **New scan**
   - Enter your API base URL

2. **Configure Scan Settings**
   - **Scan Type:** Active and Passive
   - **Extensions:** Ensure "Advanced API Security Scanner" is enabled
   - **Scan Speed:** Normal or Thorough (recommended for APIs)

3. **Optional: Import OpenAPI/Swagger**
   - Upload your API specification
   - Extension will automatically test all endpoints

---

## 🎯 What Gets Scanned

### Automatic Detection

The extension automatically identifies API endpoints based on:
- URLs containing `/api/`
- Versioned paths (`/v1/`, `/v2/`, etc.)
- JSON content types
- GraphQL endpoints

### Coverage

| OWASP Category | Detection | Notes |
|----------------|-----------|-------|
| **API1:2023** - BOLA | ✅ Active + Passive | ID manipulation, enumeration |
| **API2:2023** - Authentication | ✅ Active + Passive | JWT testing, weak auth |
| **API3:2023** - Property Authorization | ✅ Active + Passive | Data exposure, mass assignment |
| **API4:2023** - Resource Consumption | ⚠️ Passive | Rate limiting checks |
| **API5:2023** - Function Authorization | ✅ Active | HTTP method fuzzing |
| **API6:2023** - Business Flows | ⚠️ Passive | Anti-automation checks |
| **API7:2023** - SSRF | ✅ Active | Internal network access |
| **API8:2023** - Misconfiguration | ✅ Active + Passive | Headers, CORS, injections |
| **API9:2023** - Inventory Management | ⚠️ Passive | Deprecated versions, debug endpoints |
| **API10:2023** - API Consumption | ⚠️ Passive | Webhook validation |

---

## 📊 Viewing Results

### In Burp Enterprise Dashboard

1. **Navigate to Scan Results**
   - Select your completed scan
   - Go to **Issues** tab

2. **Filter by Extension**
   - Issues will be prefixed with OWASP ID
   - Example: `API1:2023 - Broken Object Level Authorization`

3. **Issue Details Include:**
   - **Severity:** Critical/High/Medium/Low/Information
   - **Confidence:** Certain/Firm/Tentative
   - **Description:** OWASP 2023 official description
   - **Proof of Concept:** Request/Response demonstrating the vulnerability
   - **Remediation:** Specific fix recommendations

### Sample Issue Output

```
Issue: API1:2023 - Broken Object Level Authorization
Severity: High
Confidence: Firm

Background:
APIs tend to expose endpoints that handle object identifiers, creating a wide
attack surface of Object Level Access Control issues. Object level authorization
checks should be considered in every function that accesses a data source using
an ID from the user.

Details:
The API endpoint is vulnerable to BOLA. Unauthorized access to user resources
was achieved by manipulating object IDs.

Original URL: https://api.example.com/users/123
Modified URL: https://api.example.com/users/456

Impact:
- Unauthorized data access
- Privacy violation
- Potential data breach

Recommendation:
Implement proper authorization checks that verify the authenticated user has
permission to access the requested resource.
```

---

## ⚙️ Advanced Configuration

### Scan Performance Tuning

For large APIs, consider:

1. **Increase Thread Count**
   - Enterprise settings → Performance
   - Set higher thread count for faster scans

2. **Adjust Timeouts**
   - Increase request timeout for slow APIs
   - Default: 30 seconds

3. **Scope Configuration**
   - Use scope rules to focus on API endpoints
   - Exclude static assets

### Example Scope Configuration

```
Include:
  - https://api.example.com/*
  - https://example.com/api/*
  - https://example.com/v1/*
  - https://example.com/v2/*

Exclude:
  - *.css
  - *.js
  - *.png
  - *.jpg
  - /static/*
  - /assets/*
```

---

## 🔍 Testing Specific Vulnerabilities

### Focus on Specific OWASP Categories

The extension runs all checks by default, but you can analyze results by category:

**Critical Issues (Immediate Action Required):**
- API1:2023 - BOLA
- API2:2023 - JWT 'none' algorithm
- API8:2023 - SQL/Command Injection
- API7:2023 - SSRF with metadata access

**High Priority:**
- API5:2023 - Dangerous HTTP methods (PUT/DELETE)
- API3:2023 - Mass assignment privilege escalation
- API8:2023 - API over HTTP

**Medium Priority:**
- API2:2023 - Long-lived JWT tokens
- API4:2023 - Missing rate limiting
- API8:2023 - Missing security headers

---

## 📈 Integration with CI/CD

### Automated Scanning Pipeline

1. **Trigger Scans via API**
```bash
curl -X POST https://enterprise.burp.example.com/api/v1/scans \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "API Security Scan",
    "urls": ["https://api.example.com"],
    "scan_configuration_ids": ["your-config-id"],
    "extensions": ["Advanced API Security Scanner"]
  }'
```

2. **Monitor Scan Progress**
```bash
curl https://enterprise.burp.example.com/api/v1/scans/{scan_id} \
  -H "Authorization: Bearer YOUR_API_KEY"
```

3. **Retrieve Results**
```bash
curl https://enterprise.burp.example.com/api/v1/scans/{scan_id}/issues \
  -H "Authorization: Bearer YOUR_API_KEY"
```

---

## 🐛 Troubleshooting

### Extension Not Loading

**Check Extension Logs:**
1. Go to Burp Enterprise → Settings → Extensions
2. View extension details
3. Check load status and error messages

**Expected Load Message:**
```
====================================
Advanced API Security Scanner v1.0.0
OWASP API Security Top 10 2023
Compatible with Burp Suite Professional & Enterprise Edition
====================================
Extension loaded successfully!
Mode: Headless (Enterprise)
```

### No Issues Detected

**Verify:**
1. ✅ Extension is enabled
2. ✅ Scan includes both Active and Passive checks
3. ✅ Target URLs are in scope
4. ✅ API endpoints are being scanned (check scan log)

**Common Causes:**
- Scan only ran passive checks (enable active scanning)
- Scope too restrictive
- API requires authentication (provide credentials in scan config)

### Issues Not Appearing

**Check Issue Filters:**
- Ensure filters include all severity levels
- Check if issues are being consolidated
- Verify scan completed successfully

---

## 📚 Additional Resources

### Burp Enterprise Documentation
- [Extension Management](https://portswigger.net/burp/documentation/enterprise/managing-extensions)
- [Scan Configuration](https://portswigger.net/burp/documentation/enterprise/scans)
- [API Reference](https://portswigger.net/burp/documentation/enterprise/api)

### OWASP API Security
- [OWASP API Security Top 10 2023](https://owasp.org/www-project-api-security/)
- [API Security Checklist](https://github.com/owasp/api-security)

---

## 🔄 Updating the Extension

To update to a newer version:

1. Build new JAR with latest code
2. Upload to Burp Enterprise
3. Old version will be automatically replaced
4. Restart active scans to use new version

---

## 💡 Best Practices

### For Accurate Results

1. **Provide Authentication**
   - Configure valid credentials in scan settings
   - Extension needs authenticated access to test authorization issues

2. **Import API Specifications**
   - Upload OpenAPI/Swagger files
   - Helps extension understand API structure

3. **Run Thorough Scans**
   - Use "Thorough" scan speed for comprehensive coverage
   - Allow sufficient time for active testing

4. **Review All Severities**
   - Don't ignore Information/Low severity issues
   - They often indicate broader security problems

### For Development Teams

1. **Integrate Early**
   - Run scans on every API deployment
   - Catch issues before production

2. **Set Thresholds**
   - Block deployments if Critical/High issues found
   - Create tickets for Medium severity issues

3. **Track Progress**
   - Monitor issue trends over time
   - Measure security improvement

---

## 📞 Support

For issues specific to:
- **Extension:** Check GitHub issues
- **Burp Enterprise:** Contact PortSwigger support
- **OWASP Standards:** Refer to OWASP documentation

---

## ✅ Verification Checklist

Before running production scans:

- [ ] Extension loaded successfully in Burp Enterprise
- [ ] Scan configuration includes Active + Passive checks
- [ ] API endpoints are in scope
- [ ] Authentication credentials configured (if required)
- [ ] Test scan completed successfully
- [ ] Issues appearing with OWASP 2023 naming format
- [ ] Issue severity and confidence levels appropriate
- [ ] Results exported and reviewed by security team

---

**Version:** 1.0.0
**Last Updated:** 2025-11-26
**Compatibility:** Burp Suite Enterprise Edition 2023.x and later
