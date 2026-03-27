# Enhanced Logging Guide - Burp API Scanner v1.0.0

## What Was Added

Comprehensive logging has been added to help debug authentication errors and track all HTTP traffic.

## New Logging Features

### 1. Request Logging

Every API request now logs:

```
═══════════════════════════════════════
[REQUEST] POST http://3.255.170.95:5002/users/v1/login
═══════════════════════════════════════
  ✓ Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVC...
  ✓ Content-Type: application/json
  📄 Body: {"username":"name1","password":"pass1"}
```

**What's logged:**
- HTTP method and full URL
- Authorization header (first 50 chars shown for security)
- Content-Type header
- Request body (first 200 chars for POST/PUT/PATCH)
- Warning if Authorization header is missing
- Warning if Authorization header doesn't use Bearer token

### 2. Response Logging

Every API response now logs:

```
[RESPONSE] ✅ 200 (SUCCESS) for http://3.255.170.95:5002/users/v1
```

**Status indicators:**
- ✅ 2xx = Success
- 🔒 401/403 = Auth errors
- ⚠️ 4xx = Client errors
- ❌ 5xx = Server errors
- ↪️ 3xx = Redirects

### 3. Authentication Error Details

When a 401 or 403 is detected:

```
─────────────────────────────────────
🔒 AUTHENTICATION/AUTHORIZATION ERROR DETECTED
─────────────────────────────────────
  Error Response: {"status":"fail","message":"Invalid token. Please log in again."}
  WWW-Authenticate: Bearer realm="VAmPI"

  💡 Troubleshooting:
  1. Check if Authorization header is present in request
  2. Verify token is valid and not expired
  3. Confirm token format (e.g., 'Bearer <token>')
  4. Check Burp's Match & Replace rules
  5. Verify Session Handling Rules are configured
─────────────────────────────────────
```

**What's logged:**
- Full error response body (first 500 chars)
- WWW-Authenticate header if present
- Automatic troubleshooting checklist

## How to Use

### 1. Load the Extension

```bash
cd /Users/rob.cornes/claude/burp-api-scanner
```

Load into Burp:
```
Extender → Extensions → Add
Extension type: Java
Extension file: target/burp-api-scanner-1.0.0-jar-with-dependencies.jar
```

### 2. Monitor the Output

Go to **Extender → Extensions → Select "Advanced API Security Scanner" → Output tab**

You'll see detailed logging for every request/response.

### 3. Debugging Authentication Errors

#### Scenario 1: No Authorization Header

If you see:
```
[REQUEST] GET http://3.255.170.95:5002/me
═══════════════════════════════════════
  ⚠️  WARNING: No Authorization header found

[RESPONSE] 🔒 401 (AUTH ERROR) for http://3.255.170.95:5002/me
```

**Problem:** Burp's Match & Replace rule isn't adding the Authorization header.

**Solution:**
- Check **Proxy → Options → Match & Replace**
- Verify the rule is enabled and applies to Scanner tool
- Ensure the pattern matches requests to the target URL

#### Scenario 2: Token Present but Getting 401

If you see:
```
[REQUEST] GET http://3.255.170.95:5002/me
═══════════════════════════════════════
  ✓ Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVC...

[RESPONSE] 🔒 401 (AUTH ERROR) for http://3.255.170.95:5002/me
  Error Response: {"status":"fail","message":"Signature expired. Please log in again."}
```

**Problem:** Token is expired (VAmPI tokens expire after 60 seconds!).

**Solution:**
- Get a fresh token: `curl -X POST http://3.255.170.95:5002/users/v1/login -H "Content-Type: application/json" -d '{"username":"name1","password":"pass1"}'`
- Update Match & Replace rule with new token
- Or configure Session Handling Rules to auto-refresh

#### Scenario 3: Token Format Wrong

If you see:
```
[REQUEST] GET http://3.255.170.95:5002/me
═══════════════════════════════════════
  ✓ Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVC...
  ⚠️  WARNING: Authorization header found but not Bearer token
```

**Problem:** Missing "Bearer " prefix.

**Solution:**
- Update Match & Replace rule to: `Authorization: Bearer YOUR_TOKEN`
- Not: `Authorization: YOUR_TOKEN`

## Testing the Logging

### Quick Test

1. **Test unauthenticated endpoint** (should work without token):
   ```bash
   curl http://3.255.170.95:5002/users/v1
   ```

   Expected log:
   ```
   [REQUEST] GET http://3.255.170.95:5002/users/v1
     ⚠️  WARNING: No Authorization header found
   [RESPONSE] ✅ 200 (SUCCESS) for ...
   ```

2. **Test authenticated endpoint without token** (should fail):
   ```bash
   curl http://3.255.170.95:5002/me
   ```

   Expected log:
   ```
   [REQUEST] GET http://3.255.170.95:5002/me
     ⚠️  WARNING: No Authorization header found
   [RESPONSE] 🔒 401 (AUTH ERROR) for ...
   🔒 AUTHENTICATION/AUTHORIZATION ERROR DETECTED
   ```

3. **Test with valid token** (should succeed):
   ```bash
   # Get token first
   TOKEN=$(curl -X POST http://3.255.170.95:5002/users/v1/login \
     -H "Content-Type: application/json" \
     -d '{"username":"name1","password":"pass1"}' | jq -r .auth_token)

   # Use token
   curl http://3.255.170.95:5002/me -H "Authorization: Bearer $TOKEN"
   ```

   Expected log:
   ```
   [REQUEST] GET http://3.255.170.95:5002/me
     ✓ Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVC...
   [RESPONSE] ✅ 200 (SUCCESS) for ...
   ```

## Troubleshooting Common Issues

### Issue: Too Much Logging

If the output is overwhelming, you can:
- Filter by searching for "AUTH ERROR" in the output tab
- Look for the "🔒" emoji to find auth issues quickly
- Search for specific URLs

### Issue: Not Seeing Logs

Check:
1. Extension is loaded and enabled in **Extender → Extensions**
2. You're looking at the correct extension's **Output** tab
3. Requests are going through Burp's proxy or scanner

### Issue: Extension Not Working with VAmPI

VAmPI-specific requirements:
- **Initialize database first**: `GET http://3.255.170.95:5002/createdb`
- **Tokens expire in 60 seconds** - must refresh frequently
- **Some endpoints don't need auth**: `/`, `/users/v1`, `/books/v1`
- **Most endpoints need auth**: `/me`, `/users/v1/{username}/email`, etc.

## Extension Location

**Built JAR**: `/Users/rob.cornes/claude/burp-api-scanner/target/burp-api-scanner-1.0.0-jar-with-dependencies.jar`

**Size**: ~1.5MB

**Compatible with**:
- Burp Suite Professional (Interactive)
- Burp Suite Enterprise (Headless/DAST)

## Next Steps

1. **Load the extension** into Burp Suite
2. **Configure authentication** (Match & Replace or Session Handling)
3. **Start scanning** your API
4. **Monitor the Output tab** for detailed logs
5. **Look for 🔒 emoji** to quickly find auth issues

## Questions or Issues?

The logging now shows exactly:
- Whether Authorization headers are present
- What the token looks like (first 50 chars)
- Response status codes with context
- Full error messages from the API
- Automatic troubleshooting tips

This should make it much easier to debug authentication issues!
