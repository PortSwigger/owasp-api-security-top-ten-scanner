# Build Instructions - Advanced API Security Scanner

## Prerequisites

1. **Java Development Kit (JDK) 11 or higher**
   ```bash
   # Check Java version
   java -version

   # Should output: java version "11.0.x" or higher
   ```

   If not installed, download from:
   - [Oracle JDK](https://www.oracle.com/java/technologies/downloads/)
   - [OpenJDK](https://openjdk.org/)

2. **Apache Maven 3.6+**
   ```bash
   # Check Maven version
   mvn -version

   # Should output: Apache Maven 3.6.x or higher
   ```

   If not installed, download from: https://maven.apache.org/download.cgi

3. **Burp Suite Professional**
   - Download from: https://portswigger.net/burp/pro

## Building the Extension

### Step 1: Navigate to Project Directory
```bash
cd /Users/rob.cornes/claude/burp-api-scanner
```

### Step 2: Clean Previous Builds (if any)
```bash
mvn clean
```

### Step 3: Compile and Package
```bash
mvn package
```

This will:
- Download all dependencies (Burp Extender API, Gson, JWT library)
- Compile all Java source files
- Run any tests (if present)
- Package everything into a JAR with dependencies
- Output: `target/burp-api-scanner-1.0.0-jar-with-dependencies.jar`

### Step 4: Verify Build
```bash
ls -lh target/burp-api-scanner-1.0.0-jar-with-dependencies.jar
```

You should see a JAR file around 2-5 MB in size.

## Loading into Burp Suite

### Method 1: Via Burp UI (Recommended)

1. **Open Burp Suite Professional**

2. **Navigate to Extensions:**
   - Click on "Extensions" tab (or "Extender" in older versions)
   - Go to "Extensions" sub-tab

3. **Add Extension:**
   - Click "Add" button
   - Extension Type: Select "Java"
   - Extension File: Browse to:
     ```
     /Users/rob.cornes/claude/burp-api-scanner/target/burp-api-scanner-1.0.0-jar-with-dependencies.jar
     ```
   - Click "Next"

4. **Verify Loading:**
   - Check "Output" tab for extension loading messages
   - Should see:
     ```
     ====================================
     Advanced API Security Scanner v1.0.0
     ====================================
     Features:
       - HTTP Method Fuzzing ...
       - OWASP API Security Top 10 Checks
       ...
     Extension loaded successfully!
     ```

5. **Verify Tab Appears:**
   - Look for new "API Scanner" tab in main Burp window

### Method 2: Command Line Loading

You can also start Burp with the extension pre-loaded:

```bash
java -jar burpsuite_pro.jar --disable-extensions --add-extension=/path/to/burp-api-scanner-1.0.0-jar-with-dependencies.jar
```

## Troubleshooting Build Issues

### Issue: Maven Not Found
```
-bash: mvn: command not found
```

**Solution:** Install Maven or add it to your PATH:
```bash
export PATH=/path/to/maven/bin:$PATH
```

### Issue: Java Version Too Old
```
[ERROR] Source option 11 is no longer supported. Use 17 or later.
```

**Solution:** Update Java to version 11 or higher.

### Issue: Dependency Download Failures
```
[ERROR] Failed to download artifact...
```

**Solution:**
1. Check internet connection
2. Clear Maven cache:
   ```bash
   rm -rf ~/.m2/repository
   mvn package
   ```

### Issue: Burp API Not Found
```
[ERROR] Cannot resolve burp.extender:burp-extender-api
```

**Solution:** The Burp API should download automatically. If it fails, you can manually install it:
1. Download from: https://portswigger.net/burp/extender/api
2. Install to local Maven repo:
   ```bash
   mvn install:install-file \
     -Dfile=burp-extender-api-2.3.jar \
     -DgroupId=net.portswigger.burp.extender \
     -DartifactId=burp-extender-api \
     -Dversion=2.3 \
     -Dpackaging=jar
   ```

### Issue: Extension Fails to Load in Burp

**Check the Extender Output:**
1. In Burp, go to Extensions → Extender → Output
2. Look for error messages

**Common causes:**
- **Wrong Java version:** Extension requires Java 11+
- **Missing dependencies:** Rebuild with `mvn clean package`
- **Corrupted JAR:** Delete and rebuild
- **Burp version:** Requires Burp Suite Professional (not Community Edition)

## Development Build

For development with auto-reload:

```bash
# Terminal 1: Watch for changes and rebuild
mvn compile

# Terminal 2: Run tests
mvn test

# Full rebuild on changes
mvn clean compile package
```

## Verifying Extension Functionality

After loading, verify the extension works:

1. **Check Console Output:**
   ```
   Extension loaded successfully!
   ```

2. **Verify Tab Exists:**
   - "API Scanner" tab should appear

3. **Test with Sample Request:**
   - Make a request to any API endpoint
   - Check "API Scanner" tab for discovered endpoints

4. **Run Active Scan:**
   - Right-click any API request
   - Select "Actively scan this request"
   - Check Issues tab for findings

## Building for Distribution

To create a release build:

```bash
# Clean build with all tests
mvn clean test package

# Verify JAR contents
jar -tf target/burp-api-scanner-1.0.0-jar-with-dependencies.jar | grep BurpExtender

# Should show: com/security/burp/BurpExtender.class
```

## Continuous Integration

For automated builds (CI/CD):

```yaml
# Example GitHub Actions
name: Build Burp Extension
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-java@v2
        with:
          java-version: '11'
      - run: cd burp-api-scanner && mvn clean package
      - uses: actions/upload-artifact@v2
        with:
          name: burp-extension
          path: burp-api-scanner/target/*.jar
```

## File Structure

After successful build:

```
burp-api-scanner/
├── src/
│   └── main/
│       └── java/
│           └── com/
│               └── security/
│                   └── burp/
│                       ├── BurpExtender.java (Entry point)
│                       ├── scanner/
│                       ├── checks/
│                       ├── model/
│                       └── ui/
├── target/
│   ├── classes/ (compiled .class files)
│   ├── burp-api-scanner-1.0.0.jar (without dependencies)
│   └── burp-api-scanner-1.0.0-jar-with-dependencies.jar ← Load this in Burp
├── pom.xml (Maven config)
└── README.md
```

## Next Steps

After successful build and load:
1. Read the [README.md](README.md) for usage instructions
2. Test against the included vulnerable API server
3. Run against your target APIs (with authorization!)

## Support

If you encounter build issues not covered here:
1. Check Maven output for specific errors
2. Verify all prerequisites are met
3. Try a clean rebuild: `mvn clean package`
4. Check Burp's Extender Output tab for runtime errors
