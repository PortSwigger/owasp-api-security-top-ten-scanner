package com.security.burp.model;

import burp.*;
import java.net.URL;

public class CustomScanIssue implements IScanIssue {

    private final IHttpService httpService;
    private final URL url;
    private final IHttpRequestResponse[] httpMessages;
    private final String name;
    private final String detail;
    private final String background;
    private final String severity;
    private final String confidence;

    public CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String background,
            String severity,
            String confidence) {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.background = background;
        this.severity = severity;
        this.confidence = confidence;
    }

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return name;
    }

    @Override
    public int getIssueType() {
        return 0x08000000; // Custom issue type (Burp uses this range for extensions)
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return confidence;
    }

    @Override
    public String getIssueBackground() {
        return background;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }
}
