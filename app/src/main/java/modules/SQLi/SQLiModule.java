package modules.SQLi;


import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import modules.VulnerabilityModule;

import java.util.ArrayList;
import java.util.List;

class SQLiRequest {
    public HttpRequest request;
    public String modifiedParameter;

    public SQLiRequest(final HttpRequest request, final String modifiedParameter) {
        this.request = request;
        this.modifiedParameter = modifiedParameter;
    }
}

enum QuoteType {
    singleQuote,
    doubleQuote
}

public class SQLiModule implements VulnerabilityModule {
    private final MontoyaApi api;

    public SQLiModule(final MontoyaApi api) {
        this.api = api;

        this.api.logging().logToOutput("SQLi Module Loaded");
    }

    @Override
    public boolean test(HttpRequestToBeSent request) {
        this.api.logging().logToOutput(Util.formatted("Testing on " + request.url()));

        // Single quote injection
        boolean singleQuoteInjectionSucceeded = testQuoteInjection(request, QuoteType.singleQuote);
        if (singleQuoteInjectionSucceeded) return true;

        // Double quote injection
        boolean doubleQuoteInjectionSucceeded = testQuoteInjection(request, QuoteType.doubleQuote);
        if (doubleQuoteInjectionSucceeded) return true;

        return false;
    }

    private boolean testQuoteInjection(final HttpRequestToBeSent request, QuoteType type) {
        // Prepare Single quote injections
        List<SQLiRequest> quoteInjectionRequests = generateQuoteInjectionRequests(request, type);
        if (quoteInjectionRequests.isEmpty()) {
            return false;
        }

        for (var injectionRequest : quoteInjectionRequests) {
            HttpRequest requestToSend = injectionRequest.request;

            HttpRequestResponse sentRequest = api.http().sendRequest(requestToSend);

            // Check if succeeded
            if (checkQuoteInjectionSucceeded(sentRequest)) {
                // Create an issue
                String detail = String.format("""
            A %s quote was appended to <b>%s</b> parameter of this request and it lead to a internal server error.<br>
            This might be an indication for a SQL Injection.
            """, (type == QuoteType.singleQuote ? "single quote" : "double quote"), injectionRequest.modifiedParameter);

                AuditIssue issue = AuditIssue.auditIssue(
                        "SQL Injection detected",
                        detail,
                        null,
                        request.url(),
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.FIRM,
                        null,
                        null,
                        AuditIssueSeverity.INFORMATION,
                        sentRequest
                );

                this.api.siteMap().add(issue);
                return true;
            }
        }

        return false;
    }

    private List<SQLiRequest> generateQuoteInjectionRequests(final HttpRequestToBeSent request, QuoteType type) {
        // Inject single quote in query parameters
        this.api.logging().logToOutput(
                Util.formatted(request.parameters().toString())
        );

        List<SQLiRequest> newRequests = new ArrayList<>();

        for (var parsedHttpParameter : request.parameters()) {
            String newValue = parsedHttpParameter.value() + (type == QuoteType.singleQuote ? "'" : "\"");
            HttpParameter parameter = HttpParameter.parameter(parsedHttpParameter.name(), newValue, parsedHttpParameter.type());

            newRequests.add(
                    new SQLiRequest(
                            request
                                .withUpdatedParameters(parameter)
                                .withAddedHeader("X-Internal-Request", "True"),
                            parameter.name()
                    )
            );
        }

        return newRequests;
    }

    private boolean checkQuoteInjectionSucceeded(HttpRequestResponse requestResponse) {
        if (requestResponse.response().statusCode() == 500) {
            return true;
        }

        return false;
    }
}
