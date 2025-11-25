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

public class SQLiModule implements VulnerabilityModule {
    private MontoyaApi api;

    public SQLiModule(final MontoyaApi api) {
        this.api = api;

        this.api.logging().logToOutput("SQLi Module Loaded");
    }

    @Override
    public boolean test(HttpRequestToBeSent request) {
        this.api.logging().logToOutput(Util.formatted("Testing on " + request.url()));

        // Prepare Single quote injections
        List<SQLiRequest> singleQuoteInjectionRequests = generateSingleQuoteInjectionRequests(request);
        if (singleQuoteInjectionRequests.isEmpty()) {
            return false;
        }

        for (var injectionRequest : singleQuoteInjectionRequests) {
            HttpRequest requestToSend = injectionRequest.request;

            HttpRequestResponse sentRequest = api.http().sendRequest(requestToSend);

            // Check if succeeded
            if (checkSingleQuoteInjectionSucceeded(sentRequest)) {
                // Create an issue
                String detail = String.format("""
            A single quote was appended to %s parameter of this request and it lead to a internal server error.<br>
            This might be an indication for a SQL Injection.
            """, injectionRequest.modifiedParameter);
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

        // Prepare Double quote injections

        // Check if succeeded

        return false;
    }

    private List<SQLiRequest> generateSingleQuoteInjectionRequests(final HttpRequestToBeSent request) {
        // Inject single quote in query parameters
        this.api.logging().logToOutput(
                Util.formatted(request.parameters().toString())
        );

        List<SQLiRequest> newRequests = new ArrayList<>();

        for (var parsedHttpParameter : request.parameters()) {
            String newValue = parsedHttpParameter.value() + "'";
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

    private boolean checkSingleQuoteInjectionSucceeded(HttpRequestResponse requestResponse) {
        if (requestResponse.response().statusCode() == 500) {
            return true;
        }

        return false;
    }
}
