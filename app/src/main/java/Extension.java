import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;

import java.util.ArrayList;
import java.util.List;

import modules.SQLi.SQLiModule;
import modules.VulnerabilityModule;

public class Extension implements BurpExtension {
    public static List<VulnerabilityModule> modules = new ArrayList<>();

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        montoyaApi.extension().setName("My Extension");

        // Load Modules
        modules.add(new SQLiModule(montoyaApi));

        // Add proxy listeners
        montoyaApi.http().registerHttpHandler(new CustomHttpHandler(montoyaApi));
    }
}

class CustomHttpHandler implements HttpHandler {
    private final MontoyaApi api;

    public CustomHttpHandler(final MontoyaApi api) {
        this.api = api;
    }

    // Will run when a request is being sent
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        // Skip requests made by the extension itself
        if (request.hasHeader("X-Internal-Request")) return null;

        new Thread(() -> {
            Extension.modules.forEach(module -> {
                module.test(request);
            });
        }).start();

        return null;
    }

    // Will run when a response to a request is being received
    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        return null;
    }
}
