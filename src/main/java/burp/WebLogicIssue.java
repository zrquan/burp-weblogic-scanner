package burp;

import java.net.URL;

public class WebLogicIssue implements IScanIssue {
    private IHttpService httpService;
    private URL url;
    private String name;
    private String detail;
    private String severity;

    public WebLogicIssue(IHttpRequestResponse checkReqResp, String name, String detail, String severity) {
        this.httpService = checkReqResp.getHttpService();
        this.url = Utilities.helpers.analyzeRequest(checkReqResp).getUrl();
        this.name = name;
        this.detail = detail;
        this.severity = severity;
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
        return 0;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return "Certain";
    }

    @Override
    public String getIssueBackground() {
        return null;
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
        return new IHttpRequestResponse[0];
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }
}
