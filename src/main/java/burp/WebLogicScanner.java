package burp;

import probes.Probe;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;

public class WebLogicScanner implements ActionListener, Runnable {
    private final List<Probe> probes;
    private final List<IScanIssue> issues;
    private final IHttpRequestResponse requestResponse;

    public WebLogicScanner(List<Probe> probes, List<IScanIssue> issues, IHttpRequestResponse requestResponse) {
        this.probes = probes;
        this.issues = issues;
        this.requestResponse = requestResponse;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        // 在 Swing 的事件调度线程中不要直接发送请求，要分发给新的线程
        new Thread(this).start();
    }

    @Override
    public void run() {
        Utilities.out.println("[*] WebLogic scanner working...");

        if (!issues.isEmpty())
            issues.clear();

        for (Probe probe : probes) {
            IScanIssue result = probe.check(requestResponse);
            if (result != null) Utilities.callbacks.addScanIssue(result);
        }
        Utilities.out.println("[*] Finish!");
    }
}
