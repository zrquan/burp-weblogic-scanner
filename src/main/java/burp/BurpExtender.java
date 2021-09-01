package burp;

import probes.*;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IScannerCheck, IContextMenuFactory {

    private List<IScanIssue> issues = new ArrayList<>();
    private List<Probe> probes = new ArrayList<>();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        new Utilities(callbacks);

        callbacks.setExtensionName("WebLogic Scanner");
        Utilities.out.println("WebLogic Scanner");

        // load all probes
        probes.add(new Console());
        probes.add(new CVE_2014_4210());
        probes.add(new CVE_2015_4852());
        probes.add(new CVE_2016_0638());
        probes.add(new CVE_2016_3510());
        probes.add(new CVE_2017_3248());
        probes.add(new CVE_2017_3506());
        probes.add(new CVE_2017_10271());
        probes.add(new CVE_2019_2890());

        callbacks.registerScannerCheck(this);
        callbacks.registerContextMenuFactory(this);
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        if (!issues.isEmpty())
            issues.clear();

        for (Probe probe : probes) {
            IScanIssue result = probe.check(baseRequestResponse);
            if (result != null) issues.add(result);
        }

        return issues;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return existingIssue.getIssueName().equals(newIssue.getIssueName()) ? -1 : 0;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        JMenuItem actionButton = new JMenuItem("go");
        List<JMenuItem> menu = new ArrayList<>();

        // get first selected item
        IHttpRequestResponse targetItem = invocation.getSelectedMessages()[0];

        actionButton.addActionListener(new WebLogicScanner(probes, issues, targetItem));
        menu.add(actionButton);

        return menu;
    }
}