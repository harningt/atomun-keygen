package us.eharning.atomun.keygen

import com.google.common.collect.ImmutableList
import com.google.common.collect.Maps
import groovy.transform.Canonical
import org.yaml.snakeyaml.Yaml

/**
 * Manager of test cases for BIP0032.
 */
class BIP0032TestData {
    @Canonical
    static class RootTestCase {
        public String name;
        public byte[] seed;

        public void setSeed(String seed) {
            this.seed = seed.decodeHex()
        }

        public String rootPublicKey;
        public String rootPrivateKey;
    }

    static class LocatorElement {
        public int sequence;
        public boolean hardened;
    }
    @Canonical
    static class DerivationTestCase extends RootTestCase {
        public String path;
        public LocatorElement[] locator;
        public String publicKey;

        public String privateKey;
    }

    static List<RootTestCase> ROOT_CASES;
    static List<DerivationTestCase> ALL_DERIVATION_CASES;
    static {
        ImmutableList.Builder<RootTestCase> rootCaseBuilder = ImmutableList.builder()
        ImmutableList.Builder<DerivationTestCase> caseBuilder = ImmutableList.builder()
        new Yaml().loadAll(BIP0032TestData.class.getResourceAsStream("/BIP32.yaml")).each {
            def rootObject = Maps.newLinkedHashMap(it)
            rootObject.remove("derived")
            RootTestCase rootTestCase = rootObject as RootTestCase
            rootCaseBuilder.add(rootTestCase)
            it.derived.each {
                DerivationTestCase testCase = (rootObject + it) as DerivationTestCase
                caseBuilder.add(testCase)
            }
        }
        ROOT_CASES = rootCaseBuilder.build()
        ALL_DERIVATION_CASES = caseBuilder.build()

    }

}
