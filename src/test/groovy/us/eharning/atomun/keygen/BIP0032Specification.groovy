/*
 * Copyright 2015, 2017 Thomas Harning Jr. <harningt@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package us.eharning.atomun.keygen

import org.bouncycastle.jce.provider.BouncyCastleProvider
import spock.lang.Specification
import spock.lang.Unroll
import us.eharning.atomun.core.ec.ECKey
import us.eharning.atomun.keygen.internal.spi.bip0032.BouncyCastleBIP0032NodeProcessor
import us.eharning.atomun.keygen.path.BIP0032Path

import java.security.Security

/**
 * Generic building test.
 */
class BIP0032Specification extends Specification {
    static final DeterministicKeyGenerator getRandom() {
        return KeyGeneratorBuilder.newBuilder(StandardKeyGeneratorAlgorithm.BIP0032).build()
    }
    static final DeterministicKeyGenerator getFromSeed(byte[] seed) {
        return KeyGeneratorBuilder.newBuilder(StandardKeyGeneratorAlgorithm.BIP0032).setSeed(ByteArraySeedParameter.getParameter(seed)).build()
    }
    static final DeterministicKeyGenerator getFromSeed(byte[] seed, BIP0032Path path) {
        return KeyGeneratorBuilder.newBuilder(StandardKeyGeneratorAlgorithm.BIP0032).setPath(path).setSeed(ByteArraySeedParameter.getParameter(seed)).build()
    }
    static final DeterministicKeyGenerator getFromSerialized(String serialized) {
        return KeyGeneratorBuilder.newBuilder(StandardKeyGeneratorAlgorithm.BIP0032).setSeed(SerializedSeedParameter.getParameter(serialized)).build()
    }
    static DeterministicKeyGenerator ekprivate = getRandom()
    static DeterministicKeyGenerator ekpublic = ekprivate.getPublic()

    def cleanup() {
        System.out.println(BouncyCastleBIP0032NodeProcessor.NODE_CACHE.stats())
    }

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    def "generation test"(int i) {
        given:
        ECKey fullControl = ekprivate.generate(i);
        ECKey readOnly = ekpublic.generatePublic(i);
        expect:
        fullControl.getPublic () ==  readOnly.getPublic()
        fullControl.getAddressHash () == readOnly.getAddressHash ()
        where:
        [ i ] << ([0..20].iterator())
    }

    def "test serialization"(BIP0032TestData.RootTestCase rootTestCase) {
        given:
        DeterministicKeyGenerator ekprivate = getFromSeed(rootTestCase.seed)
        DeterministicKeyGenerator ekpublic = ekprivate.getPublic ()
        expect:
        ekprivate.export() ==  rootTestCase.rootPrivateKey
        ekprivate.exportPublic() == rootTestCase.rootPublicKey
        ekpublic.export() == rootTestCase.rootPublicKey
        ekprivate.hasPrivate()
        !ekpublic.hasPrivate()
        where:
        rootTestCase << BIP0032TestData.ROOT_CASES
    }
    def "test round trip serialization"(BIP0032TestData.RootTestCase rootTestCase) {
        given:
        DeterministicKeyGenerator ekprivate = getFromSeed(rootTestCase.seed)
        DeterministicKeyGenerator ekpublic = ekprivate.getPublic ()
        expect:
        ekprivate.export() ==  rootTestCase.rootPrivateKey
        ekprivate.exportPublic() == rootTestCase.rootPublicKey
        ekpublic.export() == rootTestCase.rootPublicKey
        ekprivate == getFromSerialized(rootTestCase.rootPrivateKey)
        ekpublic == getFromSerialized(rootTestCase.rootPublicKey)
        where:
        rootTestCase << BIP0032TestData.ROOT_CASES
    }

    @Unroll
    def "test path-based derivation using builder: #testCase.name"(BIP0032TestData.DerivationTestCase testCase) {
        given:
        def path = BIP0032Path.fromBIP0032String(testCase.path)
        DeterministicKeyGenerator ek = KeyGeneratorBuilder.newBuilder(StandardKeyGeneratorAlgorithm.BIP0032).setPath(path).setSeed(ByteArraySeedParameter.getParameter(testCase.seed)).build()
        DeterministicKeyGenerator ep = ek.getPublic()
        expect:
        ek.export() == testCase.privateKey
        ek.exportPublic() == testCase.publicKey
        ep.export() == testCase.publicKey
        ek.hasPrivate()
        !ep.hasPrivate()
        where:
        testCase << BIP0032TestData.ALL_DERIVATION_CASES
    }

    @Unroll
    def "test path-based derivation using sequence builder: #testCase.name"(BIP0032TestData.DerivationTestCase testCase) {
        given:
        BIP0032Path.Builder pathBuilder = new BIP0032Path.Builder()
        for (BIP0032TestData.LocatorElement element: testCase.locator) {
            pathBuilder.addSegment(element.sequence, element.hardened)
        }
        def path = pathBuilder.build()
        DeterministicKeyGenerator ek = KeyGeneratorBuilder.newBuilder(StandardKeyGeneratorAlgorithm.BIP0032).setPath(path).setSeed(ByteArraySeedParameter.getParameter(testCase.seed)).build()
        DeterministicKeyGenerator ep = ek.getPublic()
        expect:
        ek.export() == testCase.privateKey
        ek.exportPublic() == testCase.publicKey
        ep.export() == testCase.publicKey
        ek.hasPrivate()
        !ep.hasPrivate()
        where:
        testCase << BIP0032TestData.ALL_DERIVATION_CASES
    }
}
