/*
 * Copyright 2015 Thomas Harning Jr. <harningt@gmail.com>
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

import groovy.json.JsonSlurper
import org.bouncycastle.jce.provider.BouncyCastleProvider
import spock.lang.Specification
import spock.lang.Unroll
import us.eharning.atomun.keygen.base.ECKey
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
    static def BIP32 = new JsonSlurper().parse(BIP0032Specification.class.getResource("/BIP32.json"))

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

    def "test serialization"(def key) {
        given:
        DeterministicKeyGenerator ekprivate = getFromSeed(key.seed.decodeHex())
        DeterministicKeyGenerator ekpublic = ekprivate.getPublic ()
        expect:
        ekprivate.export() ==  key.private
        ekprivate.exportPublic() == key.public
        ekpublic.export() == key.public
        ekprivate.hasPrivate()
        !ekpublic.hasPrivate()
        where:
        key << BIP32
    }
    def "test round trip serialization"(def key) {
        given:
        DeterministicKeyGenerator ekprivate = getFromSeed(key.seed.decodeHex())
        DeterministicKeyGenerator ekpublic = ekprivate.getPublic ()
        expect:
        ekprivate.export() ==  key.private
        ekprivate.exportPublic() == key.public
        ekpublic.export() == key.public
        ekprivate == getFromSerialized(key.private)
        ekpublic == getFromSerialized(key.public)
        where:
        key << BIP32
    }

    @Unroll
    def "test path-based derivation using builder"(String seed, def derived) {
        given:
        def path = BIP0032Path.fromBIP0032String(derived.path)
        DeterministicKeyGenerator ek = KeyGeneratorBuilder.newBuilder(StandardKeyGeneratorAlgorithm.BIP0032).setPath(path).setSeed(ByteArraySeedParameter.getParameter(seed.decodeHex())).build()
        DeterministicKeyGenerator ep = ek.getPublic()
        expect:
        ek.export() == derived.private
        ek.exportPublic() == derived.public
        ep.export() == derived.public
        ek.hasPrivate()
        !ep.hasPrivate()
        where:
        [ seed, derived ] << getPairs()
    }

    private static def getPairs() {
        List objects = new ArrayList()
        for (def key: BIP32) {
            for (def derived: key.derived) {
                objects.add([
                    key.seed,
                    derived
                ]);
            }
        }
        return objects
    }
}