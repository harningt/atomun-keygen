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

import spock.lang.Specification
import spock.lang.Unroll
import us.eharning.atomun.keygen.internal.spi.bip0032.Hash
import us.eharning.atomun.keygen.path.BIP0032Path
import us.eharning.atomun.keygen.spi.BuilderParameter

import java.security.Provider
import java.security.Security
import java.util.concurrent.Callable

/**
 * Test case specification to try to hit odd edge cases.
 */
class EdgeCaseSpecification extends Specification {
    @Unroll
    def "missing algorithm results in error on hash ops like #name"(String name, Callable<Void> op) {
        given:
        Provider[] providerBackup = Security.providers;
        for (Provider provider : Security.providers.reverse()) {
            Security.removeProvider(provider.getName())
        }
        when:
        op()
        then:
        thrown(Error)
        cleanup:
        for (Provider provider : providerBackup) {
            Security.addProvider(provider);
        }
        where:
        name | op
        "hash([])"      | { Hash.hash(new byte[0]) }
        "hash([],i,i)"  | { Hash.hash(new byte[2], 1, 1) }
        "keyHash([])"   | { Hash.keyHash(new byte[0]) }
    }

    def "unknown seed parameters cause builder problems"(KeyGeneratorAlgorithm algorithm) {
        given:
        SeedParameter seedParameter = new SeedParameter() {}
        KeyGeneratorBuilder builder = KeyGeneratorBuilder.newBuilder(algorithm)
        when:
        builder.setSeed(seedParameter)
        then:
        thrown(IllegalArgumentException)
        where:
        _ | algorithm
        _ | StandardKeyGeneratorAlgorithm.BIP0032
        _ | StandardKeyGeneratorAlgorithm.BIP0044
    }
    def "unknown path parameters cause builder problems"(KeyGeneratorAlgorithm algorithm) {
        given:
        PathParameter pathParameter = new PathParameter() {}
        KeyGeneratorBuilder builder = KeyGeneratorBuilder.newBuilder(algorithm)
        when:
        builder.setPath(pathParameter)
        then:
        thrown(IllegalArgumentException)
        where:
        _ | algorithm
        _ | StandardKeyGeneratorAlgorithm.BIP0032
        _ | StandardKeyGeneratorAlgorithm.BIP0044
    }
    /* TODO: MOVE TO BIP44 path builder test */
    def "non-BIP44 BIP0032 path parameter causes BIP0044 builder problems at build time"() {
        given:
        PathParameter pathParameter = BIP0032Path.fromSegments(1,2,3)
        KeyGeneratorBuilder builder = KeyGeneratorBuilder.newBuilder(StandardKeyGeneratorAlgorithm.BIP0044)
        when:
        builder.setPath(pathParameter)
        builder.build()
        then:
        thrown(IllegalArgumentException)
    }
}
