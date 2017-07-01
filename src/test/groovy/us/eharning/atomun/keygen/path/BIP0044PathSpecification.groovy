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

package us.eharning.atomun.keygen.path

import org.bouncycastle.jce.provider.BouncyCastleProvider
import spock.lang.Specification

import java.security.Security

/**
 * Generic building test.
 */
class BIP0044PathSpecification extends Specification {
    public static final int BITCOIN = (int) 0x80000000
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    def "not BIP0044 unparsed paths"(String path) {
        when:
        BIP0044Path.fromBIP0032String(path)

        then:
        thrown(IllegalArgumentException)

        where:
        path | _
        "m" | _
        "m/44" | _
        "m/43'" | _
    }

    def "not BIP0044 parsed paths"(String path) {
        given:
        BIP0032Path parsedPath = BIP0032Path.fromBIP0032String(path)
        when:
        BIP0044Path.fromPath(parsedPath)

        then:
        thrown(IllegalArgumentException)

        where:
        path | _
        "m" | _
        "m/44" | _
        "m/43'" | _
    }

    def "incomplete path generate test"(Integer coinType, Integer account, Integer chain, Integer address) {
        given:
        BIP0044Path.Builder builder = new BIP0044Path.Builder()
        if (null != coinType) builder.setCoinType(coinType)
        if (null != account) builder.setAccount(account)
        if (null != chain) builder.setChain(chain)
        if (null != address) builder.setAddress(address)

        when:
        builder.build()

        then:
        thrown(IllegalStateException)

        where:
        coinType | account | chain | address
        null     | 0       | 0     | 1
        BITCOIN  | null    | 0     | 1
        BITCOIN  | 0       | null  | 1
        null     | null    | null  | 1
    }

    def "partial path generation test"(String path, Integer coinType, Integer account, Integer chain, Integer address) {
        given:
        BIP0044Path.Builder builder = new BIP0044Path.Builder()
        if (null != coinType) builder.setCoinType(coinType)
        if (null != account) builder.setAccount(account)
        if (null != chain) builder.setChain(chain)
        if (null != address) builder.setAddress(address)

        BIP0032Path matchPath = builder.build()

        expect:
        path == matchPath.toString()

        where:
        path               | coinType | account | chain | address
        "m/44'/0'/0'/0/1"  | BITCOIN  | 0       | 0     | 1
        "m/44'/0'/0'/1"    | BITCOIN  | 0       | 1     | null
        "m/44'/0'/0'"      | BITCOIN  | 0       | null  | null
        "m/44'/0'"         | BITCOIN  | null    | null  | null
        "m/44'"            | null     | null    | null  | null
    }

    def "chain path generation test"(String path, int account, int chain) {
        given:
        BIP0044Path.Builder builder = new BIP0044Path.Builder()
        builder.setCoinType(BITCOIN)
                .setAccount(account)
                .setChain(chain)

        BIP0032Path matchPath = builder.build()

        expect:
        path == matchPath.toString()

        where:
        path               | account | chain
        "m/44'/0'/0'/0"    | 0       | 0
        "m/44'/0'/0'/1"    | 0       | 1
        "m/44'/0'/0'/1"    | 0       | 1
        "m/44'/0'/392'/0"  | 392     | 0
    }

    def "full path generation test"(String path, int account, int chain, int address) {
        given:
        BIP0044Path.Builder builder = new BIP0044Path.Builder()
        builder.setCoinType(BITCOIN)
                .setAccount(account)
                .setChain(chain)
                .setAddress(address)

        BIP0032Path matchPath = builder.build()

        expect:
        path == matchPath.toString()

        where:
        path                 | account | chain  | address
        "m/44'/0'/0'/0/1"    | 0       | 0      | 1
        "m/44'/0'/0'/1/1"    | 0       | 1      | 1
        "m/44'/0'/0'/1/392"  | 0       | 1      | 392
        "m/44'/0'/392'/0/1"  | 392     | 0      | 1
    }
}
