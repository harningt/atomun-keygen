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

package us.eharning.atomun.keygen.internal.spi.bip0032

import spock.lang.Specification
import us.eharning.atomun.keygen.base.ECKey

import java.security.SecureRandom

/**
 * Tests for the various ECKeyPair implementations.
 */
class BouncyCastleECKeyPairSpecification extends Specification {
    static Random random = new SecureRandom()

    def "signature-verification passes"() {
        given:
        ECKey fullControl = BouncyCastleECKeyPair.createNew(false)
        ECKey readOnly = fullControl.public
        byte[] toSign = new byte[100];
        random.nextBytes (toSign);
        byte[] signature = fullControl.sign (toSign);
        expect:
        fullControl.getPublic () ==  readOnly.getPublic()
        fullControl.getAddressHash () == readOnly.getAddressHash ()

        readOnly.verify (toSign, signature)
        where:
        [ i ] << ([0..20].iterator())
    }
}