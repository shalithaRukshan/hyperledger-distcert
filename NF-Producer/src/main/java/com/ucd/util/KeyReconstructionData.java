/**
 *  Copyright 2016 TrustPoint Innovation Technologies, Ltd.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.ucd.util;

/**
 * Container for key reconstruction data generated by the Elliptic Curve Qu-Vanstone (ECQV) scheme.
 */
public class KeyReconstructionData {
  private final byte[] publicKeyReconstructionData;
  private final byte[] privateKeyReconstructionData;

  /**
   * Creates a new instance.
   *
   * @param publicKeyData Reconstruction data for the public key.
   * @param privateKeyData Reconstruction data for the private key.
   */
  public KeyReconstructionData(byte[] publicKeyData, byte[] privateKeyData) {
    publicKeyReconstructionData = new byte[publicKeyData.length];
    System.arraycopy(publicKeyData, 0, publicKeyReconstructionData, 0, publicKeyData.length);

    privateKeyReconstructionData = new byte[privateKeyData.length];
    System.arraycopy(privateKeyData, 0, privateKeyReconstructionData, 0, privateKeyData.length);
  }

  public byte[] getPublicKeyReconstructionData() {
    return publicKeyReconstructionData;
  }

  public byte[] getPrivateKeyReconstructionData() {
    return privateKeyReconstructionData;
  }
}
