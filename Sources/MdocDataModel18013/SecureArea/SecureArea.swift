/*
Copyright (c) 2023 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else 
import Crypto
#endif 
#if canImport(Security)
import Security
#endif 

// Abstraction of a secure area for performing cryptographic operations
// 2 default iOS secure areas will be provided (SecureEnclave, Software)
public protocol SecureArea: Sendable {
    /// name of the secure area. Used to lookup an instance in the registry of secure-areas
    static var name: String { get }
    /// default Elliptic Curve type for the secure area
    static var defaultEcCurve: CoseEcCurve { get }
    /// reference to the secure-key-storage abstraction
    var storage: any SecureKeyStorage { get }
    /// initialize with a secure-key storage object
    init(storage: any SecureKeyStorage)
    /// make key and return the  public key.
    /// The public key pair is passed to the Open4VCI module
    func createKey(id: String, keyOptions: KeyOptions?) throws -> CoseKey
    /// unlock key
    func unlockKey(id: String) async throws -> Data?
    /// delete key with id
    func deleteKey(id: String) throws
    /// compute signature
    func signature(id: String, algorithm: SigningAlgorithm, dataToSign: Data, unlockData: Data?) throws -> (raw: Data, der: Data)
    /// make key-agreement (shared secret) with other public key (used for encryption and mac computations)
    func keyAgreement(id: String, publicKey: CoseKey, unlockData: Data?) throws -> SharedSecret
    /// returns information about the key with the given id
    func getKeyInfo(id: String) throws -> KeyInfo
}

extension SecureArea {
    /// default Elliptic Curve type
    public static var defaultEcCurve: CoseEcCurve { .P256 }
    /// default name
    public static var name: String { String(describing: Self.self).replacingOccurrences(of: "SecureArea", with: "") }
    // by default do nothing. For secure enclave or keychain keys, the system will handle unlocking
    public func unlockKey(id: String) async throws -> Data? {
        logger.info("Unlocking key with id: \(id)")
        return nil
    }
    
}


