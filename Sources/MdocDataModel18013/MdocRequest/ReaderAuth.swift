/*
Copyright (c) 2026 European Commission

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
import SwiftCBOR

/// Reader authentication structure encoded as Cose Sign1
public struct ReaderAuth: Sendable {
	/// encoded data
    public let coseSign1: Cose
	/// one or more certificates
	public let x5chain: [[UInt8]]
}

extension ReaderAuth: CBORDecodable {
    public init(cbor: CBOR) throws(MdocValidationError) {
        // Preflight before Cose.init, which indexes the four COSE_Sign1 fields.
        guard case let .array(fields) = cbor, fields.count == 4,
              case let .byteString(protectedBytes) = fields[0],
              case let .map(unprotected) = fields[1], fields[2] == .null,
              case .byteString = fields[3],
              let decoded = try? CBOR.decode(protectedBytes), case let .map(protected) = decoded,
              case .negativeInt = protected[.unsignedInt(1)],
              let cose = Cose(type: .sign1, cbor: cbor) else { throw .invalidCbor("reader authentication") }
        coseSign1 = cose
        let label = CBOR.unsignedInt(33)
        guard !(protected[label] != nil && unprotected[label] != nil),
              let chain = protected[label] ?? unprotected[label] else { throw .invalidCbor("reader authentication x5chain") }
        switch chain {
        case .byteString(let bytes):
            guard !bytes.isEmpty else { throw .invalidCbor("reader authentication x5chain") }
            x5chain = [bytes]
        case .array(let entries):
            guard !entries.isEmpty else { throw .invalidCbor("reader authentication x5chain") }
            x5chain = try entries.map { entry throws(MdocValidationError) in
                guard case let .byteString(bytes) = entry, !bytes.isEmpty else {
                    throw .invalidCbor("reader authentication x5chain")
                }
                return bytes
            }
        default: throw .invalidCbor("reader authentication x5chain")
        }
    }
}

extension ReaderAuth: CBOREncodable {
	public func toCBOR(options: CBOROptions) -> CBOR {
        coseSign1.toCBOR(options: options)
    }
}
