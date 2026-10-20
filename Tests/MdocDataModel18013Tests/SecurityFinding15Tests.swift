import Foundation
import Testing
import SwiftCBOR
@testable import MdocDataModel18013

struct SecurityFinding15Tests {
    @Test func rejectsDuplicateKeysAndTrailingBytes() throws {
        for bytes: [UInt8] in [
            [0xa2, 0x01, 0x00, 0x01, 0x01],
            [0xa2, 0x01, 0x00, 0x18, 0x01, 0x01],
            [0xbf, 0x61, 0x61, 0x00, 0x7f, 0x61, 0x61, 0xff, 0x01, 0xff],
            [0xa2, 0xf9, 0x3c, 0x00, 0x00, 0xfa, 0x3f, 0x80, 0x00, 0x00, 0x01],
            [0xa2, 0x62, 0xc3, 0xa9, 0x00, 0x63, 0x65, 0xcc, 0x81, 0x01],
            [0x00, 0x01], [0xa0, 0xff]
        ] {
            #expect(throws: MdocValidationError.self) { try MdocCBOR.decode(bytes) }
        }
        #expect(try MdocCBOR.decode([0xa2, 0x01, 0x00, 0x02, 0x01]) != nil)
        #expect(try MdocCBOR.decode([0xbf, 0x01, 0x00, 0xff]) != nil)
    }
    @Test func dateMapKeysCannotTrapNormalization() throws {
        let hugeDate: [UInt8] = [0xa1, 0xc1, 0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00]
        let nanDate: [UInt8] = [0xa1, 0xc1, 0xfb, 0x7f, 0xf8, 0, 0, 0, 0, 0, 0, 0]
        #expect(try MdocCBOR.decode(hugeDate) != nil)
        #expect(try MdocCBOR.decode(nanDate) != nil)
    }
    @Test func modelAndEmbeddedBoundariesAreStrict() throws {
        let valid = Array(MdocDataModel18013Tests.AnnexdTestData.d411)
        #expect(throws: MdocValidationError.self) { try DeviceRequest(data: valid + [0]) }
        #expect(CBOR.byteString([0xa2, 1, 0, 1, 1]).decodeBytestring() == nil)
        let response = Array(MdocDataModel18013Tests.AnnexdTestData.d412)
        _ = try DeviceResponse(data: response)
        #expect(throws: MdocValidationError.self) { try DeviceResponse(data: response + [0]) }
    }
    @Test func malformedProtectedHeadersFailClosed() throws {
        for bytes: [UInt8] in [[0xa2, 1, 0x26, 1, 0x26], [0xa1, 1, 0x26, 0]] {
            let cbor: CBOR = .array([.byteString(bytes), .map([33: .byteString([1])]), .null, .byteString([1])])
            #expect(Cose(type: .sign1, cbor: cbor) == nil)
            #expect(throws: MdocValidationError.self) { try ReaderAuth(cbor: cbor) }
        }
        let emptyHeader: CBOR = .array([.byteString([]), .map([33: .byteString([1])]), .null, .byteString([1])])
        #expect(Cose(type: .sign1, cbor: emptyHeader) != nil)
    }

}
