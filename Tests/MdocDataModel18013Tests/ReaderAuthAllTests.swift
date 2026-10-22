import Foundation
import Testing
import SwiftCBOR
@testable import MdocDataModel18013

struct ReaderAuthAllTests {
    func signature(protectedChain: Bool = false, chain: CBOR = .byteString([1])) -> CBOR {
        var header: CBOR = .map([1: .negativeInt(6)])
        if protectedChain { header[33] = chain }
        return .array([.byteString(header.encode()), protectedChain ? .map([:]) : .map([33: chain]), .null, .byteString([0])])
    }
    func request(auth: CBOR, info: [UInt8]? = nil, version: String = "1.1") -> CBOR {
        let items: CBOR = .map([.utf8String("docType"): .utf8String("mdl"), .utf8String("nameSpaces"): .map([.utf8String("ns"): .map([.utf8String("field"): .boolean(false)])])])
        var result: CBOR = .map([.utf8String("version"): .utf8String(version), .utf8String("docRequests"): .array([
            .map([.utf8String("itemsRequest"): items.taggedEncoded])]), .utf8String("readerAuthAll"): auth])
        if let info { result["deviceRequestInfo"] = .tagged(.encodedCBORDataItem, .byteString(info)) }
        return result
    }
    @Test func originalDeviceInfoBytesArePreservedDuringRoundTrip() throws {
        // Indefinite-length map with a noncanonical integer: typed re-encoding changes it.
        let bytes: [UInt8] = [0xbf, 0x61, 0x78, 0x18, 0x01, 0xff]
        let parsed = try DeviceRequest(cbor: request(auth: .array([signature()]), info: bytes))
        #expect(parsed.deviceRequestInfoRawData == bytes)
        #expect(parsed.toCBOR(options: CBOROptions())["deviceRequestInfo"] == .tagged(.encodedCBORDataItem, .byteString(bytes)))
    }
    @Test func supportsProtectedAndUnprotectedCertificateChains() throws {
        for protected in [true, false] {
            let parsed = try DeviceRequest(cbor: request(auth: .array([signature(protectedChain: protected)])))
            #expect(parsed.readerAuthAll?.first?.x5chain == [[1]])
        }
    }
    @Test func malformedAuthAllCannotBecomeAbsentOrTrap() {
        let malformed: [CBOR] = [.null, .map([:]), .array([]), .array([.array([])]), .array([.array([.byteString([])])]),
            .array([signature(chain: .array([.byteString([1]), .boolean(true)]))]),
            .array([signature(chain: .array([]))])]
        for value in malformed {
            #expect(throws: (any Error).self) { try DeviceRequest(cbor: request(auth: value)) }
        }
        #expect(throws: (any Error).self) { try DeviceRequest(cbor: request(auth: .array([signature()]), version: "1.0")) }
    }
    @Test func capabilityIsOptInAndSelectsVersion11() async throws {
        var engagement = try #require(DeviceEngagement(supportsCentralClientMode: true, supportsPeripheralServerMode: false))
        try await engagement.makePrivateKey(secureArea: InMemoryP256SecureArea(storage: DummySecureKeyStorage()), keyOptions: .init())
        let legacy = engagement.toCBOR(options: CBOROptions())
        #expect(legacy[0] == .utf8String("1.0"))
        #expect(legacy[6] == nil)
        engagement.readerAuthAllSupport = true
        let encoded = engagement.toCBOR(options: CBOROptions())
        #expect(encoded[0] == .utf8String("1.1"))
        #expect(encoded[5] == .array([]))
        #expect(encoded[6] == .map([3: .boolean(true)]))
        #expect(try DeviceEngagement(cbor: encoded).readerAuthAllSupport)
    }
}
