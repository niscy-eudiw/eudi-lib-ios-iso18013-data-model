//
//  DeviceSigned.swift

import Foundation
import SwiftCBOR

/// Contains the mdoc authentication structure and the data elements protected by mdoc authentication
struct DeviceSigned {
	let nameSpaces: DeviceNameSpaces
	let nsRawBytes: [UInt8]
	let deviceAuth: DeviceAuth
	//DeviceNameSpacesBytes = #6.24(bstr .cbor DeviceNameSpaces)
	enum Keys: String {
		case nameSpaces
		case deviceAuth
	}
}

extension DeviceSigned: CBORDecodable {
	init?(cbor: CBOR) {
		guard case let .map(m) = cbor else { return nil }
		guard case let .tagged(_, cdns) = m[Keys.nameSpaces], case let .byteString(bs) = cdns, let dns = DeviceNameSpaces(data: bs) else { return nil }
		nameSpaces = dns
		guard let cdu = m[Keys.deviceAuth], let du = DeviceAuth(cbor: cdu) else { return nil }
		deviceAuth = du
		nsRawBytes = bs
	}
}

/// Device data elements per namespac
struct DeviceNameSpaces {
	let deviceNameSpaces: [NameSpace: DeviceSignedItems]
	subscript(ns: NameSpace) -> DeviceSignedItems? { deviceNameSpaces[ns] }
}

extension DeviceNameSpaces: CBORDecodable {
	init?(cbor: CBOR) {
		guard case let .map(m) = cbor else { return nil }
		let dnsPairs = m.compactMap { (k: CBOR, v: CBOR) -> (NameSpace, DeviceSignedItems)?  in
			guard case .utf8String(let ns) = k else { return nil }
			guard let dsi = DeviceSignedItems(cbor: v) else { return nil }
			return (ns,dsi)
		}
		let dns = Dictionary(dnsPairs, uniquingKeysWith: { (first, _) in first })
		deviceNameSpaces = dns
	}
}

/// Contains the data element identifiers and values for a namespace
struct DeviceSignedItems {
	let deviceSignedItems: [DataElementIdentifier: DataElementValue]
	subscript(ei: DataElementIdentifier) -> DataElementValue? { deviceSignedItems[ei] }
}

extension DeviceSignedItems: CBORDecodable {
	init?(cbor: CBOR) {
		guard case let .map(m) = cbor else { return nil }
		let dsiPairs = m.compactMap { (k: CBOR, v: CBOR) -> (DataElementIdentifier, DataElementValue)?  in
			guard case .utf8String(let dei) = k else { return nil }
			return (dei,v)
		}
		let dsi = Dictionary(dsiPairs, uniquingKeysWith: { (first, _) in first })
		if dsi.count == 0 { return nil }
		deviceSignedItems = dsi
	}
}


