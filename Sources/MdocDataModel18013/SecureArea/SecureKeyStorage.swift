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

public protocol SecureKeyStorage: Actor {
    // read key public info
    func readKeyInfo(id: String) throws -> [String: Data]
    // read key sensitive info (may trigger biometric or password checks)
    func readKeyData(id: String) throws -> [String: Data]

    // save key public info
    func writeKeyInfo(id: String, dict: [String: Data]) throws
    // save key sensitive info
    // todo: pass key options
    func writeKeyData(id: String, dict: [String: Data]) throws
    // delete key info and data
    func deleteKey(id: String) throws
}
