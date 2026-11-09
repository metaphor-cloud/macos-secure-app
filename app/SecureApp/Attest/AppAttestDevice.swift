import DeviceCheck
import Foundation
import SecureAppKit

/// DCAppAttestService on this Mac. Apple: App Attest works for a
/// native macOS 27 app; isSupported is still checked at launch and before
/// enrolment, and false is a hard stop with no way round it.
final class AppAttestDevice: Attester, @unchecked Sendable {
    private let service = DCAppAttestService.shared

    var isSupported: Bool {
        service.isSupported
    }

    func generateKey() async throws -> String {
        do {
            return try await service.generateKey()
        } catch {
            throw Self.map(error)
        }
    }

    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        do {
            return try await service.attestKey(keyId, clientDataHash: clientDataHash)
        } catch {
            throw Self.map(error)
        }
    }

    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        do {
            return try await service.generateAssertion(keyId, clientDataHash: clientDataHash)
        } catch {
            throw Self.map(error)
        }
    }

    static func map(_ error: Error) -> AttestError {
        guard let dc = error as? DCError else { return .unknown(code: (error as NSError).code) }
        switch dc.code {
        case .serverUnavailable: return .serverUnavailable
        case .featureUnsupported: return .featureUnsupported
        case .invalidKey: return .invalidKey
        case .invalidInput: return .invalidInput
        default: return .unknown(code: dc.code.rawValue)
        }
    }
}
