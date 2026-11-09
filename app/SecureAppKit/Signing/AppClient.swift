import Foundation

/// Something the app has to show, raised while a request was being recovered.
public enum AppClientEvent: Equatable, Sendable {
    case needsSignIn
    case needsReenrol
    case clockWrong
}

/// What came back for a page's request.
public enum AppResult: Sendable {
    case response(status: Int, headers: [String: String], body: Data)
    /// No response to hand over; `reason` is a code.
    case failed(reason: String)
}

public enum EnrolStage: Equatable, Sendable {
    case challenge
    case creatingKey
    case attesting
    /// Apple's attestation service is unavailable; trying again after this many seconds.
    case waitingForApple(retryIn: TimeInterval)
    case registering
}

public enum EnrolOutcome: Equatable, Sendable {
    case enrolled(AttestKeyRecord)
    case unsupported
    /// Apple refused the key's access policy: on a Mac, that means it is not in
    /// Full Security (Startup Security Utility). The key is discarded.
    case fullSecurityNeeded
    /// Apple stayed unavailable for the life of the challenge. The key is kept for the next try.
    case appleUnavailable
    case ssoRequired
    case signIn
    case rateLimited
    /// The Worker would not add this Mac (an old build, a refused attestation). The key is discarded.
    case refused
    case unreachable
    case failed(reason: String)
}

/// Signs and sends every request, and enrols this Mac.
///
/// Holds the gate from signing until the response is back, so assertion
/// counters reach the Worker in order. Keeps the session challenge fresh
/// (bootstrap after enrolment or a restart, rotated before it lapses), and
/// recovers from the gate's uniform 403 per ForbiddenRecovery.
public final class AppClient: @unchecked Sendable {
    public typealias Send = @Sendable (URLRequest) async throws -> (Data, HTTPURLResponse)

    /// Rotate the session challenge when it has less than this left. The Worker keeps the previous one too.
    static let sessionRefreshMargin: TimeInterval = 2 * 60
    static let sessionTTLFallback: TimeInterval = 10 * 60

    public let config: AppConfig
    private let transport: HTTPTransport
    private let attester: Attester
    private let tokens: TokenSource
    private let keys: AttestKeyStore
    private let now: @Sendable () -> Date
    private let sleep: @Sendable (TimeInterval) async throws -> Void
    private let retryPolicy: AttestRetryPolicy
    private let gate = SerialGate()

    // Touched only while the gate is held.
    private var sub: String?
    private var keyId: String?
    private var session: (challenge: String, localExpiry: Date)?

    private let eventLock = NSLock()
    private var eventHandler: (@Sendable (AppClientEvent) -> Void)?

    public init(
        config: AppConfig,
        transport: HTTPTransport,
        attester: Attester,
        tokens: TokenSource,
        keys: AttestKeyStore,
        retryPolicy: AttestRetryPolicy = AttestRetryPolicy(),
        now: @escaping @Sendable () -> Date = { Date() },
        sleep: @escaping @Sendable (TimeInterval) async throws -> Void = { try await Task.sleep(nanoseconds: UInt64($0 * 1_000_000_000)) }
    ) {
        self.config = config
        self.transport = transport
        self.attester = attester
        self.tokens = tokens
        self.keys = keys
        self.retryPolicy = retryPolicy
        self.now = now
        self.sleep = sleep
    }

    public func onEvent(_ handler: @escaping @Sendable (AppClientEvent) -> Void) {
        eventLock.withLock { eventHandler = handler }
    }

    private func emit(_ event: AppClientEvent) {
        let handler = eventLock.withLock { eventHandler }
        Log.api.notice("client needs attention, event: \(String(describing: event), privacy: .public)")
        handler?(event)
    }

    /// Who requests are signed for. Called after sign-in with the enrolled key, and with nil on sign-out.
    public func use(sub: String?, keyId: String?) async {
        await gate.acquire()
        self.sub = sub
        self.keyId = keyId
        self.session = nil
        await gate.release()
    }

    public var currentKeyId: String? {
        get async {
            await gate.acquire()
            let k = keyId
            await gate.release()
            return k
        }
    }

    // MARK: Requests

    /// Signs and sends one request for the page.
    public func perform(_ request: AppHTTPRequest) async -> AppResult {
        let transport = self.transport
        return await performSigned(request) { try await transport.send($0) }
    }

    /// Signs one request and hands it to `send`, recovering as for any request.
    /// The live socket uses this for its upgrade request: `send` resolves when the handshake has finished,
    /// so no other request is signed while it is in flight.
    public func performSigned(_ request: AppHTTPRequest, send: Send) async -> AppResult {
        await gate.acquire()
        let result = await performLocked(request, send: send)
        await gate.release()
        return result
    }

    private func performLocked(_ request: AppHTTPRequest, send: Send) async -> AppResult {
        var recovery = ForbiddenRecovery()
        while true {
            guard let keyId else { return .failed(reason: "not_enrolled") }
            let token: String
            do {
                token = try await tokens.accessToken()
            } catch AuthError.signedOut {
                emit(.needsSignIn)
                return .failed(reason: "signed_out")
            } catch {
                return .failed(reason: "auth_unreachable")
            }

            if needsSessionRefresh {
                switch await refreshSession(keyId: keyId, token: token) {
                case .ok:
                    break
                case .failed(let reason):
                    return .failed(reason: reason)
                case .refused(let serverDate):
                    switch recovery.sessionRefused(serverDate: serverDate, now: now()) {
                    case .refreshTokenAndRetry:
                        if let failure = await refreshToken() { return failure }
                        continue
                    case .clockWrong:
                        emit(.clockWrong)
                        return .failed(reason: "clock_wrong")
                    default:
                        emit(.needsReenrol)
                        return .failed(reason: "reenrol")
                    }
                }
            }
            guard let challenge = session?.challenge else { return .failed(reason: "no_session") }

            let urlRequest: URLRequest
            do {
                urlRequest = try await sign(request, keyId: keyId, token: token, challenge: challenge)
            } catch let error as AttestError {
                return await assertionFailed(error)
            } catch {
                return .failed(reason: "sign_failed")
            }

            let data: Data
            let response: HTTPURLResponse
            do {
                (data, response) = try await send(urlRequest)
            } catch {
                Log.api.notice("request failed in transport, path: \(Self.pathOnly(request.pathAndQuery), privacy: .public)")
                return .failed(reason: "network")
            }

            let action = recovery.next(status: response.statusCode, body: data, serverDate: response.value(forHTTPHeaderField: "Date"), now: now())
            if action != .deliver {
                Log.api.notice("request refused, status: \(response.statusCode, privacy: .public), action: \(String(describing: action), privacy: .public), path: \(Self.pathOnly(request.pathAndQuery), privacy: .public), keyRef: \(keyRef(keyId), privacy: .public)")
            }
            let result = AppResult.response(status: response.statusCode, headers: BridgeValidator.filterResponseHeaders(response.allHeaderFields), body: data)
            switch action {
            case .deliver:
                return result
            case .refreshSessionAndRetry:
                session = nil
                continue
            case .refreshTokenAndRetry:
                if let failure = await refreshToken() { return failure }
                continue
            case .reenrol:
                emit(.needsReenrol)
                return result
            case .signIn:
                emit(.needsSignIn)
                return result
            case .clockWrong:
                emit(.clockWrong)
                return result
            }
        }
    }

    private func refreshToken() async -> AppResult? {
        do {
            _ = try await tokens.forceRefresh()
            return nil
        } catch AuthError.signedOut {
            emit(.needsSignIn)
            return .failed(reason: "signed_out")
        } catch {
            return .failed(reason: "auth_unreachable")
        }
    }

    private func assertionFailed(_ error: AttestError) async -> AppResult {
        Log.attest.error("assertion failed, code: \(error.code, privacy: .public)")
        if error.keyCannotSign, let sub {
            // The Secure Enclave no longer has this key, or has it and refuses to sign (a restore,
            // a migration, or a reboot after which signing fails with an unknown error, code 0):
            // it can never sign again.
            keys.discard(for: sub)
            keyId = nil
            emit(.needsReenrol)
            return .failed(reason: "reenrol")
        }
        return .failed(reason: "assertion_\(error.code)")
    }

    static func pathOnly(_ pathAndQuery: String) -> String {
        String(pathAndQuery.split(separator: "?", maxSplits: 1).first ?? "")
    }

    /// The signed URLRequest for `request`: bearer token, X-App-* headers, the body as hashed.
    func sign(_ request: AppHTTPRequest, keyId: String, token: String, challenge: String) async throws -> URLRequest {
        guard let url = config.url(for: request.pathAndQuery) else { throw TransportError(message: "bad_url") }
        let body = request.body ?? Data()
        let time = Int64((now().timeIntervalSince1970 * 1000).rounded(.down))
        let nonce = makeNonce()
        let parts = AppRequestParts(
            appId: config.appId,
            keyId: keyId,
            method: request.method,
            pathAndQuery: request.pathAndQuery,
            bodySha256: sha256Hex(body),
            tokenSha256: sha256Hex(token),
            time: time,
            nonce: nonce,
            challenge: challenge
        )
        let clientDataHash = sha256(Data(appClientData(parts).utf8))
        let assertion = try await attester.generateAssertion(keyId, clientDataHash: clientDataHash)

        var out = URLRequest(url: url)
        out.httpMethod = request.method
        for (name, value) in request.headers { out.setValue(value, forHTTPHeaderField: name) }
        out.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        out.setValue(config.appId, forHTTPHeaderField: AppHeader.app)
        out.setValue(keyId, forHTTPHeaderField: AppHeader.key)
        out.setValue(String(time), forHTTPHeaderField: AppHeader.time)
        out.setValue(nonce, forHTTPHeaderField: AppHeader.nonce)
        out.setValue(challenge, forHTTPHeaderField: AppHeader.challenge)
        out.setValue(assertion.base64EncodedString(), forHTTPHeaderField: AppHeader.assertion)
        if request.body != nil { out.httpBody = body }
        return out
    }

    // MARK: Session challenge

    private var needsSessionRefresh: Bool {
        guard let session else { return true }
        return session.localExpiry.timeIntervalSince(now()) < Self.sessionRefreshMargin
    }

    private enum SessionRefresh {
        case ok
        case refused(serverDate: String?)
        case failed(String)
    }

    /// A signed GET of the session path over the current challenge, or bootstrap when there is none.
    private func refreshSession(keyId: String, token: String) async -> SessionRefresh {
        let challenge = session.flatMap { $0.localExpiry > now() ? $0.challenge : nil } ?? AppContract.sessionBootstrap
        let request = AppHTTPRequest(method: "GET", pathAndQuery: AppContract.attestSessionPath, headers: ["Accept": "application/json"])
        let signed: URLRequest
        do {
            signed = try await sign(request, keyId: keyId, token: token, challenge: challenge)
        } catch let error as AttestError {
            if case .failed(let reason) = await assertionFailed(error) { return .failed(reason) }
            return .failed("assertion_failed")
        } catch {
            return .failed("sign_failed")
        }
        let data: Data
        let response: HTTPURLResponse
        do {
            (data, response) = try await transport.send(signed)
        } catch {
            return .failed("network")
        }
        let serverDate = response.value(forHTTPHeaderField: "Date")
        guard response.statusCode == 200 else {
            Log.attest.notice("session challenge refused, status: \(response.statusCode, privacy: .public), bootstrap: \(challenge == AppContract.sessionBootstrap, privacy: .public), keyRef: \(keyRef(keyId), privacy: .public)")
            session = nil
            return response.statusCode == 403 ? .refused(serverDate: serverDate) : .failed("session_http_\(response.statusCode)")
        }
        guard let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let next = json["challenge"] as? String, matches(challengePattern, next)
        else { return .failed("session_malformed") }
        let expiresAtMs = (json["expiresAt"] as? NSNumber)?.doubleValue
        adoptSession(challenge: next, expiresAtMs: expiresAtMs, serverDate: serverDate)
        Log.attest.debug("session challenge rotated, keyRef: \(keyRef(keyId), privacy: .public)")
        return .ok
    }

    /// Keeps a session challenge with its life measured on this Mac's clock, so a clock that is
    /// a little out (inside the Worker's skew) still rotates it on time.
    private func adoptSession(challenge: String, expiresAtMs: Double?, serverDate: String?) {
        let serverNow = serverDate.flatMap { httpDateFormatter.date(from: $0) } ?? now()
        var ttl = expiresAtMs.map { Date(timeIntervalSince1970: $0 / 1000).timeIntervalSince(serverNow) } ?? Self.sessionTTLFallback
        if !(ttl > 0) || ttl > Self.sessionTTLFallback { ttl = Self.sessionTTLFallback }
        session = (challenge, now().addingTimeInterval(ttl))
    }

    // MARK: Enrolment

    /// Enrols this Mac for `sub`. Holds the gate, so nothing is signed with a half-enrolled key.
    public func enrol(sub: String, deviceLabel: String, progress: @escaping @Sendable (EnrolStage) -> Void) async -> EnrolOutcome {
        await gate.acquire()
        let outcome = await enrolLocked(sub: sub, deviceLabel: deviceLabel, progress: progress)
        if case .enrolled(let record) = outcome {
            self.sub = sub
            self.keyId = record.keyId
        }
        await gate.release()
        Log.attest.info("enrolment finished, outcome: \(String(describing: outcome).prefix(40), privacy: .public)")
        return outcome
    }

    private func enrolLocked(sub: String, deviceLabel rawLabel: String, progress: @escaping @Sendable (EnrolStage) -> Void) async -> EnrolOutcome {
        guard attester.isSupported else {
            Log.attest.error("app attest not supported on this mac")
            return .unsupported
        }
        guard let label = cleanDeviceLabel(rawLabel) else { return .failed(reason: "label_invalid") }
        if let existing = keys.record(for: sub), existing.enrolled { return .enrolled(existing) }

        // A fresh ID token, so the SSO and MFA evidence the Worker checks has not expired.
        let token: String
        do {
            token = try await tokens.forceRefresh()
        } catch AuthError.signedOut {
            return .signIn
        } catch {
            return .unreachable
        }
        let idToken = await tokens.idToken()

        progress(.challenge)
        let challenge: String
        switch await postJSON(AppContract.attestChallengePath, token: token, body: [:]) {
        case .failure:
            return .unreachable
        case .success(let (status, json)):
            switch status {
            case 200:
                guard let c = json["challenge"] as? String, !c.isEmpty else { return .failed(reason: "challenge_malformed") }
                challenge = c
            case 401: return .signIn
            case 429: return .rateLimited
            case 500...599:
                Log.attest.error("enrolment challenge failed, status: \(status, privacy: .public)")
                return .unreachable
            default:
                Log.attest.error("enrolment challenge refused, status: \(status, privacy: .public)")
                return .failed(reason: "challenge_http_\(status)")
            }
        }

        let clientDataHash = sha256(Data(challenge.utf8))
        // A key kept from an earlier try (Apple was unavailable, or /register never answered)
        // may be refused with invalidKey when it is attested again. That says nothing about
        // Full Security, so the kept key is dropped and one fresh key is tried. A fresh key
        // never loops: its invalidKey is the Full Security answer.
        var kept = keys.record(for: sub)
        var record: AttestKeyRecord
        let attestation: Data
        while true {
            let fresh = kept == nil
            if let kept {
                record = kept
            } else {
                progress(.creatingKey)
                do {
                    let keyId = try await attester.generateKey()
                    record = AttestKeyRecord(keyId: keyId, enrolled: false, deviceLabel: label)
                } catch let error as AttestError {
                    Log.attest.error("key generation failed, code: \(error.code, privacy: .public)")
                    return error == .featureUnsupported ? .unsupported : .failed(reason: "generate_\(error.code)")
                } catch {
                    return .failed(reason: "generate_failed")
                }
            }
            record.deviceLabel = label
            do { try keys.save(record, for: sub) } catch { return .failed(reason: "keychain") }

            progress(.attesting)
            switch await attestWithRetry(record.keyId, clientDataHash: clientDataHash, progress: progress) {
            case .attested(let data):
                attestation = data
            case .appleUnavailable:
                return .appleUnavailable
            case .refused(let error):
                // Apple: on any error but serverUnavailable, discard the key.
                Log.attest.error("attestation failed, key discarded, code: \(error.code, privacy: .public), fresh: \(fresh, privacy: .public)")
                keys.discard(for: sub)
                switch error {
                case .invalidKey where !fresh:
                    kept = nil
                    continue
                case .featureUnsupported: return .unsupported
                case .invalidKey: return .fullSecurityNeeded
                default: return .failed(reason: "attest_\(error.code)")
                }
            case .failed:
                keys.discard(for: sub)
                return .failed(reason: "attest_failed")
            }
            break
        }

        progress(.registering)
        var body: [String: Any] = [
            "challenge": challenge,
            "keyId": record.keyId,
            "attestation": attestation.base64EncodedString(),
            "appId": config.appId,
            "deviceLabel": label,
        ]
        if let idToken { body["idToken"] = idToken }
        switch await postJSON(AppContract.attestRegisterPath, token: token, body: body) {
        case .failure:
            // The challenge is spent either way; the key may or may not be enrolled. Keep it:
            // the next try gets a 409 if it was, and enrols it if it was not.
            return .unreachable
        case .success(let (status, json)):
            switch status {
            case 201:
                record.enrolled = true
                do { try keys.save(record, for: sub) } catch { return .failed(reason: "keychain") }
                if let next = json["sessionChallenge"] as? String, matches(challengePattern, next) {
                    adoptSession(challenge: next, expiresAtMs: (json["sessionChallengeExpiresAt"] as? NSNumber)?.doubleValue, serverDate: nil)
                } else {
                    session = nil
                }
                Log.attest.info("this mac enrolled, keyRef: \(keyRef(record.keyId), privacy: .public), environment: \(json["environment"] as? String ?? "unknown", privacy: .public)")
                return .enrolled(record)
            case 409:
                // Already enrolled: an earlier try got through but its answer was lost.
                record.enrolled = true
                do { try keys.save(record, for: sub) } catch { return .failed(reason: "keychain") }
                session = nil
                Log.attest.notice("enrolment answered already enrolled, keyRef: \(keyRef(record.keyId), privacy: .public)")
                return .enrolled(record)
            case 401:
                return .signIn
            case 403 where (json["sso"] as? String) == "required":
                // The attested key was spent on a refused enrolment: start the next try with a new one.
                keys.discard(for: sub)
                return .ssoRequired
            case 403 where (json["device"] as? String) == "full_security":
                // The Worker read a key policy other than Apple's Full Security one: Reduced Security.
                Log.attest.error("enrolment refused, key discarded, reason: full_security_needed")
                keys.discard(for: sub)
                return .fullSecurityNeeded
            case 429:
                keys.discard(for: sub)
                return .rateLimited
            case 500...599:
                // The Worker broke, not the key: kept, as for a lost answer above.
                Log.attest.error("enrolment failed at the Worker, key kept, status: \(status, privacy: .public)")
                return .unreachable
            default:
                Log.attest.error("enrolment refused, key discarded, status: \(status, privacy: .public)")
                keys.discard(for: sub)
                return .refused
            }
        }
    }

    private enum AttestAttempt {
        case attested(Data)
        case appleUnavailable
        case refused(AttestError)
        case failed
    }

    /// attestKey, retried on serverUnavailable with the same key and hash within the retry budget.
    private func attestWithRetry(_ keyId: String, clientDataHash: Data, progress: @escaping @Sendable (EnrolStage) -> Void) async -> AttestAttempt {
        let started = now()
        var attempt = 0
        while true {
            do {
                return .attested(try await attester.attestKey(keyId, clientDataHash: clientDataHash))
            } catch let error as AttestError where error == .serverUnavailable {
                guard let delay = retryPolicy.delay(attempt: attempt, elapsed: now().timeIntervalSince(started)) else {
                    Log.attest.notice("apple attestation unavailable, giving up for this challenge, attempts: \(attempt + 1, privacy: .public)")
                    return .appleUnavailable
                }
                Log.attest.notice("apple attestation unavailable, retrying, attempt: \(attempt + 1, privacy: .public), delay: \(delay, privacy: .public)")
                progress(.waitingForApple(retryIn: delay))
                do { try await sleep(delay) } catch { return .appleUnavailable }
                attempt += 1
                progress(.attesting)
            } catch let error as AttestError {
                return .refused(error)
            } catch {
                return .failed
            }
        }
    }

    private func postJSON(_ path: String, token: String, body: [String: Any]) async -> Result<(Int, [String: Any]), TransportError> {
        guard let url = config.url(for: path), let data = try? JSONSerialization.data(withJSONObject: body) else {
            return .failure(TransportError(message: "bad_request"))
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.httpBody = data
        do {
            let (out, response) = try await transport.send(request)
            let json = ((try? JSONSerialization.jsonObject(with: out)) as? [String: Any]) ?? [:]
            return .success((response.statusCode, json))
        } catch {
            Log.attest.notice("enrolment request failed in transport, path: \(path, privacy: .public)")
            return .failure(TransportError(message: "network"))
        }
    }
}
