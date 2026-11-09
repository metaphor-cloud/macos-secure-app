import Foundation

/// One request at a time, first come first served.
///
/// The Worker accepts an assertion only if its counter is higher than the last
/// one it accepted, so two signed requests in flight can arrive out of order
/// and the earlier one is refused. Swift actors are re-entrant across awaits,
/// so an actor alone does not serialise a sign-then-send; this gate does, and
/// is held from signing until the response (or the socket handshake) is back.
public actor SerialGate {
    private var busy = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    public init() {}

    public func acquire() async {
        if !busy {
            busy = true
            return
        }
        await withCheckedContinuation { waiters.append($0) }
    }

    public func release() {
        if waiters.isEmpty {
            busy = false
        } else {
            waiters.removeFirst().resume()
        }
    }

    public func run<T: Sendable>(_ body: @Sendable () async -> T) async -> T {
        await acquire()
        let result = await body()
        release()
        return result
    }
}
