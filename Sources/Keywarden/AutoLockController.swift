import AppKit

/// Owns automatic locking; browser traffic and network work never extend the inactivity deadline.
/// The callback decides whether a timeout locks or signs out.
@MainActor
final class AutoLockController {
    private let settings: AppSettings
    private let now: () -> TimeInterval
    private let lock: () -> Void
    private var timer: DispatchSourceTimer?
    private var lastActivity: TimeInterval?
    private var unlocked = false
    private var observers: [NSObjectProtocol] = []

    init(settings: AppSettings, now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
         lock: @escaping () -> Void) {
        self.settings = settings
        self.now = now
        self.lock = lock
        settings.onChange = { [weak self] in self?.settingsChanged() }

        let workspace = NSWorkspace.shared.notificationCenter
        observers.append(workspace.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) {
            [weak self] _ in MainActor.assumeIsolated { self?.systemEvent(sleep: true) }
        })
        observers.append(workspace.addObserver(forName: NSWorkspace.sessionDidResignActiveNotification, object: nil, queue: .main) {
            [weak self] _ in MainActor.assumeIsolated { self?.systemEvent(sleep: false) }
        })
        // Undocumented and unauthenticated: an additional best-effort signal, never an unlock signal.
        observers.append(DistributedNotificationCenter.default().addObserver(
            forName: Notification.Name("com.apple.screenIsLocked"), object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.systemEvent(sleep: false) }
        })
    }

    isolated deinit {
        timer?.cancel()
        for observer in observers {
            NSWorkspace.shared.notificationCenter.removeObserver(observer)
            DistributedNotificationCenter.default().removeObserver(observer)
        }
    }

    func setUnlocked(_ value: Bool) {
        if value && !unlocked { lastActivity = now() }
        if !value { lastActivity = nil }
        unlocked = value
        reschedule()
    }

    func recordActivity() {
        guard unlocked else { return }
        lastActivity = now()
        reschedule()
    }

    func settingsChanged() { reschedule() }

    private func systemEvent(sleep: Bool) {
        guard settings.locksOn(sleep: sleep) else { return }
        lockNow()
    }

    private func lockNow() {
        timer?.cancel()
        timer = nil
        lastActivity = nil
        unlocked = false
        lock()
    }

    private func reschedule() {
        timer?.cancel()
        timer = nil
        guard unlocked, let lastActivity, let minutes = settings.vaultTimeout.inactivityMinutes else { return }
        let remaining = lastActivity + Double(minutes * 60) - now()
        if remaining <= 0 {
            lockNow()
            return
        }
        let source = DispatchSource.makeTimerSource(queue: .main)
        source.schedule(deadline: .now() + remaining)
        source.setEventHandler { [weak self] in
            MainActor.assumeIsolated { self?.reschedule() }
        }
        timer = source
        source.resume()
    }
}
