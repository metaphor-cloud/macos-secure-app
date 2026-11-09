import SecureAppKit

/// Every word the shell shows. NZ English, sentence case, no em or en dashes,
/// no exclamation marks. Says what happens, not how.
enum Copy {
    enum SignIn {
        static let title = "Secure App"
        static let body = "Sign in with your Metaphor ID to get going."
        static let button = "Sign in"
        static let waiting = "Finish signing in through the window that opened."
        static let sessionEnded = "You've been signed out. Sign in again to carry on."
        static let unreachable = "Can't reach Metaphor ID. Check your connection and try again."
        static let failed = "That sign-in didn't work. Try again."
    }

    enum NameThisMac {
        static let title = "Add this Mac"
        static let body = "Secure App only works on Macs added to your account. Give this one a name you'll recognise in the device list."
        static let field = "Name"
        static let button = "Add this Mac"
        static let signOut = "Sign out"
    }

    static func enrolStage(_ stage: EnrolStage) -> String {
        switch stage {
        case .challenge: "Getting ready"
        case .creatingKey: "Making a key on this Mac"
        case .attesting: "Checking this Mac with Apple"
        case .waitingForApple(let seconds): "Apple isn't answering. Trying again in \(Int(seconds.rounded())) seconds."
        case .registering: "Adding this Mac to your account"
        }
    }

    enum Unsupported {
        static let title = "This Mac can't run Secure App"
        static let body = "Secure App needs macOS 27 or later on a Mac that Apple can confirm is genuine. This one can't, so Secure App won't open here. Use another Mac."
    }

    enum FullSecurity {
        static let title = "Turn on Full Security"
        static let body = "Apple won't vouch for this Mac while it's in Reduced Security. Restart into Recovery, open Startup Security Utility, choose Full Security, then try again."
        static let button = "Try again"
    }

    enum AppleUnavailable {
        static let title = "Apple can't confirm this Mac right now"
        static let body = "Adding a Mac needs Apple to check it, and Apple isn't answering. Try again soon. Macs already added keep working."
        static let button = "Try again"
    }

    enum Sso {
        static let title = "Sign in with your work account"
        static let body = "Adding a Mac needs a fresh sign-in through your organisation's single sign-on. Sign in again with your work account, not a passkey."
        static let button = "Sign in again"
    }

    enum RateLimited {
        static let title = "Too many tries"
        static let body = "This Mac has been tried too many times today. Wait a while, then try again."
        static let button = "Try again"
    }

    enum Refused {
        static let title = "This Mac couldn't be added"
        static let body = "Check you're on the latest Secure App, then try again. If it keeps happening, let the team know."
        static let button = "Try again"
    }

    enum Unreachable {
        static let title = "Can't reach the server"
        static let body = "Check your internet connection, then try again."
        static let button = "Try again"
    }

    enum Failed {
        static let title = "Something went wrong"
        static let body = "Try again. If it keeps happening, let the team know and quote this:"
        static let button = "Try again"
    }

    enum Reenrol {
        static let title = "This Mac isn't set up for Secure App any more"
        static let body = "It may have been removed from your account, or Secure App was reinstalled. Add it again to carry on."
        static let button = "Add this Mac again"
    }

    enum Clock {
        static let title = "This Mac's clock is out"
        static let body = "Secure App needs the right time. Turn on Set time and date automatically in System Settings, General, Date and Time, then try again."
        static let button = "Try again"
    }

    enum Misconfigured {
        static let title = "This copy of Secure App is broken"
        static let body = "It was built without its settings. Install it again."
    }

    enum Lock {
        static let title = "Secure App is locked"
        static let button = "Unlock"
    }

    enum Settings {
        static let account = "Account"
        static let device = "This Mac"
        static let signOut = "Sign out"
        static let notEnrolled = "Not added yet"
    }

    enum AIApps {
        static let section = "AI apps"
        static let toggle = "Let AI apps on this Mac use Secure App"
        static let about = "Claude Code and other AI apps on this Mac can look things up and make changes through Secure App, as you. You confirm every change here before it happens. Secure App has to be open, signed in and unlocked."
        static let url = "Address"
        static let secret = "Secret"
        static let copy = "Copy"
        static let copied = "Copied"
        static let regenerate = "Make a new secret"
        static let regenerateNote = "Apps using the old secret stop working."
        static let claudeCode = "Claude Code"
        static let claudeCodeNote = "Run this in a terminal."
    }

    enum Menu {
        static let reload = "Reload"
        static let signOut = "Sign out"
        static let lock = "Lock Secure App"
        static let newTab = "New Tab"
        static let openInNewTab = "Open in New Tab"
        static let appearance = "Appearance"
        static let appearanceSystem = "System"
        static let appearanceLight = "Light"
        static let appearanceDark = "Dark"
    }

    enum Sidebar {
        static let signedInAs = "Signed in as"
    }
}
