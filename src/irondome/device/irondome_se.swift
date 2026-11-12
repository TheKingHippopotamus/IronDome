// SPDX-License-Identifier: GPL-3.0-only
//
// irondome-se -- the only native code in IronDome.
//
// A deliberately small bridge to the Apple Secure Enclave. It never sees the
// vault, the master password or the vault key. It can do exactly three things:
//
//   info              report whether a Secure Enclave and biometry are usable
//   create <policy>   generate a P-256 key inside the Secure Enclave
//   agree             run one ECDH key agreement inside the Secure Enclave
//
// The private key is generated in the Secure Enclave and never leaves it. What
// `create` prints is an opaque blob that only the Secure Enclave of this Mac
// can use. Under the "biometry" policy the Secure Enclave itself refuses to run
// `agree` until the sensor reports a match for a currently enrolled finger. That
// check is enforced by the chip, not by this program and not by the OS: there
// is no key anywhere that a process could read instead.
//
// Protocol (kept trivial on purpose, so it can be audited in one sitting):
//
//   irondome-se info
//       stdout: one JSON object
//   irondome-se create device|biometry|presence
//       stdout: {"key": <base64 blob>, "public_key": <base64 X9.63 point>}
//   irondome-se agree [--interactive]
//       stdin:  {"key": <base64 blob>, "peer": <base64 X9.63 point>, "reason": <text>}
//       stdout: exactly 32 raw bytes, the ECDH shared secret
//
// Failures print {"error": <code>, "message": <text>} on stderr and exit with
// the status listed in `Failure` below. Nothing secret is ever written to
// stderr, to a log, or to disk.
//
// Keys under the "device" policy are created AfterFirstUnlockThisDeviceOnly:
// they work while the screen is locked, once the Mac has been unlocked since
// it started. "biometry" and "presence" keys are WhenUnlockedThisDeviceOnly,
// so while the screen is locked the Secure Enclave refuses `create` and `agree`
// for them. That refusal is reported as the error code "device_locked"
// (status 3) rather than as a rejected key, because the key is fine and works
// again after unlocking.

import CryptoKit
import Foundation
import IOKit
import LocalAuthentication

let protocolVersion = 1

enum Failure: Int32 {
    case usage = 2            // bad arguments or malformed request
    case unavailable = 3      // no Secure Enclave, or biometry not usable
    case interaction = 4      // authentication is required but was not allowed
    case denied = 5           // the user cancelled, or the match failed
    case keyUnusable = 6      // blob rejected: other Mac, or fingerprints changed
    case internalError = 1
}

func fail(_ kind: Failure, _ code: String, _ message: String) -> Never {
    let body: [String: Any] = ["error": code, "message": message]
    if let data = try? JSONSerialization.data(withJSONObject: body, options: [.sortedKeys]) {
        FileHandle.standardError.write(data)
        FileHandle.standardError.write(Data([0x0A]))
    }
    exit(kind.rawValue)
}

func emit(_ object: [String: Any]) {
    guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) else {
        fail(.internalError, "encode_failed", "could not encode the response")
    }
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data([0x0A]))
}

/// Write every byte or die: a short write of key material must never look like success.
func writeAll(_ fd: Int32, _ buffer: UnsafeRawBufferPointer) {
    var offset = 0
    while offset < buffer.count {
        let n = write(fd, buffer.baseAddress! + offset, buffer.count - offset)
        if n < 0 {
            if errno == EINTR { continue }
            fail(.internalError, "write_failed", "could not write the result")
        }
        offset += n
    }
}

/// True while the console session is locked. The I/O Registry root publishes
/// this as "IOConsoleLocked" (kIOConsoleLockedKey in IOKit/IOKitKeys.h).
func consoleIsLocked() -> Bool {
    let root = IORegistryGetRootEntry(mach_port_t(MACH_PORT_NULL))
    guard root != 0 else { return false }
    defer { IOObjectRelease(root) }
    guard let value = IORegistryEntryCreateCFProperty(
        root, "IOConsoleLocked" as CFString, kCFAllocatorDefault, 0)
    else { return false }
    return (value.takeRetainedValue() as? Bool) ?? false
}

/// A refusal while the screen is locked says nothing about the key itself.
func failIfLocked() {
    if consoleIsLocked() {
        fail(.unavailable, "device_locked",
             "this Mac is locked, and the Secure Enclave only uses the vault's key while the screen is unlocked")
    }
}

func biometryName(_ type: LABiometryType) -> String {
    switch type {
    case .touchID: return "touchid"
    case .faceID: return "faceid"
    case .none: return "none"
    default: return "other"
    }
}

func accessControl(for policy: String) -> SecAccessControl {
    // "device" keys work whenever the Mac has been unlocked once since it started,
    // including while the screen is locked, so SSH sessions, scheduled jobs and
    // agents keep working. Keys that need a finger or the password need a person
    // at an unlocked Mac. Every key is ThisDeviceOnly: it never leaves this chip.
    var flags: SecAccessControlCreateFlags
    var protection = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    switch policy {
    case "device":
        flags = [.privateKeyUsage]
        protection = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    case "biometry": flags = [.privateKeyUsage, .biometryCurrentSet]
    case "presence": flags = [.privateKeyUsage, .userPresence]
    default: fail(.usage, "bad_policy", "policy must be device, biometry or presence")
    }
    var error: Unmanaged<CFError>?
    guard let control = SecAccessControlCreateWithFlags(nil, protection, flags, &error)
    else {
        let detail = error.map { String(describing: $0.takeRetainedValue()) } ?? "unknown"
        fail(.unavailable, "access_control", "could not build the access policy: \(detail)")
    }
    return control
}

func commandInfo() {
    let context = LAContext()
    var error: NSError?
    let biometryUsable = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    emit([
        "protocol": protocolVersion,
        "secure_enclave": SecureEnclave.isAvailable,
        "biometry": biometryName(context.biometryType),
        "biometry_usable": biometryUsable,
        "biometry_detail": biometryUsable ? "" : (error?.localizedDescription ?? ""),
    ])
}

func commandCreate(_ policy: String) {
    guard SecureEnclave.isAvailable else {
        fail(.unavailable, "no_secure_enclave", "this Mac has no usable Secure Enclave")
    }
    let control = accessControl(for: policy)
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: control)
        emit([
            "key": key.dataRepresentation.base64EncodedString(),
            "public_key": key.publicKey.x963Representation.base64EncodedString(),
            "policy": policy,
        ])
    } catch {
        failIfLocked()
        fail(.unavailable, "create_failed", "the Secure Enclave refused to create a key: \(error.localizedDescription)")
    }
}

func commandAgree(interactive: Bool) {
    guard SecureEnclave.isAvailable else {
        fail(.unavailable, "no_secure_enclave", "this Mac has no usable Secure Enclave")
    }
    let input = FileHandle.standardInput.readDataToEndOfFile()
    guard input.count <= 65_536,
          let request = (try? JSONSerialization.jsonObject(with: input)) as? [String: Any],
          let keyText = request["key"] as? String, let blob = Data(base64Encoded: keyText),
          let peerText = request["peer"] as? String, let peerBytes = Data(base64Encoded: peerText)
    else {
        fail(.usage, "bad_request", "expected a JSON object with base64 \"key\" and \"peer\"")
    }
    let reason = (request["reason"] as? String) ?? "unlock your IronDome vault"

    let peer: P256.KeyAgreement.PublicKey
    do {
        // Validates that the point is on the curve; anything else is rejected here.
        peer = try P256.KeyAgreement.PublicKey(x963Representation: peerBytes)
    } catch {
        fail(.usage, "bad_peer", "the peer public key is not a valid P-256 point")
    }

    let context = LAContext()
    context.localizedReason = String(reason.prefix(200))
    context.interactionNotAllowed = !interactive

    let key: SecureEnclave.P256.KeyAgreement.PrivateKey
    do {
        key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: blob, authenticationContext: context)
    } catch {
        failIfLocked()
        fail(.keyUnusable, "key_rejected", "this Secure Enclave does not accept the key: \(error.localizedDescription)")
    }

    do {
        let secret = try key.sharedSecretFromKeyAgreement(with: peer)
        secret.withUnsafeBytes { bytes in
            guard bytes.count == 32 else {
                fail(.internalError, "bad_length", "unexpected shared secret length")
            }
            writeAll(STDOUT_FILENO, bytes)
        }
    } catch let error as NSError {
        if error.domain == LAErrorDomain {
            switch error.code {
            case LAError.notInteractive.rawValue:
                fail(.interaction, "interaction_required", "authentication is required to use this key")
            case LAError.userCancel.rawValue, LAError.appCancel.rawValue, LAError.systemCancel.rawValue:
                fail(.denied, "cancelled", "authentication was cancelled")
            case LAError.authenticationFailed.rawValue, LAError.userFallback.rawValue:
                fail(.denied, "auth_failed", "authentication failed")
            case LAError.biometryLockout.rawValue:
                fail(.denied, "biometry_lockout", "biometry is locked out; unlock the Mac with its password first")
            case LAError.biometryNotAvailable.rawValue, LAError.biometryNotEnrolled.rawValue,
                 LAError.passcodeNotSet.rawValue:
                fail(.unavailable, "biometry_unavailable", error.localizedDescription)
            default:
                fail(.denied, "auth_error", error.localizedDescription)
            }
        }
        failIfLocked()
        fail(.keyUnusable, "agree_failed", "the Secure Enclave refused the operation: \(error.localizedDescription)")
    }
}

// No core file may ever contain a shared secret.
var noCore = rlimit(rlim_cur: 0, rlim_max: 0)
setrlimit(RLIMIT_CORE, &noCore)

let arguments = Array(CommandLine.arguments.dropFirst())
switch arguments.first {
case "info" where arguments.count == 1:
    commandInfo()
case "create" where arguments.count == 2:
    commandCreate(arguments[1])
case "agree" where arguments.count == 1:
    commandAgree(interactive: false)
case "agree" where arguments.count == 2 && arguments[1] == "--interactive":
    commandAgree(interactive: true)
default:
    fail(.usage, "usage", "usage: irondome-se info | create device|biometry|presence | agree [--interactive]")
}
