//
//  FixManager.swift
//  mergen
//
//  Typed, unprivileged remediation executor. Downloaded advisory or rule data
//  can never provide executable paths or arguments to this API.
//

import Foundation

enum DefaultsValue {
    case boolean(Bool)
    case integer(Int)
    case string(String)

    var arguments: [String] {
        switch self {
        case .boolean(let value): return ["-bool", value ? "true" : "false"]
        case .integer(let value): return ["-int", String(value)]
        case .string(let value): return ["-string", value]
        }
    }
}

/// Closed set of reviewed remediation operations. There is intentionally no
/// arbitrary-command case.
indirect enum RemediationOperation {
    case defaultsWrite(domain: String, key: String, value: DefaultsValue, currentHost: Bool = false)
    case sequence([RemediationOperation])

    var auditLabel: String {
        switch self {
        case .defaultsWrite(let domain, let key, _, _):
            return "defaults-write:\(domain):\(key)"
        case .sequence(let operations):
            return "sequence:\(operations.count)-operations"
        }
    }
}

enum FixResult {
    case success
    case cancelled
    case executionError(String)
}

enum FixManager {
    /// Executes only typed operations using fixed absolute binaries and argument
    /// arrays. Privileged operations are deliberately unavailable until the
    /// signed, authenticated helper target is shipped.
    static func run(_ operation: RemediationOperation) -> FixResult {
        switch operation {
        case .defaultsWrite(let domain, let key, let value, let currentHost):
            var arguments: [String] = []
            if currentHost { arguments.append("-currentHost") }
            arguments += ["write", domain, key]
            arguments += value.arguments
            return run(executable: "/usr/bin/defaults", arguments: arguments)

        case .sequence(let operations):
            for operation in operations {
                let result = run(operation)
                if case .success = result { continue }
                return result
            }
            return .success
        }
    }

    private static func run(executable: String, arguments: [String]) -> FixResult {
        let process = Process()
        let standardError = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = Pipe()
        process.standardError = standardError

        do {
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else {
                let data = standardError.fileHandleForReading.readDataToEndOfFile()
                let message = String(data: data, encoding: .utf8)?
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                return .executionError(message?.isEmpty == false ? message! : "exit \(process.terminationStatus)")
            }
            return .success
        } catch {
            return .executionError(error.localizedDescription)
        }
    }
}
