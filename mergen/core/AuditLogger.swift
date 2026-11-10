//
//  AuditLogger.swift
//  mergen
//
//  Structured, private JSON Lines audit log. Evidence is normalized and
//  redacted before it reaches disk; executable command strings are never logged.
//

import Foundation

final class AuditLogger {
    static let shared = AuditLogger()

    private let logURL: URL
    private let queue = DispatchQueue(label: "com.mergen.logger", qos: .background)

    private init() {
        let library = FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask).first!
        let directory = library.appendingPathComponent("Logs/mergen", isDirectory: true)
        try? FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)

        let day = String(ISO8601DateFormatter().string(from: Date()).prefix(10))
        logURL = directory.appendingPathComponent("mergen-\(day).jsonl")
    }

    func logScanStart(category: String?) {
        write(event: "scan_start", fields: ["category": category ?? "All"])
    }

    func logCheckResult(_ vulnerability: Vulnerability) {
        write(event: "check_result", fields: [
            "cis_id": vulnerability.cisID.isEmpty ? "-" : vulnerability.cisID,
            "status": vulnerability.checkstatus ?? "unknown",
            "name": vulnerability.name,
            "result": redact(vulnerability.status ?? ""),
        ])
    }

    func logScanComplete(_ results: [Vulnerability]) {
        write(event: "scan_complete", fields: [
            "total": String(results.count),
            "passed": String(results.filter { $0.checkstatus == "Green" }.count),
            "failed": String(results.filter { $0.checkstatus == "Red" }.count),
            "warnings": String(results.filter { $0.checkstatus == "Yellow" }.count),
            "advisories": String(results.filter { $0.checkstatus == "Blue" }.count),
        ])
    }

    func logFixStart(_ vulnerability: Vulnerability) {
        write(event: "fix_start", fields: [
            "cis_id": vulnerability.cisID,
            "name": vulnerability.name,
            "operation": vulnerability.fixOperation?.auditLabel ?? "unavailable",
        ])
    }

    func logFixResult(_ vulnerability: Vulnerability, success: Bool) {
        write(event: "fix_result", fields: [
            "cis_id": vulnerability.cisID,
            "name": vulnerability.name,
            "success": String(success),
        ])
    }

    func logFixExecutionError(_ vulnerability: Vulnerability, message: String) {
        write(event: "fix_execution_error", fields: [
            "cis_id": vulnerability.cisID,
            "name": vulnerability.name,
            "message": redact(message),
        ])
    }

    func logAdminError(code: Int, message: String) {
        write(event: "helper_error", fields: [
            "code": String(code),
            "message": redact(message),
        ])
    }

    var logFileURL: URL { logURL }

    func recentLines(limit: Int = 600) -> [String] {
        guard let raw = try? String(contentsOf: logURL, encoding: .utf8) else { return [] }
        return Array(raw.split(separator: "\n").suffix(limit).map(String.init))
    }

    private func write(event: String, fields: [String: String]) {
        queue.async {
            var record = fields
            record["timestamp"] = ISO8601DateFormatter().string(from: Date())
            record["event"] = event
            guard JSONSerialization.isValidJSONObject(record),
                  var data = try? JSONSerialization.data(withJSONObject: record, options: [.sortedKeys]) else { return }
            data.append(0x0A)

            if !FileManager.default.fileExists(atPath: self.logURL.path) {
                FileManager.default.createFile(
                    atPath: self.logURL.path,
                    contents: nil,
                    attributes: [.posixPermissions: 0o600]
                )
            }
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: self.logURL.path)
            guard let handle = try? FileHandle(forWritingTo: self.logURL) else { return }
            defer { try? handle.close() }
            do {
                try handle.seekToEnd()
                try handle.write(contentsOf: data)
            } catch {
                return
            }
        }
    }

    private func redact(_ value: String) -> String {
        var result = value.replacingOccurrences(
            of: NSHomeDirectory(),
            with: "$HOME",
            options: [.caseInsensitive]
        )
        result = result.replacingOccurrences(
            of: #"(?i)(token|password|secret|authorization)\s*[:=]\s*\S+"#,
            with: "$1=[REDACTED]",
            options: .regularExpression
        )
        return String(result.prefix(2_000))
    }
}
