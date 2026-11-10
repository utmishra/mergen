//
//  ScanManager.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation
import Combine

class ScanManager: ObservableObject {
    @Published var scanResults: [Vulnerability] = []
    @Published var progress: Double = 0
    @Published var scanning: Bool = false
    @Published var fixingIDs:     Set<UUID>  = []
    @Published var fixResults:    [UUID: Bool] = [:]   // true = check passed after fix
    @Published var fixCancelled:  Set<UUID>  = []      // user dismissed password dialog
    private var totalModules: Int = 0
    
    func startScan(category: String?) {
        // A rescan replaces the previous snapshot. Keeping old objects here
        // causes every run to append another copy of all findings.
        guard !scanning else { return }
        scanResults.removeAll(keepingCapacity: true)
        progress = 0
        fixingIDs.removeAll()
        fixResults.removeAll()
        fixCancelled.removeAll()
        scanning = true
        AuditLogger.shared.logScanStart(category: category)

        DispatchQueue.global(qos: .userInitiated).async {
            let scanner = Scanner()
            if let category = category {
                scanner.loadModules(category: category)
            } else {
                scanner.loadModules()
            }
            self.totalModules = scanner.moduleCount
            var completedModules = 0

            scanner.modules.forEach { module in
                let timeout: DispatchTimeInterval = .seconds(15)

                let semaphore = DispatchSemaphore(value: 0)

                let taskQueue = DispatchQueue(label: "com.sametsazak.mergen", qos: .userInteractive)
                taskQueue.async {
                    module.check()
                    semaphore.signal()
                }

                let result = semaphore.wait(timeout: DispatchTime.now() + timeout)

                if result == .timedOut {
                    module.checkstatus = "Yellow"
                    module.status = "Check timed out"
                }

                AuditLogger.shared.logCheckResult(module)

                DispatchQueue.main.async {
                    self.scanResults.append(module)
                    completedModules += 1
                    self.progress = Double(completedModules) / Double(self.totalModules)

                    if self.progress >= 0.9999 {
                        self.scanning = false
                        AuditLogger.shared.logScanComplete(self.scanResults)
                    }
                }
            }
        }
    }


    func resetScan() {
        scanning = false
        progress = 0.0
        scanResults = []
        fixingIDs    = []
        fixResults   = [:]
        fixCancelled = []
    }

    // MARK: - Auto-Remediation

    /// Applies the fix for a single vulnerability, then re-runs its check.
    /// Success is determined by whether the check passes after the fix, not by exit code.
    func applyFix(for vulnerability: Vulnerability) {
        guard vulnerability.isAutoFixable,
              let operation = vulnerability.fixOperation else { return }
        let id = vulnerability.id
        fixingIDs.insert(id)
        AuditLogger.shared.logFixStart(vulnerability)

        DispatchQueue.global(qos: .userInitiated).async {
            let result = FixManager.run(operation)

            if case .executionError(let message) = result {
                AuditLogger.shared.logFixExecutionError(vulnerability, message: message)
            }

            // Re-run the check unless the user cancelled the password dialog.
            if case .cancelled = result {
                AuditLogger.shared.logFixResult(vulnerability, success: false)
                DispatchQueue.main.async {
                    self.fixingIDs.remove(id)
                    self.fixCancelled.insert(id)
                    self.objectWillChange.send()
                }
                return
            }

            vulnerability.check()
            let success = vulnerability.checkstatus == "Green"
            AuditLogger.shared.logFixResult(vulnerability, success: success)

            DispatchQueue.main.async {
                self.fixingIDs.remove(id)
                self.fixResults[id] = success
                self.objectWillChange.send()
            }
        }
    }

    /// Applies reviewed, typed user-level fixes one at a time. Privileged fixes
    /// are not executable until the authenticated helper is shipped.
    func fixAll(_ vulnerabilities: [Vulnerability]) {
        // Defense in depth: callers cannot batch confirmation-required or
        // guided remediations even if the UI passes them accidentally.
        let fixable    = vulnerabilities.filter { $0.isBatchFixable }
        guard !fixable.isEmpty else { return }

        fixingIDs.formUnion(fixable.map { $0.id })
        for v in fixable { AuditLogger.shared.logFixStart(v) }

        DispatchQueue.global(qos: .userInitiated).async {

            for v in fixable {
                guard let operation = v.fixOperation else { continue }
                let result = FixManager.run(operation)
                if case .executionError(let message) = result {
                    AuditLogger.shared.logFixExecutionError(v, message: message)
                }
                v.check()
                let success = v.checkstatus == "Green"
                AuditLogger.shared.logFixResult(v, success: success)
                DispatchQueue.main.async {
                    self.fixingIDs.remove(v.id)
                    self.fixResults[v.id] = success
                    self.objectWillChange.send()
                }
            }

        }
    }
}


