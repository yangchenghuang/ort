/*
 * Copyright (C) 2017-2019 HERE Europe B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * License-Filename: LICENSE
 */

package org.ossreviewtoolkit.reporter.utils

import org.ossreviewtoolkit.model.Identifier
import org.ossreviewtoolkit.model.LicenseSource
import org.ossreviewtoolkit.model.OrtIssue
import org.ossreviewtoolkit.model.OrtResult
import org.ossreviewtoolkit.model.Project
import org.ossreviewtoolkit.model.RemoteArtifact
import org.ossreviewtoolkit.model.RuleViolation
import org.ossreviewtoolkit.model.VcsInfo
import org.ossreviewtoolkit.model.config.Excludes
import org.ossreviewtoolkit.model.config.ScopeExclude
import org.ossreviewtoolkit.model.licenses.LicenseInfoResolver
import org.ossreviewtoolkit.model.utils.ResolutionProvider
import org.ossreviewtoolkit.reporter.utils.ReportTableModel.DependencyRow
import org.ossreviewtoolkit.reporter.utils.ReportTableModel.IssueRow
import org.ossreviewtoolkit.reporter.utils.ReportTableModel.IssueTable
import org.ossreviewtoolkit.reporter.utils.ReportTableModel.ProjectTable
import org.ossreviewtoolkit.reporter.utils.ReportTableModel.ResolvableIssue
import org.ossreviewtoolkit.reporter.utils.ReportTableModel.SummaryRow
import org.ossreviewtoolkit.reporter.utils.ReportTableModel.SummaryTable

private fun Collection<ResolvableIssue>.filterUnresolved() = filter { !it.isResolved }

private fun Project.getScopesForDependencies(excludes: Excludes): Map<Identifier, Map<String, List<ScopeExclude>>> {
    val result = mutableMapOf<Identifier, MutableMap<String, List<ScopeExclude>>>()

    scopes.forEach { scope ->
        scope.collectDependencies().forEach { dependency ->
            result.getOrPut(dependency, { mutableMapOf() })
                .getOrPut(scope.name, { excludes.findScopeExcludes(scope.name) })
        }
    }

    return result
}

/**
 * A mapper which converts an [OrtIssue] to a [ReportTableModel] view model.
 */
class ReportTableModelMapper(
    private val resolutionProvider: ResolutionProvider
) {
    companion object {
        private val VIOLATION_COMPARATOR = compareBy<ReportTableModel.ResolvableViolation>(
            { it.isResolved },
            { it.violation.severity },
            { it.violation.rule },
            { it.violation.pkg },
            { it.violation.license.toString() },
            { it.violation.message },
            { it.resolutionDescription }
        )
    }

    private fun OrtIssue.toResolvableIssue(): ResolvableIssue {
        val resolutions = resolutionProvider.getIssueResolutionsFor(this)
        return ResolvableIssue(
            source = this@toResolvableIssue.source,
            description = this@toResolvableIssue.toString(),
            resolutionDescription = buildString {
                if (resolutions.isNotEmpty()) {
                    append(resolutions.joinToString(prefix = "\nResolved by: ") {
                        "${it.reason} - ${it.comment}"
                    })
                }
            },
            isResolved = resolutions.isNotEmpty(),
            severity = severity
        )
    }

    private fun RuleViolation.toResolvableEvaluatorIssue(): ReportTableModel.ResolvableViolation {
        val resolutions = resolutionProvider.getRuleViolationResolutionsFor(this)
        return ReportTableModel.ResolvableViolation(
            violation = this,
            resolutionDescription = buildString {
                if (resolutions.isNotEmpty()) {
                    append(resolutions.joinToString(prefix = "\nResolved by: ") {
                        "${it.reason} - ${it.comment}"
                    })
                }
            },
            isResolved = resolutions.isNotEmpty()
        )
    }

    fun mapToReportTableModel(
        ortResult: OrtResult,
        licenseInfoResolver: LicenseInfoResolver
    ): ReportTableModel {
        val issueSummaryRows = mutableMapOf<Identifier, IssueRow>()
        val summaryRows = mutableMapOf<Identifier, SummaryRow>()

        requireNotNull(ortResult.analyzer?.result) {
            "The provided ORT result does not contain an analyzer result."
        }

        val analyzerResult = ortResult.analyzer!!.result
        val excludes = ortResult.getExcludes()

        val scanRecord = ortResult.scanner?.results
        val analyzerIssuesForPackages = ortResult.getPackages().associateBy({ it.pkg.id }, { it.pkg.collectIssues() })

        val projectTables = analyzerResult.projects.associateWith { project ->
            val scopesForDependencies = project.getScopesForDependencies(excludes)
            val pathExcludes = excludes.findPathExcludes(project, ortResult)

            val allIds = sortedSetOf(project.id)
            allIds += project.collectDependencies()

            val projectIssues = project.collectIssues()
            val tableRows = allIds.map { id ->
                val scanResult = scanRecord?.scanResults?.find { it.id == id }

                val resolvedLicenseInfo = licenseInfoResolver.resolveLicenseInfo(id)

                val concludedLicense = resolvedLicenseInfo.licenseInfo.concludedLicenseInfo.concludedLicense
                val declaredLicenses = resolvedLicenseInfo.filter { LicenseSource.DECLARED in it.sources }
                    .sortedBy { it.license.toString() }
                val detectedLicenses = resolvedLicenseInfo.filter { LicenseSource.DETECTED in it.sources }
                    .sortedBy { it.license.toString() }

                val analyzerIssues = projectIssues[id].orEmpty() + analyzerResult.issues[id].orEmpty() +
                        analyzerIssuesForPackages[id].orEmpty()

                val scanIssues = scanResult?.results?.flatMap {
                    it.summary.issues
                }?.distinct().orEmpty()

                val packageForId = ortResult.getPackage(id)?.pkg ?: ortResult.getProject(id)?.toPackage()

                DependencyRow(
                    id = id,
                    sourceArtifact = packageForId?.sourceArtifact ?: RemoteArtifact.EMPTY,
                    vcsInfo = packageForId?.vcsProcessed ?: VcsInfo.EMPTY,
                    scopes = scopesForDependencies[id].orEmpty().toSortedMap(),
                    concludedLicense = concludedLicense,
                    declaredLicenses = declaredLicenses,
                    detectedLicenses = detectedLicenses,
                    analyzerIssues = analyzerIssues.map { it.toResolvableIssue() },
                    scanIssues = scanIssues.map { it.toResolvableIssue() }
                ).also { row ->
                    val isRowExcluded = pathExcludes.isNotEmpty()
                            || (row.scopes.isNotEmpty() && row.scopes.all { it.value.isNotEmpty() })

                    val nonExcludedAnalyzerIssues = if (isRowExcluded) emptyList() else row.analyzerIssues
                    val nonExcludedScanIssues = if (isRowExcluded) emptyList() else row.scanIssues

                    val summaryRow = SummaryRow(
                        id = row.id,
                        scopes = sortedMapOf(project.id to row.scopes),
                        concludedLicenses = row.concludedLicense?.let { setOf(it) }.orEmpty(),
                        declaredLicenses = row.declaredLicenses.mapTo(sortedSetOf()) { it.license.toString() },
                        detectedLicenses = row.detectedLicenses.mapTo(sortedSetOf()) { it.license.toString() },
                        analyzerIssues = if (nonExcludedAnalyzerIssues.isNotEmpty()) {
                            sortedMapOf(project.id to nonExcludedAnalyzerIssues)
                        } else {
                            sortedMapOf()
                        },
                        scanIssues = if (nonExcludedScanIssues.isNotEmpty()) {
                            sortedMapOf(project.id to nonExcludedScanIssues)
                        } else {
                            sortedMapOf()
                        }
                    )

                    summaryRows[row.id] = summaryRows[row.id]?.merge(summaryRow) ?: summaryRow

                    val unresolvedAnalyzerIssues = row.analyzerIssues.filterUnresolved()
                    val unresolvedScanIssues = row.scanIssues.filterUnresolved()

                    if ((unresolvedAnalyzerIssues.isNotEmpty() || unresolvedScanIssues.isNotEmpty())
                        && !isRowExcluded
                    ) {
                        val issueRow = IssueRow(
                            id = row.id,
                            analyzerIssues = if (unresolvedAnalyzerIssues.isNotEmpty()) {
                                sortedMapOf(project.id to unresolvedAnalyzerIssues)
                            } else {
                                sortedMapOf()
                            },
                            scanIssues = if (unresolvedScanIssues.isNotEmpty()) {
                                sortedMapOf(project.id to unresolvedScanIssues)
                            } else {
                                sortedMapOf()
                            }
                        )

                        issueSummaryRows[row.id] = issueSummaryRows[issueRow.id]?.merge(issueRow) ?: issueRow
                    }
                }
            }

            ProjectTable(
                tableRows,
                ortResult.getDefinitionFilePathRelativeToAnalyzerRoot(project),
                pathExcludes
            )
        }.toSortedMap()

        val issueSummaryTable = IssueTable(issueSummaryRows.values.toList().sortedBy { it.id })

        val summaryTable = SummaryTable(
            // Sort excluded rows to the end of the list.
            summaryRows.values.toList().sortedWith(compareBy({ ortResult.isExcluded(it.id) }, { it.id }))
        )

        val metadata = mutableMapOf<String, String>()
        (ortResult.data["job_parameters"] as? Map<*, *>)?.let {
            it.entries.associateTo(metadata) { (key, value) -> key.toString() to value.toString() }
        }
        (ortResult.data["process_parameters"] as? Map<*, *>)?.let {
            it.entries.associateTo(metadata) { (key, value) -> key.toString() to value.toString() }
        }

        val ruleViolations = ortResult.getRuleViolations()
            .map { it.toResolvableEvaluatorIssue() }
            .sortedWith(VIOLATION_COMPARATOR)

        return ReportTableModel(
            ortResult.repository.vcsProcessed,
            ortResult.repository.config,
            ruleViolations,
            issueSummaryTable,
            summaryTable,
            projectTables,
            metadata
        )
    }
}
