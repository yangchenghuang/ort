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

package com.here.ort.reporter.reporters.webapp

import com.fasterxml.jackson.annotation.JsonInclude

import com.here.ort.model.CuratedPackage
import com.here.ort.model.CustomData
import com.here.ort.model.Identifier
import com.here.ort.model.LicenseSource
import com.here.ort.model.OrtIssue
import com.here.ort.model.OrtResult
import com.here.ort.model.Package
import com.here.ort.model.PackageCurationResult
import com.here.ort.model.PackageReference
import com.here.ort.model.Project
import com.here.ort.model.Provenance
import com.here.ort.model.RemoteArtifact
import com.here.ort.model.RuleViolation
import com.here.ort.model.ScanResult
import com.here.ort.model.ScanSummary
import com.here.ort.model.ScannerDetails
import com.here.ort.model.Severity
import com.here.ort.model.VcsInfo
import com.here.ort.model.config.CopyrightGarbage
import com.here.ort.model.config.IssueResolution
import com.here.ort.model.config.OrtConfiguration
import com.here.ort.model.config.PathExclude
import com.here.ort.model.config.Resolutions
import com.here.ort.model.config.RuleViolationResolution
import com.here.ort.model.config.ScopeExclude
import com.here.ort.model.jsonMapper
import com.here.ort.model.licenses.LicenseConfiguration
import com.here.ort.model.readValue
import com.here.ort.model.utils.FindingsMatcher
import com.here.ort.model.yamlMapper
import com.here.ort.reporter.DefaultLicenseTextProvider
import com.here.ort.reporter.DefaultResolutionProvider
import com.here.ort.reporter.ReporterInput
import com.here.ort.reporter.model.Statistics
import com.here.ort.reporter.utils.StatisticsCalculator
import com.here.ort.spdx.SpdxExpression
import com.here.ort.utils.DeclaredLicenseProcessor
import com.here.ort.utils.ProcessedDeclaredLicense
import com.here.ort.utils.expandTilde

import java.io.File
import java.time.Instant
import java.util.SortedMap
import java.util.SortedSet

fun main() {
    val ortResult = File("~/evaluator/mime-types/evaluation-result.json").expandTilde().readValue<OrtResult>()

    val resolutionProvider = DefaultResolutionProvider()
    resolutionProvider.add(ortResult.getResolutions())
    File("~/git/oss/configuration/resolutions.yml").expandTilde().readValue<Resolutions>()
        .let { resolutionProvider.add(it) }

    val licenseConfiguration =
        File("~/git/oss/configuration/licenses.yml").expandTilde().readValue<LicenseConfiguration>()

    val input = ReporterInput(
        ortResult = ortResult,
        ortConfig = OrtConfiguration(),
        resolutionProvider = resolutionProvider,
        licenseTextProvider = DefaultLicenseTextProvider(),
        copyrightGarbage = CopyrightGarbage(),
        licenseConfiguration = licenseConfiguration
    )

    val webAppModel = WebAppModelFactory().create(input)

    val json = jsonMapper.writerWithDefaultPrettyPrinter().writeValueAsString(webAppModel)
    println(json)

    File("~/web-app-model.json").expandTilde().writeText(json)

    // TODO: - License finding curations
    //       - Global list for scope names
    //       - Other global lists? E.g. identifiers?
}

class WebAppModelFactory {
    fun create(input: ReporterInput): WebAppModel {
        val builder = WebAppModelBuilder(input)

        input.ortResult.analyzer?.result?.projects?.forEach { project ->
            builder.addProject(project)
        }

        input.ortResult.analyzer?.result?.packages?.forEach { curatedPkg ->
            builder.addPackage(curatedPkg)
        }

        input.ortResult.evaluator?.violations?.forEach { ruleViolation ->
            builder.addRuleViolation(ruleViolation)
        }

        return builder.build()
    }
}

class WebAppModelBuilder(val input: ReporterInput) {
    private val packages = mutableListOf<WebAppPackage>()
    private val dependencyTrees = mutableListOf<WebAppTreeNode>()
    private val scanResults = mutableListOf<WebAppScanResult>()
    private val copyrights = mutableListOf<String>()
    private val licenses = mutableListOf<String>()
    private val declaredLicenseStats = mutableMapOf<Int, MutableSet<Int>>()
    private val detectedLicenseStats = mutableMapOf<Int, MutableSet<Int>>()
    private val issues = mutableListOf<WebAppOrtIssue>()
    private val issueResolutions = mutableListOf<IssueResolution>()
    private val pathExcludes = mutableListOf<PathExclude>()
    private val scopeExcludes = mutableListOf<ScopeExclude>()
    private val violations = mutableListOf<WebAppRuleViolation>()
    private val violationResolutions = mutableListOf<RuleViolationResolution>()

    private val findingsMatcher = FindingsMatcher()

    fun build(): WebAppModel {
        input.ortResult.analyzer?.result?.projects?.forEach { project ->
            val projectIndex = packages.indexOfFirst { it.id == project.id }
            addDependencyTree(project, projectIndex)
        }

        return WebAppModel(
            packages = packages,
            dependencyTrees = dependencyTrees,
            scanResults = scanResults,
            copyrights = copyrights.toSortedSet(),
            licenses = licenses.toSortedSet(),
            declaredLicenseStats = declaredLicenseStats.mapValuesTo(sortedMapOf()) { it.value.size },
            detectedLicenseStats = detectedLicenseStats.mapValuesTo(sortedMapOf()) { it.value.size },
            issues = issues,
            issueResolutions = issueResolutions,
            violations = violations,
            violationResolutions = violationResolutions,
            pathExcludes = pathExcludes,
            scopeExcludes = scopeExcludes,
            statistics = StatisticsCalculator().getStatistics(input.ortResult, input.resolutionProvider),
            repositoryConfiguration = yamlMapper.writeValueAsString(input.ortResult.repository.config),
            customData = input.ortResult.data
        )
    }

    fun addProject(project: Project) {
        val scanResultIndices = sortedSetOf<Int>()
        val detectedLicenses = sortedSetOf<Int>()
        val findings = mutableListOf<WebAppFinding>()
        val issueIndices = sortedSetOf<Int>()

        val applicablePathExcludes = input.ortResult.getExcludes().findPathExcludes(project, input.ortResult)
        val pathExcludeIndices = pathExcludes.addIfRequired(applicablePathExcludes)

        val webAppPackage = WebAppPackage(
            id = project.id,
            isProject = true,
            definitionFilePath = project.definitionFilePath,
            purl = project.id.toPurl(), // TODO: Add PURL to Project class.
            declaredLicenses = project.declaredLicenses,
            declaredLicensesProcessed = project.declaredLicensesProcessed,
            detectedLicenses = detectedLicenses,
            concludedLicense = null,
            description = "",
            homepageUrl = project.homepageUrl,
            binaryArtifact = RemoteArtifact.EMPTY, // Should be nullable?
            sourceArtifact = RemoteArtifact.EMPTY, // Should be nullable?
            vcs = project.vcs,
            vcsProcessed = project.vcsProcessed,
            curations = emptyList(),
            paths = mutableSetOf(),
            levels = sortedSetOf(0),
            scanResults = scanResultIndices,
            findings = findings,
            isExcluded = applicablePathExcludes.isNotEmpty(),
            pathExcludes = pathExcludeIndices,
            scopeExcludes = sortedSetOf(),
            issues = issueIndices
        )

        val packageIndex = packages.addIfRequired(webAppPackage)

        project.declaredLicensesProcessed.allLicenses.forEach { license ->
            val licenseIndex = licenses.addIfRequired(license)
            declaredLicenseStats.count(licenseIndex, packageIndex)
        }

        addAnalyzerIssues(issueIndices, project.id, packageIndex)

        input.ortResult.getScanResultsForId(project.id).mapTo(scanResultIndices) { result ->
            convertScanResult(result, findings, packageIndex)
        }.toSortedSet()

        findings.filter { it.type == WebAppFindingType.LICENSE }.mapTo(detectedLicenses) { it.index }
    }

    fun addPackage(curatedPkg: CuratedPackage) {
        val pkg = curatedPkg.pkg

        val scanResultIndices = sortedSetOf<Int>()
        val detectedLicenses = sortedSetOf<Int>()
        val findings = mutableListOf<WebAppFinding>()
        val issueIndices = sortedSetOf<Int>()

        val isExcluded = input.ortResult.isPackageExcluded(curatedPkg.pkg.id)
        val (applicablePathExcludes, applicableScopeExcludes) = if (isExcluded) {
            Pair(input.ortResult.findPathExcludes(pkg), input.ortResult.findScopeExcludes(pkg))
        } else {
            Pair(emptySet(), emptySet())
        }

        val pathExcludeIndices = pathExcludes.addIfRequired(applicablePathExcludes)
        val scopeExcludeIndices = scopeExcludes.addIfRequired(applicableScopeExcludes)

        val webAppPackage = WebAppPackage(
            id = pkg.id,
            isProject = false,
            definitionFilePath = "",
            purl = pkg.purl,
            declaredLicenses = pkg.declaredLicenses,
            declaredLicensesProcessed = pkg.declaredLicensesProcessed,
            detectedLicenses = detectedLicenses,
            concludedLicense = pkg.concludedLicense,
            description = pkg.description,
            homepageUrl = pkg.homepageUrl,
            binaryArtifact = pkg.binaryArtifact,
            sourceArtifact = pkg.sourceArtifact,
            vcs = pkg.vcs,
            vcsProcessed = pkg.vcsProcessed,
            curations = curatedPkg.curations,
            paths = mutableSetOf(),
            levels = sortedSetOf(),
            scanResults = scanResultIndices,
            findings = findings,
            isExcluded = isExcluded,
            pathExcludes = pathExcludeIndices,
            scopeExcludes = scopeExcludeIndices,
            issues = issueIndices
        )

        val packageIndex = packages.addIfRequired(webAppPackage)

        pkg.declaredLicensesProcessed.allLicenses.forEach { license ->
            val licenseIndex = licenses.addIfRequired(license)
            declaredLicenseStats.count(licenseIndex, packageIndex)
        }

        addAnalyzerIssues(issueIndices, pkg.id, packageIndex)

        input.ortResult.getScanResultsForId(pkg.id).mapTo(scanResultIndices) { result ->
            convertScanResult(result, findings, packageIndex)
        }.toSortedSet()

        findings.filter { it.type == WebAppFindingType.LICENSE }.mapTo(detectedLicenses) { it.index }
    }

    private fun addAnalyzerIssues(indices: SortedSet<Int>, id: Identifier, packageId: Int) {
        input.ortResult.analyzer?.result?.issues?.get(id)?.let { analyzerIssues ->
            addIssues(indices, analyzerIssues, WebAppOrtIssueType.ANALYZER, packageId, -1, null)
        }
    }

    fun addRuleViolation(ruleViolation: RuleViolation) {
        val resolutionIndices = addResolutions(ruleViolation)
        val packageId = packages.indexOfFirst { it.id == ruleViolation.pkg }

        val webAppViolation = WebAppRuleViolation(
            rule = ruleViolation.rule,
            packageId = packageId,
            license = ruleViolation.license,
            licenseSource = ruleViolation.licenseSource,
            severity = ruleViolation.severity,
            message = ruleViolation.message,
            howToFix = ruleViolation.howToFix,
            resolutions = resolutionIndices
        )

        violations += webAppViolation
    }

    private fun convertScanResult(result: ScanResult, findings: MutableList<WebAppFinding>, packageIndex: Int): Int {
        val issueIndices = sortedSetOf<Int>()

        val webAppScanResult = WebAppScanResult(
            provenance = result.provenance,
            scanner = result.scanner,
            startTime = result.summary.startTime,
            endTime = result.summary.endTime,
            fileCount = result.summary.fileCount,
            packageVerificationCode = result.summary.packageVerificationCode,
            issues = issueIndices
        )

        val scanResultIndex = scanResults.addIfRequired(webAppScanResult)

        addIssues(issueIndices, result.summary.issues, WebAppOrtIssueType.SCANNER, packageIndex, scanResultIndex, null)
        addLicensesAndCopyrights(result.summary, scanResultIndex, packageIndex, findings)

        return scanResultIndex
    }

    private fun addDependencyTree(project: Project, projectIndex: Int) {
        fun PackageReference.toWebAppTreeNode(scope: String, path: List<Int>): WebAppTreeNode {
            val packageIndex = packages.indexOfFirst { it.id == id }
            val issueIndices = sortedSetOf<Int>()
            if (packageIndex >= 0) {
                val packagePath = WebAppPackagePath(
                    project = projectIndex,
                    scope = scope,
                    packages = path
                )

                packages[packageIndex].paths += packagePath
                packages[packageIndex].levels += path.size

                addIssues(issueIndices, issues, WebAppOrtIssueType.ANALYZER, packageIndex, -1, packagePath)
            }

            return WebAppTreeNode(
                title = id.toCoordinates(),
                pkg = packageIndex,
                children = dependencies.map { it.toWebAppTreeNode(scope, path + packageIndex) },
                pathExcludes = sortedSetOf(),
                scopeExcludes = sortedSetOf(),
                issues = issueIndices
            )
        }

        val scopeTrees = project.scopes.map { scope ->
            val subTrees = scope.dependencies.map { it.toWebAppTreeNode(scope.name, listOf(projectIndex)) }

            val applicableScopeExcludes = input.ortResult.getExcludes().findScopeExcludes(scope)
            val scopeExcludeIndices = scopeExcludes.addIfRequired(applicableScopeExcludes)

            WebAppTreeNode(
                title = scope.name,
                pkg = -1,
                children = subTrees,
                pathExcludes = sortedSetOf(),
                scopeExcludes = scopeExcludeIndices,
                issues = sortedSetOf()
            )
        }

        val webAppPackage = packages[projectIndex]

        val tree = WebAppTreeNode(
            title = project.id.toCoordinates(),
            pkg = projectIndex,
            children = scopeTrees,
            pathExcludes = webAppPackage.pathExcludes,
            scopeExcludes = sortedSetOf(),
            issues = sortedSetOf()
        )

        dependencyTrees += tree
    }

    private fun addIssues(
        indices: SortedSet<Int>,
        issues: List<OrtIssue>,
        type: WebAppOrtIssueType,
        packageId: Int,
        scanResultId: Int,
        path: WebAppPackagePath?
    ) {
        val webAppIssues = issues.map { issue ->
            val resolutionIndices = addResolutions(issue)

            WebAppOrtIssue(
                timestamp = issue.timestamp,
                type = type,
                source = issue.source,
                message = issue.message,
                severity = issue.severity,
                resolutions = resolutionIndices,
                packageId = packageId,
                scanResultId = scanResultId,
                path = path
            )
        }

        indices += this.issues.addIfRequired(webAppIssues)
    }

    private fun addResolutions(issue: OrtIssue): SortedSet<Int> {
        val matchingResolutions = input.resolutionProvider.getIssueResolutionsFor(issue)

        return issueResolutions.addIfRequired(matchingResolutions)
    }


    private fun addResolutions(ruleViolation: RuleViolation): SortedSet<Int> {
        val matchingResolutions = input.resolutionProvider.getRuleViolationResolutionsFor(ruleViolation)

        return violationResolutions.addIfRequired(matchingResolutions)
    }

    private fun addLicensesAndCopyrights(
        summary: ScanSummary,
        scanResultIndex: Int,
        packageIndex: Int,
        findings: MutableList<WebAppFinding>
    ) {
        val matchedFindings = findingsMatcher.match(
            summary.licenseFindings,
            summary.copyrightFindings
        )

        // TODO: Apply license curations.
        // TODO: Apply copyright garbage and statement processor?

        matchedFindings.forEach { licenseFindings ->

            licenseFindings.copyrights.forEach { copyrightFinding ->
                val copyrightIndex = copyrights.addIfRequired(copyrightFinding.statement)

                copyrightFinding.locations.forEach { location ->
                    findings += WebAppFinding(
                        type = WebAppFindingType.COPYRIGHT,
                        index = copyrightIndex,
                        path = location.path,
                        startLine = location.startLine,
                        endLine = location.endLine,
                        scanResultId = scanResultIndex
                    )
                }
            }

            val licenseIndex = licenses.addIfRequired(licenseFindings.license)
            detectedLicenseStats.count(licenseIndex, packageIndex)

            licenseFindings.locations.forEach { location ->
                findings += WebAppFinding(
                    type = WebAppFindingType.LICENSE,
                    index = licenseIndex,
                    path = location.path,
                    startLine = location.startLine,
                    endLine = location.endLine,
                    scanResultId = scanResultIndex
                )
            }
        }
    }

    private fun <T> MutableList<T>.addIfRequired(value: T): Int {
        val index = indexOf(value)

        return if (index == -1) {
            add(value)
            lastIndex
        } else {
            index
        }
    }

    private fun <T> MutableList<T>.addIfRequired(values: Collection<T>): SortedSet<Int> {
        val indices = sortedSetOf<Int>()

        values.forEach { value ->
            val index = indexOf(value)

            if (index == -1) {
                add(value)
                indices += lastIndex
            } else {
                indices += index
            }
        }

        return indices
    }

    private fun MutableMap<Int, MutableSet<Int>>.count(key: Int, value: Int) {
        this.getOrPut(key) { mutableSetOf() } += value
    }

    // TODO: Move this function to OrtResult. Consider changing PackageEntry to contain the excludes instead of only isExcluded.
    private fun OrtResult.findPathExcludes(pkg: Package): Set<PathExclude> {
        val excludes = mutableSetOf<PathExclude>()

        getProjects().forEach { project ->
            if (project.dependsOn(pkg.id)) {
                excludes += getExcludes().findPathExcludes(project, this)
            }
        }

        return excludes
    }

    // TODO: Move this function to OrtResult.
    private fun OrtResult.findScopeExcludes(pkg: Package): Set<ScopeExclude> {
        val excludes = mutableSetOf<ScopeExclude>()

        getProjects().forEach { project ->
            project.scopes.forEach { scope ->
                if (scope.contains(pkg.id)) {
                    excludes += getExcludes().findScopeExcludes(scope)
                }
            }
        }

        return excludes
    }

    // TODO: Move to Project.
    private fun Project.dependsOn(id: Identifier): Boolean = scopes.any { it.contains(id) }
}

data class WebAppModel(
    val packages: List<WebAppPackage>,
    val dependencyTrees: List<WebAppTreeNode>,
    val scanResults: List<WebAppScanResult>,
    val copyrights: SortedSet<String>,
    val licenses: SortedSet<String>,
    val declaredLicenseStats: SortedMap<Int, Int>,
    val detectedLicenseStats: SortedMap<Int, Int>,
    val issues: List<WebAppOrtIssue>,
    val issueResolutions: List<IssueResolution>,
    val violations: List<WebAppRuleViolation>,
    val violationResolutions: List<RuleViolationResolution>,
    val pathExcludes: List<PathExclude>,
    val scopeExcludes: List<ScopeExclude>,
    val statistics: Statistics,
    val repositoryConfiguration: String,
    val customData: CustomData
)

data class WebAppPackage(
    val id: Identifier,
    val isProject: Boolean,
    val definitionFilePath: String,
    val purl: String = id.toPurl(),
    val declaredLicenses: SortedSet<String>,
    val declaredLicensesProcessed: ProcessedDeclaredLicense = DeclaredLicenseProcessor.process(declaredLicenses),
    val detectedLicenses: SortedSet<Int>,
    @JsonInclude(JsonInclude.Include.NON_NULL)
    val concludedLicense: SpdxExpression? = null,
    val description: String,
    val homepageUrl: String,
    val binaryArtifact: RemoteArtifact,
    val sourceArtifact: RemoteArtifact,
    val vcs: VcsInfo,
    val vcsProcessed: VcsInfo = vcs.normalize(),
    val curations: List<PackageCurationResult>,
    val paths: MutableSet<WebAppPackagePath>,
    val levels: SortedSet<Int>,
    val scanResults: SortedSet<Int>,
    val findings: List<WebAppFinding>,
    val isExcluded: Boolean,
    val pathExcludes: SortedSet<Int>,
    val scopeExcludes: SortedSet<Int>,
    val issues: SortedSet<Int>
)

data class WebAppPackagePath(
    val project: Int,
    val scope: String,
    val packages: List<Int>
)

data class WebAppScanResult(
    val provenance: Provenance,
    val scanner: ScannerDetails,
    val startTime: Instant,
    val endTime: Instant,
    val fileCount: Int,
    val packageVerificationCode: String,
    val issues: SortedSet<Int>
)

enum class WebAppFindingType {
    COPYRIGHT, LICENSE
}

data class WebAppFinding(
    val type: WebAppFindingType,
    val index: Int,
    val path: String,
    val startLine: Int,
    val endLine: Int,
    val scanResultId: Int
)

enum class WebAppOrtIssueType {
    ANALYZER, SCANNER
}

data class WebAppOrtIssue(
    val timestamp: Instant = Instant.now(),
    val type: WebAppOrtIssueType,
    val source: String,
    val message: String,
    val severity: Severity = Severity.ERROR,
    val resolutions: SortedSet<Int>,
    val packageId: Int,
    val scanResultId: Int, // Only for scanner issues.
    @JsonInclude(JsonInclude.Include.NON_NULL)
    val path: WebAppPackagePath? // Only for issues in package references.
)

data class WebAppRuleViolation(
    val rule: String,
    val packageId: Int,
    @JsonInclude(JsonInclude.Include.NON_NULL)
    val license: String?,
    @JsonInclude(JsonInclude.Include.NON_NULL)
    val licenseSource: LicenseSource?,
    val severity: Severity,
    val message: String,
    val howToFix: String,
    val resolutions: SortedSet<Int>
)

data class WebAppTreeNode(
    val title: String,
    val key: Int = nextKey(),
    val pkg: Int,
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    val pathExcludes: SortedSet<Int>,
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    val scopeExcludes: SortedSet<Int>,
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    val issues: SortedSet<Int>,
    val children: List<WebAppTreeNode>
) {
    companion object {
        private var lastKey = -1
        private fun nextKey() = ++lastKey
    }
}
