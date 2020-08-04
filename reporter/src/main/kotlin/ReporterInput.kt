/*
 * Copyright (C) 2019 HERE Europe B.V.
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

package org.ossreviewtoolkit.reporter

import org.ossreviewtoolkit.model.OrtIssue
import org.ossreviewtoolkit.model.OrtResult
import org.ossreviewtoolkit.model.RuleViolation
import org.ossreviewtoolkit.model.config.CopyrightGarbage
import org.ossreviewtoolkit.model.config.OrtConfiguration
import org.ossreviewtoolkit.model.licenses.DefaultLicenseInfoProvider
import org.ossreviewtoolkit.model.licenses.LicenseConfiguration
import org.ossreviewtoolkit.model.licenses.LicenseInfoResolver
import org.ossreviewtoolkit.model.utils.DefaultResolutionProvider
import org.ossreviewtoolkit.model.utils.PackageConfigurationProvider
import org.ossreviewtoolkit.model.utils.ResolutionProvider
import org.ossreviewtoolkit.model.utils.SimplePackageConfigurationProvider

/**
 * A bundle of input to be used by [Reporter] implementations.
 */
data class ReporterInput(
    /**
     * The [OrtResult] to generate a report for.
     */
    val ortResult: OrtResult,

    /**
     * The [OrtConfiguration], can be used by the reporter to adapt the output based on how ORT is configured.
     */
    val ortConfig: OrtConfiguration = OrtConfiguration(),

    /**
     * A [PackageConfigurationProvider], can be used to obtain [PackageConfiguration]s for packages.
     */
    val packageConfigurationProvider: PackageConfigurationProvider = SimplePackageConfigurationProvider(),

    /**
     * A [ResolutionProvider], can be used to check which [OrtIssue]s and [RuleViolation]s are resolved.
     */
    val resolutionProvider: ResolutionProvider = DefaultResolutionProvider(),

    /**
     * A [LicenseTextProvider], can be used to integrate licenses texts into reports.
     */
    val licenseTextProvider: LicenseTextProvider = DefaultLicenseTextProvider(),

    /**
     * A [CopyrightGarbage] container, can be used to clean up copyrights used in reports.
     */
    val copyrightGarbage: CopyrightGarbage = CopyrightGarbage(),

    /**
     * A resolver for license information for the projects and packages contained in [ortResult].
     */
    val licenseInfoResolver: LicenseInfoResolver = LicenseInfoResolver(
        provider = DefaultLicenseInfoProvider(ortResult, packageConfigurationProvider),
        copyrightGarbage = copyrightGarbage
    ),

    /**
     * A [LicenseConfiguration], can be used to handle licenses based on the user's configuration, for example to
     * determine which licenses to include in a notice file.
     */
    val licenseConfiguration: LicenseConfiguration = LicenseConfiguration()
)
