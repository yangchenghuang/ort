/*
 * Copyright (C) 2020 HERE Europe B.V.
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

package org.ossreviewtoolkit.reporter.reporters

import java.io.File

import org.ossreviewtoolkit.reporter.Reporter
import org.ossreviewtoolkit.reporter.ReporterInput
import org.ossreviewtoolkit.reporter.utils.SpdxDocumentModelMapper
import org.ossreviewtoolkit.spdx.SpdxModelMapper.FileFormat

/**
 * Creates YAML and JSON SPDX documents mainly targeting the use case of sharing information about the dependencies
 * used, similar to e.g. a NOTICE file. Information about the project / sub-module structure as well as project VCS
 * locations are deliberately omitted. The underlying idea is to clearly separate this mentioned use case from a maximum
 * detailed report which could be preferred for archiving or internal use only. The latter could be implemented either
 * as a future extension of this [SpdxDocumentReporter] or as a separate [Reporter].
 *
 * The option keys [CREATION_INFO_COMMENT], [DOCUMENT_COMMENT] and [DOCUMENT_NAME]
 * can be provided to [generateReport] to inject the corresponding values as meta-data into the produced [SpdxDocument].
 * The option key [OUTPUT_FILE_FORMATS] specifies a comma separated list of [FileFormat]s, whereas [FileFormat.values]
 * is used by default.
 */
class SpdxDocumentReporter : Reporter {
    companion object {
        const val CREATION_INFO_COMMENT = "creationInfo.comment"
        const val DOCUMENT_COMMENT = "document.comment"
        const val DOCUMENT_NAME = "document.name"
        const val OUTPUT_FILE_FORMATS = "output.file.formats"

        private const val DOCUMENT_NAME_DEFAULT_VALUE = "Unnamed document"
    }

    override val reporterName = "SpdxDocument"

    override fun generateReport(
        input: ReporterInput,
        outputDir: File,
        options: Map<String, String>
    ): List<File> {
        val outputFileFormats = options[OUTPUT_FILE_FORMATS]
            ?.split(",")
            ?.map { FileFormat.valueOf(it.toUpperCase()) }
            ?.distinct()
            ?: listOf(FileFormat.YAML)

        val params = SpdxDocumentModelMapper.SpdxDocumentParams(
            documentName = options.getOrDefault(DOCUMENT_NAME, DOCUMENT_NAME_DEFAULT_VALUE),
            documentComment = options.getOrDefault(DOCUMENT_COMMENT, ""),
            creationInfoComment = options.getOrDefault(CREATION_INFO_COMMENT, "")
        )

        val spdxDocument = SpdxDocumentModelMapper.map(
            input.ortResult,
            input.packageConfigurationProvider,
            input.licenseTextProvider,
            params
        )

        return outputFileFormats.map { fileFormat ->
            val serializedDocument = fileFormat.mapper.writeValueAsString(spdxDocument)

            outputDir.resolve("document.spdx.${fileFormat.fileExtension}").apply {
                bufferedWriter().use { it.write(serializedDocument) }
            }
        }
    }
}
