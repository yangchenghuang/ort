package com.here.provenanceanalyzer.functionaltest

import com.here.provenanceanalyzer.managers.NPM

import io.kotlintest.matchers.shouldBe
import io.kotlintest.specs.StringSpec

import java.io.File

class NpmTest : StringSpec() {
    init {
        "yarn dependencies are resolved correctly" {
            val expectedDependencies = readResource("/projects/synthetic/project-npm-expected-yarn-dependencies.txt")
            val resolvedDependencies = NPM.resolveYarnDependencies(
                    File("src/funTest/resources/projects/synthetic/project-npm"))

            val resolvedDependencyList = resolvedDependencies.toString().lines().filter { it.isNotEmpty() }
            resolvedDependencyList.size shouldBe expectedDependencies.size
            resolvedDependencyList.zip(expectedDependencies).forEach { (resolved, expected) ->
                resolved shouldBe expected
            }
        }

        "NPM dependencies are resolved correctly" {
            val expectedDependencies = readResource("/projects/synthetic/project-npm-expected-npm-dependencies.txt")
            val resolvedDependencies = NPM.resolveNpmDependencies(
                    File("src/funTest/resources/projects/synthetic/project-npm"))

            val resolvedDependencyList = resolvedDependencies.toString().lines().filter { it.isNotEmpty() }
            resolvedDependencyList.size shouldBe expectedDependencies.size
            resolvedDependencyList.zip(expectedDependencies).forEach { (resolved, expected) ->
                resolved shouldBe expected
            }
        }
    }
}
