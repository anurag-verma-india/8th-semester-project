pipeline {
    agent { label 'Agent43' }

    environment {
        REPORT_DIR = 'reports'
        IMAGE_NAME = 'node-app:scan'

        // Cache dirs (persist between runs if workspace persists)
        TRIVY_CACHE_DIR = '/tmp/trivy-cache'
        GRYPE_DB_CACHE_DIR = '/tmp/grype-cache'
    }

    stages {
        stage('Prepare') {
            steps {
                sh '''
                    ip a

                    rm -rf $REPORT_DIR
                    mkdir -p $REPORT_DIR
                    rm -f $REPORT_DIR/.security_failed

                    mkdir -p $TRIVY_CACHE_DIR
                    mkdir -p $GRYPE_DB_CACHE_DIR
                '''
            }
        }

        stage('Build Docker Image') {
            steps {
                sh 'docker build -t $IMAGE_NAME .'
            }
        }

        stage('Security Scans (Parallel)') {
            parallel {
                stage('Hadolint') {
                    steps {
                        // Informational only (not part of fail gate)
                        sh 'hadolint -f json Dockerfile > $REPORT_DIR/hadolint.json || true'
                    }
                }

                stage('Semgrep') {
                    steps {
                        script {
                            /*
                             Severity Policy:
                             - FAIL on: ERROR
                             */
                            def status = sh(
                                script: '''
                                    semgrep scan \
                                      --config auto \
                                      --severity ERROR \
                                      --error \
                                      --json > $REPORT_DIR/semgrep.json
                                ''',
                                returnStatus: true
                            )
                            if (status != 0) {
                                sh 'touch $REPORT_DIR/.security_failed'
                            }
                        }
                    }
                }

                stage('Gitleaks') {
                    steps {
                        script {
                            /*
                             Severity Policy:
                             - FAIL on: ANY secret detected
                             */
                            def status = sh(
                                script: '''
                                    gitleaks detect \
                                      --source . \
                                      --report-format json \
                                      --report-path $REPORT_DIR/gitleaks.json
                                ''',
                                returnStatus: true
                            )
                            if (status != 0) {
                                sh 'touch $REPORT_DIR/.security_failed'
                            }
                        }
                    }
                }

                stage('Trivy FS') {
                    steps {
                        script {
                            /*
                             Severity Policy:
                             - FAIL on: HIGH, CRITICAL
                             */
                            def status = sh(
                                script: '''
                                    trivy fs . \
                                      --cache-dir $TRIVY_CACHE_DIR \
                                      --severity HIGH,CRITICAL \
                                      --exit-code 1 \
                                      --format json \
                                      --output $REPORT_DIR/trivy-fs.json
                                ''',
                                returnStatus: true
                            )
                            if (status != 0) {
                                sh 'touch $REPORT_DIR/.security_failed'
                            }
                        }
                    }
                }
                stage('Syft SBOM + Grype Scanning') {
                    steps {
                        script {
                            /*
                            Severity Policy:
                            - FAIL on: HIGH, CRITICAL (via Grype)
                            */

                            def status = sh(
                                script: '''
                                    syft . -o syft-json > $REPORT_DIR/syft-sbom.json
                                    SYFT_STATUS=$?
                            
                                    if [ ! -s "$REPORT_DIR/syft-sbom.json" ]; then
                                      echo "SBOM missing or empty"
                                      exit 1
                                    fi
                            
                                    grype sbom:$REPORT_DIR/syft-sbom.json \
                                      --fail-on high \
                                      --add-cpes-if-none \
                                      -o json > $REPORT_DIR/grype.json
                                    GRYPE_STATUS=$?
                            
                                    if [ $SYFT_STATUS -ne 0 ] || [ $GRYPE_STATUS -ne 0 ]; then
                                      exit 1
                                    fi
                                ''',
                                returnStatus: true
                            )

                            if (status != 0) {
                                sh 'touch $REPORT_DIR/.security_failed'
                            }
                        }
                    }
                }

                stage('Trivy Image') {
                    steps {
                        script {
                            /*
                             Severity Policy:
                             - FAIL on: HIGH, CRITICAL
                             */
                            def status = sh(
                                script: '''
                                    trivy image $IMAGE_NAME \
                                      --cache-dir $TRIVY_CACHE_DIR \
                                      --severity HIGH,CRITICAL \
                                      --exit-code 1 \
                                      --format json \
                                      --output $REPORT_DIR/trivy-image.json
                                ''',
                                returnStatus: true
                            )
                            if (status != 0) {
                                sh 'touch $REPORT_DIR/.security_failed'
                            }
                        }
                    }
                }

                stage('SonarQube') {
                    steps {
                        withSonarQubeEnv('Sonar') {
                            script {
                                /*
                                 Severity Policy:
                                 - FAIL on: scanner exit code != 0 (analysis errors)
                                 */
                                // def scannerHome = tool 'sonar-scanner'
                                def scannerHome = tool 'Sonar'
                                def scanStatus = sh(
                                    script: """
                                        # ${scannerHome}/bin/sonar-scanner \
                                        ${scannerHome}/bin/Sonar \
                                          -Dsonar.projectKey=node-todo \
                                          -Dsonar.sources=.
                                    """,
                                    returnStatus: true
                                )
                                // Always export issues for DefectDojo regardless of scan result
                                sh """
                                    curl -s -u "\${SONAR_AUTH_TOKEN}:" \
                                      "\${SONAR_HOST_URL}/api/issues/search?componentKeys=node-todo&resolved=false&ps=500" \
                                      > \$REPORT_DIR/sonarqube.json
                                """
                                if (scanStatus != 0) {
                                    sh 'touch $REPORT_DIR/.security_failed'
                                }
                            }
                        }
                    }
                }

                stage('DAST - ZAP') {
                    steps {
                        script {
                            /*
                             Severity Policy:
                             - Informational (can be upgraded to FAIL later)
                             */
                            def status = sh(
                                script: '''
                                    echo "Starting app container for DAST scan..."

                                    docker run -d -p 8080:8080 --name zap-test-app $IMAGE_NAME

                                    # Give app time to start
                                    sleep 15

                                    echo "Running OWASP ZAP Baseline Scan..."

                                    docker run --rm --network host owasp/zap2docker-stable \
                                        zap-baseline.py \
                                        -t http://localhost:8080 \
                                        -J $REPORT_DIR/zap.json || true

                                    echo "Cleaning up container..."
                                    docker stop zap-test-app || true
                                    docker rm zap-test-app || true
                                ''',
                                returnStatus: true
                            )

                            // Optional: fail gate (enable later if needed)
                            if (status != 0) {
                                sh 'touch $REPORT_DIR/.security_failed'
                            }
                        }
                    }
                }
                // 
            }
        }

        stage('Upload to DefectDojo') {
            steps {
                // withCredentials([string(credentialsId: 'defect-dojo-api-key-agent43', variable: 'DD_API_KEY')]) {
                withCredentials([string(credentialsId: 'defect-dojo-10-81-2-34', variable: 'DD_API_KEY')]) {
                    sh '''
                        # DD_URL="http://192.168.56.43:8085"
                        DD_URL="http://10.81.2.34:8085"
                        DD_PRODUCT="node-todo"
                        # Stable engagement name so reimport can match against previous scans
                        DD_ENGAGEMENT="CI-Pipeline"

                        # SCAN_TYPE: DefectDojo parser type
                        # FILE:      path to the report
                        # TEST_TITLE: optional — required when the same scan_type is uploaded
                        #             more than once (e.g. Trivy FS vs Trivy Image).
                        #             DefectDojo uses this to keep them as separate tests so
                        #             reimport compares FS-vs-FS and image-vs-image independently,
                        #             instead of marking image-only findings as mitigated.
                        upload() {
                            SCAN_TYPE="$1"
                            FILE="$2"
                            TEST_TITLE="${3:-}"

                            if [ ! -s "$FILE" ]; then
                                echo "Skipping $FILE (empty or missing)"
                                return
                            fi

                            echo "Uploading $FILE as '$SCAN_TYPE'${TEST_TITLE:+ (test_title: $TEST_TITLE)}..."

                            # reimport-scan deduplicates: ignores existing findings, closes resolved ones,
                            # reopens reintroduced ones - prevents duplicate findings across builds.
                            # test_title is passed via if/else to avoid word-splitting on spaces in the value.
                            if [ -n "$TEST_TITLE" ]; then
                                HTTP_CODE=$(curl -s -o /tmp/defectdojo-response.txt -w "%{http_code}" -X POST \
                                    "${DD_URL}/api/v2/reimport-scan/" \
                                    -H "Authorization: Token ${DD_API_KEY}" \
                                    -F "scan_type=${SCAN_TYPE}" \
                                    -F "file=@${FILE}" \
                                    -F "product_name=${DD_PRODUCT}" \
                                    -F "engagement_name=${DD_ENGAGEMENT}" \
                                    -F "auto_create_context=true" \
                                    -F "active=true" \
                                    -F "verified=false" \
                                    -F "close_old_findings=true" \
                                    -F "test_title=${TEST_TITLE}")
                            else
                                HTTP_CODE=$(curl -s -o /tmp/defectdojo-response.txt -w "%{http_code}" -X POST \
                                    "${DD_URL}/api/v2/reimport-scan/" \
                                    -H "Authorization: Token ${DD_API_KEY}" \
                                    -F "scan_type=${SCAN_TYPE}" \
                                    -F "file=@${FILE}" \
                                    -F "product_name=${DD_PRODUCT}" \
                                    -F "engagement_name=${DD_ENGAGEMENT}" \
                                    -F "auto_create_context=true" \
                                    -F "active=true" \
                                    -F "verified=false" \
                                    -F "close_old_findings=true")
                            fi

                            echo "HTTP Status: $HTTP_CODE"

                            if [ "$HTTP_CODE" -lt 200 ] || [ "$HTTP_CODE" -ge 300 ]; then
                                echo "Upload failed for $FILE"
                                cat /tmp/defectdojo-response.txt
                                exit 1
                            fi
                        }

                        upload "Hadolint Dockerfile check" "$REPORT_DIR/hadolint.json"
                        upload "Semgrep JSON Report"        "$REPORT_DIR/semgrep.json"
                        upload "Gitleaks Scan"              "$REPORT_DIR/gitleaks.json"
                        upload "Trivy Scan"                 "$REPORT_DIR/trivy-fs.json"    "Trivy Filesystem"
                        upload "Trivy Scan"                 "$REPORT_DIR/trivy-image.json" "Trivy Image"
                        upload "Anchore Grype"              "$REPORT_DIR/grype.json"
                        upload "SonarQube Scan"             "$REPORT_DIR/sonarqube.json"
                        upload "ZAP Scan"                   "$REPORT_DIR/zap.json"
                    '''
                }
            }
        }

        stage('Final Security Gate') {
            steps {
                script {
                    if (fileExists("${env.REPORT_DIR}/.security_failed")) {
                        error('High/Critical vulnerabilities or secrets detected!')
                    } else {
                        echo 'No high/critical vulnerabilities found'
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**', fingerprint: true
        }
    }
}
