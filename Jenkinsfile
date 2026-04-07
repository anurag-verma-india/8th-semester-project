pipeline {
    agent { label 'Agent43' }

    environment {
        REPORT_DIR = 'reports'
        IMAGE_NAME = 'node-app:scan'
        SECURITY_FAILED = 'false'

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
                             - FAIL on: ERROR (treated as HIGH)
                             */
                            def status = sh(
                                script: '''
                                    semgrep scan \
                                      --config auto \
                                      --severity ERROR \
                                      --json > $REPORT_DIR/semgrep.json
                                ''',
                                returnStatus: true
                            )
                            if (status != 0) {
                                env.SECURITY_FAILED = 'true'
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
                                env.SECURITY_FAILED = 'true'
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
                                env.SECURITY_FAILED = 'true'
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
                                env.SECURITY_FAILED = "true"
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
                                env.SECURITY_FAILED = 'true'
                            }
                        }
                    }
                }
            }
        }

        stage('Upload to DefectDojo') {
            steps {
                withCredentials([string(credentialsId: 'defect-dojo-api-key-agent43', variable: 'DD_API_KEY')]) {
                    sh '''
                        DD_URL="http://192.168.56.43:8085"
                        DD_PRODUCT="node-todo"
                        DD_ENGAGEMENT="Build-${BUILD_NUMBER}"

                        upload() {
                            SCAN_TYPE="$1"
                            FILE="$2"

                            if [ ! -s "$FILE" ]; then
                                echo "Skipping $FILE (empty or missing)"
                                return
                            fi

                            echo "Uploading $FILE as '$SCAN_TYPE'..."

                            HTTP_CODE=$(curl -s -o /tmp/defectdojo-response.txt -w "%{http_code}" -X POST \
                                "${DD_URL}/api/v2/import-scan/" \
                                -H "Authorization: Token ${DD_API_KEY}" \
                                -F "scan_type=${SCAN_TYPE}" \
                                -F "file=@${FILE}" \
                                -F "product_name=${DD_PRODUCT}" \
                                -F "engagement_name=${DD_ENGAGEMENT}" \
                                -F "auto_create_context=true" \
                                -F "active=true" \
                                -F "verified=false" \
                                -F "close_old_findings=false")

                            echo "HTTP Status: $HTTP_CODE"

                            # if [ "$HTTP_CODE" -lt 200 ] || [ "$HTTP_CODE" -ge 300 ]; then
                            #     echo "Upload failed for $FILE"
                            #     cat /tmp/defectdojo-response.txt
                            #     exit 1
                            # fi
                            cat /tmp/defectdojo-response.txt
                        }

                        upload "Hadolint Dockerfile check" "$REPORT_DIR/hadolint.json"
                        upload "Semgrep JSON Report" "$REPORT_DIR/semgrep.json"
                        upload "Gitleaks Scan" "$REPORT_DIR/gitleaks.json"
                        upload "Trivy Scan" "$REPORT_DIR/trivy-fs.json"
                        upload "Trivy Scan" "$REPORT_DIR/trivy-image.json"
                        upload "Anchore Grype" "$REPORT_DIR/grype.json"
                    '''
                }
            }
        }

        stage('Final Security Gate') {
            steps {
                script {
                    if (env.SECURITY_FAILED == 'true') {
                        error('❌ High/Critical vulnerabilities or secrets detected!')
                    } else {
                        echo '✅ No high/critical vulnerabilities found'
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
