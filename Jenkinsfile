@Library('factual-shared-libs@kaniko_v1.19.2-slim') _
pipeline {
    agent none
    environment{
        PATH                          = "${PATH}:/usr/local/airflow/.local/bin"
    }
    stages {
        stage ('Build') {
            when {
                anyOf {
                    branch 'release'
                    branch 'dev'
                    triggeredBy 'UserIdCause'
                }
            }
            steps {
                docker_build name: 'infraeng-consoleme'
            }
        }
        stage ('Deploy-dev') {
            when {
                branch 'dev'
            }
            steps {
                k8s_deploy cluster: 'eks-ss-use1-security', team: 'consoleme', app: 'dev', image_name: '087473112489.dkr.ecr.us-east-1.amazonaws.com/infraeng-consoleme'
            }
        }
        stage ('Deploy-prod') {
            when {
                branch 'release'
            }
            steps {
                k8s_deploy cluster: 'eks-ss-use1-security', team: 'consoleme', app: 'prod', image_name: '087473112489.dkr.ecr.us-east-1.amazonaws.com/infraeng-consoleme'
            }
        }
    }
}
