@Library('factual-shared-libs') _
def ts = new Date().format("yyyy-MM-dd'T'HH-mm-ss")
pipeline {
    agent none
    environment {
        TAG = "${ts}"
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
                docker_build name: 'infraeng-consoleme', tag: '$TAG'
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
