@Library('factual-shared-libs') _
pipeline {
    agent none
    stages {
        stage ('Build') {
            steps {
                docker_build name: 'infraeng-consoleme'
            }
        }
        stage ('Deploy') {
            when {
                branch 'jenkins_build'
            }
            steps {
                k8s_deploy cluster: 'eks-us-use1-infra', team: 'infra-eng', app: 'consoleme-dev', image_name: '087473112489.dkr.ecr.us-east-1.amazonaws.com/infraeng-consoleme'
            }
        }
    }
}