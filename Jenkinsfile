pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('SonarQube Analysis') {
            steps {
                echo 'Running SonarQube scan...'
                withSonarQubeEnv('SonarServer') {
                    bat '"D:/sonar-scanner-cli-7.3.0.5189-windows-x64/sonar-scanner-7.3.0.5189-windows-x64/bin/sonar-scanner.bat"


