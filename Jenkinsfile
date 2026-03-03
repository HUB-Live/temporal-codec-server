    pipeline {
        agent {label 'docker'}
        // environment {
        //     AWS_DEFAULT_REGION = 'us-east-1'
        // }
        stages {
            stage('Checkout') {
                steps {
                    checkout scm
                }
            }
            stage('get envs') {
                steps {
                    script {
                        if (env.BRANCH_NAME == 'develop') {
                            withCredentials([
                                aws(accessKeyVariable: 'AWS_ACCESS_KEY_ID', credentialsId: 'AWS_STAGING', secretKeyVariable: 'AWS_SECRET_ACCESS_KEY')
                            ]) {
                                    sh '''
                                        echo "getting files from jenkins"
                                        echo develop > environment.txt
                                        cat environment.txt
                                    '''
                            }
                        } else if (env.BRANCH_NAME == 'main') {
                            withCredentials([
                                aws(accessKeyVariable: 'AWS_ACCESS_KEY_ID', credentialsId: 'AWS_PRODUCTION', secretKeyVariable: 'AWS_SECRET_ACCESS_KEY')
                            ]) {
                                    sh '''
                                        echo "getting files from jenkins"
                                        echo production > environment.txt
                                        cat environment.txt
                                    '''
                            }
                        }
                    }
                }
            }
            stage('docker build and push') {
                steps {
                    script{
                    if (env.BRANCH_NAME == 'develop') {
                        withCredentials(
                            [
                                aws(accessKeyVariable: 'AWS_ACCESS_KEY_ID', credentialsId: 'AWS_STAGING', secretKeyVariable: 'AWS_SECRET_ACCESS_KEY'), 
                                usernamePassword(credentialsId: 'github-requirements-credentials', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD')
                            ]) {
                            sh '''
                                export AWS_DEFAULT_REGION=us-east-1
                                export ENVIRONMENT=$(cat environment.txt)
                                export APP_VERSION=0.1.0
                                export APP_NAME=temporal-codec-server
                                export IMAGE_TAG=${ENVIRONMENT}-${APP_VERSION}
                                export REGISTRY=093126182733.dkr.ecr.us-east-1.amazonaws.com
                                export CI_IMAGE_COMPLETE=${REGISTRY}/${APP_NAME}:${IMAGE_TAG}
                                printf "machine github.com\n  login %s\n  password %s\n" "${USERNAME}" "${PASSWORD}" > .netrc
                                cat .netrc
                                aws ecr get-login-password --region $AWS_DEFAULT_REGION | docker login --username AWS --password-stdin ${REGISTRY}
                                cd server
                                docker build -t $CI_IMAGE_COMPLETE .
                                docker push $CI_IMAGE_COMPLETE
                                docker rmi $CI_IMAGE_COMPLETE
                                echo "Image published $CI_IMAGE_COMPLETE"
                                '''
                        }
                    }else if (env.BRANCH_NAME == 'main') {
                        withCredentials(
                            [
                                aws(accessKeyVariable: 'AWS_ACCESS_KEY_ID', credentialsId: 'AWS_PRODUCTION', secretKeyVariable: 'AWS_SECRET_ACCESS_KEY'), 
                                usernamePassword(credentialsId: 'github-requirements-credentials', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD')
                            ]) {
                            sh '''
                                export AWS_DEFAULT_REGION=sa-east-1
                                export ENVIRONMENT=$(cat environment.txt)
                                export APP_VERSION=0.1.0
                                export APP_NAME=temporal-codec-server
                                export IMAGE_TAG=${ENVIRONMENT}-${APP_VERSION}
                                export REGISTRY=816353935207.dkr.ecr.sa-east-1.amazonaws.com
                                export CI_IMAGE_COMPLETE=${REGISTRY}/${APP_NAME}:${IMAGE_TAG}
                                printf "machine github.com\n  login %s\n  password %s\n" "${USERNAME}" "${PASSWORD}" > .netrc
                                aws ecr get-login-password --region $AWS_DEFAULT_REGION | docker login --username AWS --password-stdin ${REGISTRY}
                                cd server
                                docker build -t $CI_IMAGE_COMPLETE .
                                docker push $CI_IMAGE_COMPLETE
                                docker rmi $CI_IMAGE_COMPLETE
                                echo "Image published $CI_IMAGE_COMPLETE"
                                '''
                        }
                    } 
                    }
                }
            }
            stage('kubernetes deploy') {
                steps {
                    script{
                    if (env.BRANCH_NAME.matches('^(feature/|hotfix/|fix/|bug/|codex/|bugfix/|develop|homolog).*')) {
                        withCredentials(
                            [
                                aws(accessKeyVariable: 'AWS_ACCESS_KEY_ID', credentialsId: 'AWS_STAGING', secretKeyVariable: 'AWS_SECRET_ACCESS_KEY')
                            ]) {
                            sh '''
                                export AWS_DEFAULT_REGION=us-east-1
                                aws eks update-kubeconfig --region ${AWS_DEFAULT_REGION} --name cluster-hublive-develop
                                kubectl apply -f yaml/deployments/server-deployment.yaml
                                kubectl apply -f yaml/services/server-service.yaml
                                kubectl apply -f yaml/ingress/server-ingress.yaml
                                echo "Image published $CI_IMAGE_COMPLETE"
                                '''
                        }
                    }else if (env.BRANCH_NAME == 'main') {
                        withCredentials(
                            [
                                aws(accessKeyVariable: 'AWS_ACCESS_KEY_ID', credentialsId: 'AWS_PRODUCTION', secretKeyVariable: 'AWS_SECRET_ACCESS_KEY')
                            ]) {
                            sh '''
                                export AWS_DEFAULT_REGION=sa-east-1
                                aws eks update-kubeconfig --region ${AWS_DEFAULT_REGION} --name cluster-hublive-production
                                kubectl apply -f yaml/deployments/server-deployment-prd.yaml
                                kubectl apply -f yaml/services/server-service-prd.yaml
                                kubectl apply -f yaml/ingress/server-ingress-prd.yaml
                                echo "Image published $CI_IMAGE_COMPLETE"
                                '''
                            }
                    }  
                    }
                }
            }
        }
        post {
            always {
                cleanWs()
                sh '''
                rm -rf ~/.kube/config || true
                rm -rf ~/.docker/config.json || true
                '''
            }
            success {
                echo 'Pipeline executada com sucesso!'
            }
            failure {
                echo 'Falha na execução da pipeline.'
            }
        }
    }
