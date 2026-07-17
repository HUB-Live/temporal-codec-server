apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: ${K8S_ENV_SECRET_NAME}
  namespace: ${ENVIRONMENT}
spec:
  refreshInterval: 5m
  secretStoreRef:
    kind: ClusterSecretStore
    name: aws-secretsmanager
  target:
    name: ${K8S_ENV_SECRET_NAME}
    creationPolicy: Owner
  dataFrom:
    - extract:
        key: ${ENV_SECRET_ID}
