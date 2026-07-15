apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${APP_NAME}
  namespace: ${ENVIRONMENT}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ${APP_NAME}
  template:
    metadata:
      labels:
        app: ${APP_NAME}
    spec:
      automountServiceAccountToken: false
      nodeSelector:
        type: graviton
      tolerations:
        - key: architecture
          operator: Equal
          value: arm
          effect: NoSchedule
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: codec
          image: ${CI_IMAGE_COMPLETE}
          imagePullPolicy: Always
          envFrom:
            - secretRef:
                name: ${K8S_ENV_SECRET_NAME}
          env:
            - name: PORT
              value: "8081"
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          ports:
            - name: http
              containerPort: 8081
          startupProbe:
            httpGet:
              path: /
              port: http
            failureThreshold: 30
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /
              port: http
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /
              port: http
            periodSeconds: 10
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
