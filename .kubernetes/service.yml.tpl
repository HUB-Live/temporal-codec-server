apiVersion: v1
kind: Service
metadata:
  name: ${APP_NAME}
  namespace: ${ENVIRONMENT}
spec:
  selector:
    app: ${APP_NAME}
  ports:
    - name: http
      port: 8081
      targetPort: http
