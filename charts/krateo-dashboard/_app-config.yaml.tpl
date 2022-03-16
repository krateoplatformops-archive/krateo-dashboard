app:
  title: {{ .Values.organization }} - Krateo
  baseUrl: {{ .Values.frontendUrl }}
  googleAnalyticsTrackingId: {{ .Values.appConfig.app.googleAnalyticsTrackingId }}
  support:
    url: https://github.com/backstage/backstage/issues # Used by common ErrorPage
    items: # Used by common SupportButton component
      - title: GitHub Krateo
        icon: github
        links:
          - url: https://github.com/krateoplatformops/krateo
            title: GitHub

organization:
  name: {{ .Values.organization }}

backend:
  baseUrl: {{ .Values.backendUrl }}
  listen:
    port: 7007
  csp:
    connect-src: ["'self'", "http:", "https:"]
  cors:
    origin: {{ .Values.frontendUrl }}
    methods: [GET, POST, PUT, DELETE]
    credentials: true
  database:
    client: pg
    connection:
      host: {{ include "backend.postgresql.host" . | quote }}
      port: {{ include "backend.postgresql.port" . | quote }}
      user: {{ include "backend.postgresql.user" . | quote }}
      database: {{ .Values.postgresql.database | quote }}
      rejectUnauthorized: "false"
  cache:
    store: memory

sonarQube:
  baseUrl: {{ .Values.sonarqube.target }}

proxy:
  "/argocd/api/applications/name":
    target: http://krateo-module-core-argocd-server.krateo-system.svc/api/v1/applications
    changeOrigin: true
    secure: false
    headers:
      Cookie: argocd.token=${ARGOCD_AUTH_TOKEN}
  "/sonarqube":
    target: {{ .Values.sonarqube.target }}/api
    allowedMethods: ['GET']
    secure: false
    auth: '${SONARQUBE_AUTH}:'
  "/grafana/api":
    target: {{ .Values.grafana.target }}
    headers:
      Authorization: Bearer ${GRAFANA_AUTH}
  "/prometheus/api":
    target: {{ .Values.prometheus.target }}
    secure: false
    headers:
      Authorization: Bearer ${PROMETHEUS_TOKEN}

  "/circleci/api":
    target: https://circleci.com/api/v1.1
    headers:
      Circle-Token: ${CIRCLECI_AUTH_TOKEN}

  {{- with (first .Values.jenkins.instances) }}
  "/jenkins/api":
    target: {{ .baseUrl }}
    changeOrigin: true
    headers:
      Authorization: Basic {{ .apiKey }}
  {{- end }}

  "/travisci/api":
    target: https://api.travis-ci.com
    changeOrigin: true
    headers:
      Authorization: ${TRAVISCI_AUTH_TOKEN}
      travis-api-version: "3"

  "/newrelic/apm/api":
    target: https://api.newrelic.com/v2
    headers:
      X-Api-Key: ${NEW_RELIC_REST_API_KEY}

  "/pagerduty":
    target: https://api.pagerduty.com
    headers:
      Authorization: Token token=${PAGERDUTY_TOKEN}

  "/buildkite/api":
    target: https://api.buildkite.com/v2/
    headers:
      Authorization: ${BUILDKITE_TOKEN}

  "/sentry/api":
    target: https://sentry.io/api/
    allowedMethods: ["GET"]
    headers:
      Authorization: ${SENTRY_TOKEN}

  "/ilert":
    target: https://api.ilert.com
    allowedMethods: ["GET", "POST", "PUT"]
    allowedHeaders: ["Authorization"]
    headers:
      Authorization: ${ILERT_AUTH_HEADER}

  "/airflow":
    target: https://your.airflow.instance.com/api/v1
    headers:
      Authorization: ${AIRFLOW_BASIC_AUTH_HEADER}

  "/keptn":
    target: {{ .Values.keptn.api }}
    secure: false
    headers:
      x-token: ${KEPTN_API_TOKEN}

grafana:
  domain: {{ .Values.grafana.target }}

integrations:
  github:
    {{ if .Values.providers.github.enterprise.enabled }}
    - host: {{ .Values.providers.github.enterprise.url }}
      apiBaseUrl: https://{{ .Values.providers.github.enterprise.url }}/api/v3
    {{ else }}
    - host: github.com
    {{ end }}
      token: ${GITHUB_TOKEN}
  gitlab:
    - host: gitlab.com
      token: ${GITLAB_TOKEN}
  bitbucket:
    - host: bitbucket.org
      username: ${BITBUCKET_USERNAME}
      appPassword: ${BITBUCKET_APP_PASSWORD}
  azure:
    - host: dev.azure.com
      token: ${AZURE_TOKEN}

sentry:
  organization: my-company

rollbar:
  organization: my-company
  # NOTE: The rollbar-backend & accountToken key may be deprecated in the future (replaced by a proxy config)
  accountToken: my-rollbar-account-token

techdocs:
  builder: "local" # Alternatives - 'external'
  generator:
    runIn: "local" # Alternatives - 'local'
  publisher:
    type: "local"

auth:
  {{ if ne .Values.auth.session.secret "a" }}
  session:
    secret: ${AUTH_SESSION_SECRET}
  {{ end }}
  providers:
    guest:
      enabled: ${AUTH_GUEST}
    google:
      development:
        clientId: ${AUTH_GOOGLE_CLIENT_ID}
        clientSecret: ${AUTH_GOOGLE_CLIENT_SECRET}
    github:
      development:
        appOrigin: {{ .Values.frontendUrl }}
        secure: false
        clientId: ${AUTH_GITHUB_CLIENT_ID}
        clientSecret: ${AUTH_GITHUB_CLIENT_SECRET}
        {{ if .Values.providers.github.enterprise.enabled }}
        enterpriseInstanceUrl: https://{{ .Values.providers.github.enterprise.url }}
        {{ end }}
    gitlab:
      development:
        clientId: ${AUTH_GITLAB_CLIENT_ID}
        clientSecret: ${AUTH_GITLAB_CLIENT_SECRET}
        audience: ${GITLAB_BASE_URL}
    saml:
      entryPoint: ${AUTH_SAML_ENTRY_POINT}
      issuer: ${AUTH_SAML_ISSUER}
    okta:
      development:
        clientId: ${AUTH_OKTA_CLIENT_ID}
        clientSecret: ${AUTH_OKTA_CLIENT_SECRET}
        audience: ${AUTH_OKTA_AUDIENCE}
    oauth2:
      development:
        clientId: ${AUTH_OAUTH2_CLIENT_ID}
        clientSecret: ${AUTH_OAUTH2_CLIENT_SECRET}
        authorizationUrl: ${AUTH_OAUTH2_AUTH_URL}
        tokenUrl: ${AUTH_OAUTH2_TOKEN_URL}
        ###
        # provide a list of scopes as needed for your OAuth2 Server:
        #
        # scope: saml-login-selector openid profile email
    oidc:
      development:
        metadataUrl: ${AUTH_OIDC_METADATA_URL}
        clientId: ${AUTH_OIDC_CLIENT_ID}
        clientSecret: ${AUTH_OIDC_CLIENT_SECRET}
        authorizationUrl: ${AUTH_OIDC_AUTH_URL}
        tokenUrl: ${AUTH_OIDC_TOKEN_URL}
        tokenSignedResponseAlg: ${AUTH_OIDC_TOKEN_SIGNED_RESPONSE_ALG}
    auth0:
      development:
        clientId: ${AUTH_AUTH0_CLIENT_ID}
        clientSecret: ${AUTH_AUTH0_CLIENT_SECRET}
        domain: ${AUTH_AUTH0_DOMAIN}
    microsoft:
      development:
        clientId: ${AUTH_MICROSOFT_CLIENT_ID}
        clientSecret: ${AUTH_MICROSOFT_CLIENT_SECRET}
        tenantId: ${AUTH_MICROSOFT_TENANT_ID}
    onelogin:
      development:
        clientId: ${AUTH_ONELOGIN_CLIENT_ID}
        clientSecret: ${AUTH_ONELOGIN_CLIENT_SECRET}
        issuer: ${AUTH_ONELOGIN_ISSUER}

scaffolder:
  github:
    token: ${GITHUB_TOKEN}
    visibility: public # or 'internal' or 'private'

catalog:
  rules:
    - allow: [Component, System, API, Group, User, Resource, Location, Domain, Template]
  processors:
    {{ if .Values.providers.github.enterprise.enabled }}
    githubOrg:
      providers:
        - target: https://{{ .Values.providers.github.enterprise.url }}
          token: ${GITHUB_TOKEN}
    {{ end }}
    {{ if .Values.ldap.enabled }}
    ldapOrg:
      providers:
        - target: {{ .Values.ldap.target }}
          bind:
            dn: {{ .Values.ldap.bind.dn }}
            secret: ${LDAP_SECRET}
          users:
            dn: {{ .Values.ldap.users.dn }}
            options:
              filter: {{ .Values.ldap.users.options.filter }}
              scope: {{ .Values.ldap.users.options.scope }}
              paged:
                pageSize: 100
                pagePause: true
            map:
              name: cn
              displayName: cn
              memberOf: memberOf
          groups:
            dn: {{ .Values.ldap.groups.dn }}
            options:
              filter: {{ .Values.ldap.groups.options.filter }}
              scope: {{ .Values.ldap.groups.options.scope }}
              paged:
                pageSize: 100
                pagePause: true
            map:
              name: cn
              displayName: cn
              memberOf: memberOf
              members: member
    {{ end }}
    microsoftGraphOrg:
      providers:
        - target: https://graph.microsoft.com/v1.0
          authority: https://login.microsoftonline.com
          # If you don't know you tenantId, you can use Microsoft Graph Explorer
          # to query it
          tenantId: ${AUTH_MICROSOFT_TENANT_ID}
          # Client Id and Secret can be created under Certificates & secrets in
          # the App registration in the Microsoft Azure Portal.
          clientId: ${AUTH_MICROSOFT_CLIENT_ID}
          clientSecret: ${AUTH_MICROSOFT_CLIENT_SECRET}
          # Optional filter for user, see Microsoft Graph API for the syntax
          # See https://docs.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0#properties
          # and for the syntax https://docs.microsoft.com/en-us/graph/query-parameters#filter-parameter
          userFilter: accountEnabled eq true
          # Optional filter for group, see Microsoft Graph API for the syntax
          # See https://docs.microsoft.com/en-us/graph/api/resources/group?view=graph-rest-1.0#properties
          # groupFilter: securityEnabled eq false
          groupFilter: {{ .Values.microsoftGraphOrg.groupFilter }}
  locations:
    - type: microsoft-graph-org
      target: https://graph.microsoft.com/v1.0
      rules:
        - allow: [Group, User]
    {{ if .Values.ldap.enabled }}
    - type: ldap-org
      target: {{ .Values.ldap.target }}
    {{ end }}
{{- if .Values.backend.demoData }}
    # Backstage example components
    - type: github
      target: https://github.com/backstage/backstage/blob/master/packages/catalog-model/examples/all-components.yaml
    # Example component for github-actions
    - type: github
      target: https://github.com/backstage/backstage/blob/master/plugins/github-actions/examples/sample.yaml
    # Example component for techdocs
    - type: github
      target: https://github.com/backstage/backstage/blob/master/plugins/techdocs-backend/examples/documented-component/documented-component.yaml
    # Backstage example APIs
    - type: github
      target: https://github.com/backstage/backstage/blob/master/packages/catalog-model/examples/all-apis.yaml
    # Backstage example templates
    - type: github
      target: https://github.com/backstage/backstage/blob/master/plugins/scaffolder-backend/sample-templates/all-templates.yaml
    - type: url
      target: https://github.com/krateoplatformops/gcp-stack-template/blob/main/template-beta.yaml
      rules:
        - allow: [Template]
{{- end }}

kubernetes:
  customResources:
    {{- range $k8s := .Values.kubernetes.customResources }}
      - group: {{ $k8s.group | quote }}
        apiVersion: {{ $k8s.apiVersion | quote }}
        plural: {{ $k8s.plural | quote }}
    {{- end }}
  serviceLocatorMethod:
    type: "multiTenant"
  clusterLocatorMethods:
    - type: "config"
      clusters:
        {{- range $k8s := .Values.kubernetes.clusters }}
        - name: {{ $k8s.name | quote }}
          url: {{ $k8s.url | quote }}
          serviceAccountToken: ${K8S_SA_TOKEN}
          skipTLSVerify: {{ $k8s.skipTLSVerify }}
          authProvider: {{ $k8s.authProvider | quote }}
        {{- end }}

lighthouse:
  baseUrl: http://localhost:3003

kafka:
  clientId: backstage
  clusters:
    - name: cluster
      brokers:
        - localhost:9092

allure:
  baseUrl: http://localhost:5050/allure-docker-service

pagerduty:
  eventsBaseUrl: "https://events.pagerduty.com/v2"
jenkins:
  instances:
    {{- range $j := .Values.jenkins.instances }}
    - name: {{ $j.name | quote }}
      baseUrl: {{ $j.baseUrl | quote }}
      username: {{ $j.username | quote }}
      apiKey: {{ $j.apiKey | quote }}
    {{- end }}

azureDevOps:
  host: dev.azure.com
  token: my-token
  organization: my-company

apacheAirflow:
  baseUrl: https://your.airflow.instance.com

costInsights:
  engineerCost: 200000
  products:
    computeEngine:
      name: Compute Engine
      icon: compute
    cloudDataflow:
      name: Cloud Dataflow
      icon: data
    cloudStorage:
      name: Cloud Storage
      icon: storage
    bigQuery:
      name: BigQuery
      icon: search
    events:
      name: Events
      icon: data
  metrics:
    DAU:
      name: Daily Active Users
      default: true
    MSC:
      name: Monthly Subscribers
  currencies:
    engineers:
      label: "Engineers 🛠"
      unit: "engineer"
    usd:
      label: "US Dollars 💵"
      kind: "USD"
      unit: "dollar"
      prefix: "$"
      rate: 1
    carbonOffsetTons:
      label: "Carbon Offset Tons ♻️⚖️s"
      kind: "CARBON_OFFSET_TONS"
      unit: "carbon offset ton"
      rate: 3.5
    beers:
      label: "Beers 🍺"
      kind: "BEERS"
      unit: "beer"
      rate: 4.5
    pintsIceCream:
      label: "Pints of Ice Cream 🍦"
      kind: "PINTS_OF_ICE_CREAM"
      unit: "ice cream pint"
      rate: 5.5

homepage:
  clocks:
    - label: UTC
      timezone: UTC
    - label: NYC
      timezone: "America/New_York"
    - label: STO
      timezone: "Europe/Stockholm"
    - label: TYO
      timezone: "Asia/Tokyo"

