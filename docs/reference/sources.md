# Built-In Sources

Cerebro sources live under `sources/<id>` and expose their capabilities through `sources/*/catalog.yaml`.

Source-specific configuration is passed as `key=value` pairs in CLI calls or query parameters in HTTP calls. Required keys vary by source and family.

Declarative connector catalog entries are cataloged when a spec exists. They are callable only when the connector has wired auth and an earned validation grade of `fixture_validated` or higher in `internal/connectorvalidation/registry.yaml`; entries without evidence remain `generated_from_docs`.

| Source ID | Description | Emitted kinds / families |
| --- | --- | --- |
| `abnormal_security` | Abnormal Security source | abnormal_security.assets, abnormal_security.audit_events, abnormal_security.findings, abnormal_security.policies, abnormal_security.vulnerabilities |
| `abuseipdb` | Abuseipdb source | abuseipdb.audit_events, abuseipdb.ip_addresses, abuseipdb.reports |
| `activecampaign` | Activecampaign source | activecampaign.accounts, activecampaign.audit_events, activecampaign.policies, activecampaign.records, activecampaign.users |
| `activtrak` | Activtrak source | activtrak.accounts, activtrak.audit_events, activtrak.policies, activtrak.records, activtrak.users |
| `acunetix` | Acunetix source | acunetix.assets, acunetix.audit_events, acunetix.findings, acunetix.policies, acunetix.vulnerabilities |
| `ada_support` | Ada Support source | ada_support.accounts, ada_support.audit_events, ada_support.policies, ada_support.records, ada_support.users |
| `addigy` | Addigy source | addigy.audit_events, addigy.devices, addigy.groups, addigy.policies, addigy.users |
| `adobe_workfront` | Adobe Workfront source | adobe_workfront.audit_events, adobe_workfront.documents, adobe_workfront.groups, adobe_workfront.users, adobe_workfront.workspaces |
| `adp_workforce_now` | Adp Workforce Now source | adp_workforce_now.accounts, adp_workforce_now.audit_events, adp_workforce_now.policies, adp_workforce_now.records, adp_workforce_now.users |
| `agiloft` | Agiloft source | agiloft.accounts, agiloft.audit_events, agiloft.policies, agiloft.records, agiloft.users |
| `aha` | Aha source | aha.audit_events, aha.deployments, aha.projects, aha.repositories, aha.users |
| `airbase` | Airbase source | airbase.accounts, airbase.audit_events, airbase.policies, airbase.records, airbase.users |
| `airbrake` | Airbrake source | airbrake.alerts, airbrake.audit_events, airbrake.dashboards, airbrake.incidents, airbrake.monitors |
| `airbyte_cloud` | Airbyte Cloud source | airbyte_cloud.accounts, airbyte_cloud.audit_events, airbyte_cloud.policies, airbyte_cloud.records, airbyte_cloud.users |
| `aircall` | Aircall source | aircall.audit_events, aircall.documents, aircall.groups, aircall.users, aircall.workspaces |
| `airfocus` | Airfocus source | airfocus.audit_events, airfocus.deployments, airfocus.projects, airfocus.repositories, airfocus.users |
| `airtable` | Airtable source | airtable.audit_events, airtable.projects, airtable.users |
| `akeneo` | Akeneo source | akeneo.asset, akeneo.asset_families_attribute, akeneo.asset_family, akeneo.attribute, akeneo.attribute_group, akeneo.attributes_option, akeneo.draft, akeneo.option, akeneo.products_draft, akeneo.products_uuid_draft, akeneo.reference_entities_attribute, akeneo.v1_attribute |
| `akeyless` | Akeyless secrets management source | items, auth methods, roles, audit events |
| `alation` | Alation source | alation.accounts, alation.audit_events, alation.policies, alation.records, alation.users |
| `alchemer` | Alchemer source | alchemer.accounts, alchemer.audit_events, alchemer.policies, alchemer.records, alchemer.users |
| `alteryx` | Alteryx source | alteryx.accounts, alteryx.audit_events, alteryx.policies, alteryx.records, alteryx.users |
| `amplitude` | Amplitude source | amplitude.accounts, amplitude.audit_events, amplitude.policies, amplitude.records, amplitude.users |
| `anchore` | Anchore source | anchore.assets, anchore.findings, anchore.vulnerabilities |
| `anecdotes` | Anecdotes source | anecdotes.assets, anecdotes.audit_events, anecdotes.findings, anecdotes.policies, anecdotes.vulnerabilities |
| `anomali_threatstream` | Anomali Threatstream source | anomali_threatstream.assets, anomali_threatstream.audit_events, anomali_threatstream.findings, anomali_threatstream.policies, anomali_threatstream.vulnerabilities |
| `anomalo` | Anomalo source | anomalo.accounts, anomalo.audit_events, anomalo.policies, anomalo.records, anomalo.users |
| `anthropic` | Anthropic organization governance source | organization, users, invites, workspaces and members, API keys, service accounts, federation, external keys, usage/cost reports, rate/spend limits, compliance activity |
| `apache` | Apache source | apache.eventlog, apache.permission, apache.role, apache.user |
| `apacta` | Apacta source | apacta.activity, apacta.changelog, apacta.city, apacta.contact_person, apacta.event, apacta.mass_messages_user, apacta.projects_user, apacta.role, apacta.time_entry_rule_group, apacta.user, apacta.user_custom_field_attribute, apacta.user_custom_field_value |
| `api2cart` | Api2cart source | api2cart.attribute_attributeset_list_json, api2cart.attribute_group_list_json |
| `apideck` | Apideck source | apideck.bill, apideck.credit_note, apideck.customer, apideck.ledger_account |
| `apigee` | Apigee source | apigee.audit_events, apigee.deployments, apigee.projects, apigee.repositories, apigee.users |
| `apiiro` | Apiiro source | apiiro.assets, apiiro.audit_events, apiiro.findings, apiiro.policies, apiiro.vulnerabilities |
| `apollo` | Apollo source | apollo.accounts, apollo.audit_events, apollo.policies, apollo.records, apollo.users |
| `appcircle` | Appcircle source | appcircle.audit_events, appcircle.deployments, appcircle.projects, appcircle.repositories, appcircle.users |
| `appdynamics` | Appdynamics source | appdynamics.alerts, appdynamics.audit_events, appdynamics.dashboards, appdynamics.incidents, appdynamics.monitors |
| `appfolio` | Appfolio source | appfolio.accounts, appfolio.audit_events, appfolio.policies, appfolio.records, appfolio.users |
| `appgate` | Appgate source | appgate.applications, appgate.audit_events, appgate.groups, appgate.roles, appgate.users |
| `applitools` | Applitools source | applitools.audit_events, applitools.deployments, applitools.projects, applitools.repositories, applitools.users |
| `appomni` | Appomni source | appomni.assets, appomni.audit_events, appomni.findings, appomni.policies, appomni.vulnerabilities |
| `appveyor` | Appveyor source | appveyor.artifact, appveyor.collaborator, appveyor.role, appveyor.user |
| `appwrite` | Appwrite source | appwrite.continent, appwrite.log, appwrite.membership, appwrite.team |
| `aqua_security` | Aqua Security source | aqua_security.assets, aqua_security.findings, aqua_security.vulnerabilities |
| `archetype` | Archetype repository vulnerability scan source | scans, vulnerabilities |
| `arctic_wolf` | Arctic Wolf source | arctic_wolf.assets, arctic_wolf.audit_events, arctic_wolf.findings, arctic_wolf.policies, arctic_wolf.vulnerabilities |
| `argo_cd` | Argo Cd source | argo_cd.audit_events, argo_cd.findings, argo_cd.pipelines |
| `armis` | Armis source | armis.assets, armis.audit_events, armis.findings, armis.policies, armis.vulnerabilities |
| `armo_platform` | Armo Platform source | armo_platform.assets, armo_platform.audit_events, armo_platform.findings, armo_platform.policies, armo_platform.vulnerabilities |
| `armorcode` | Armorcode source | armorcode.assets, armorcode.audit_events, armorcode.findings, armorcode.policies, armorcode.vulnerabilities |
| `arnica_security` | Arnica Security source | arnica_security.assets, arnica_security.audit_events, arnica_security.findings, arnica_security.policies, arnica_security.vulnerabilities |
| `asana` | Asana source | asana.audit_events, asana.projects, asana.users |
| `ashby` | Ashby source | ashby.accounts, ashby.audit_events, ashby.policies, ashby.records, ashby.users |
| `astrix_security` | Astrix Security source | astrix_security.assets, astrix_security.audit_events, astrix_security.findings, astrix_security.policies, astrix_security.vulnerabilities |
| `atlan` | Atlan source | atlan.accounts, atlan.audit_events, atlan.policies, atlan.records, atlan.users |
| `attackiq` | Attackiq source | attackiq.assets, attackiq.audit_events, attackiq.findings, attackiq.policies, attackiq.vulnerabilities |
| `auditboard` | Auditboard source | auditboard.controls, auditboard.findings, auditboard.users |
| `aurelius` | SaaS/business-operation export source | configured catalog families |
| `auth0` | Auth0 Management API source | users, roles, audit events, organizations, organization members, clients, connections, resource servers, client grants, grants, user roles, user authentication methods, Guardian factors |
| `authentik_cloud` | Authentik Cloud source | authentik_cloud.applications, authentik_cloud.audit_events, authentik_cloud.groups, authentik_cloud.roles, authentik_cloud.users |
| `autotask` | Autotask source | autotask.entityinformation_field, autotask.excludedrole, autotask.field, autotask.userdefinedfield |
| `avature` | Avature source | avature.accounts, avature.audit_events, avature.policies, avature.records, avature.users |
| `avaza` | Avaza source | avaza.bill, avaza.billpayment, avaza.company, avaza.contact, avaza.creditnote, avaza.currency, avaza.estimate, avaza.expense, avaza.lookup, avaza.projectmember, avaza.userprofile, avaza.webhook |
| `aws` | AWS IAM, cloud, workload, network exposure, and CloudTrail source | access keys, IAM users/groups/roles/trust, EC2, ECS, EKS, Lambda, public endpoints, resource exposure, CloudTrail |
| `aws_bedrock` | Aws Bedrock source | aws_bedrock.custom_models, aws_bedrock.foundation_models, aws_bedrock.guardrails, aws_bedrock.model_customization_jobs, aws_bedrock.provisioned_model_throughputs |
| `axiom` | Axiom source | axiom.alerts, axiom.audit_events, axiom.dashboards, axiom.incidents, axiom.monitors |
| `axonius` | Axonius source | axonius.assets, axonius.audit_events, axonius.findings, axonius.policies, axonius.vulnerabilities |
| `azure` | Azure Entra ID, RBAC, activity, and audit source | activity logs, directory audit, users, groups, role/app assignments, service principals, credentials, resource exposure |
| `azure_devops` | Azure Devops source | azure_devops.audit_events, azure_devops.repositories, azure_devops.users |
| `azure_openai` | Azure Openai source | azure_openai.deployments, azure_openai.model_catalog, azure_openai.private_endpoint_connections, azure_openai.rai_blocklists, azure_openai.rai_policies |
| `backstage` | Backstage catalog source | components |
| `bamboohr` | Bamboohr source | bamboohr.audit_events, bamboohr.groups, bamboohr.users |
| `basecamp` | Basecamp source | basecamp.audit_events, basecamp.documents, basecamp.groups, basecamp.users, basecamp.workspaces |
| `baselime` | Baselime source | baselime.alerts, baselime.audit_events, baselime.dashboards, baselime.incidents, baselime.monitors |
| `bazaarvoice` | Bazaarvoice source | bazaarvoice.accounts, bazaarvoice.audit_events, bazaarvoice.policies, bazaarvoice.records, bazaarvoice.users |
| `beeline` | Beeline source | beeline.accounts, beeline.audit_events, beeline.policies, beeline.records, beeline.users |
| `beezup` | Beezup source | beezup.alert, beezup.autoimport, beezup.beezupcolumn, beezup.catalogcolumn, beezup.category, beezup.channelcatalog, beezup.customcolumn, beezup.filteroperator, beezup.offer, beezup.random |
| `better_stack` | Better Stack source | better_stack.alerts, better_stack.audit_events, better_stack.dashboards, better_stack.incidents, better_stack.monitors |
| `bettercloud` | Bettercloud source | bettercloud.applications, bettercloud.audit_events, bettercloud.groups, bettercloud.roles, bettercloud.users |
| `beyondtrust` | Beyondtrust source | beyondtrust.audit_events, beyondtrust.secrets, beyondtrust.users |
| `biapi` | Biapi source | biapi.account, biapi.add_to_data, biapi.alert, biapi.logo |
| `bigfix` | Bigfix source | bigfix.analyses, bigfix.computers, bigfix.sites |
| `bigid` | Bigid source | bigid.assets, bigid.audit_events, bigid.findings, bigid.policies, bigid.vulnerabilities |
| `bigpanda` | Bigpanda source | bigpanda.alerts, bigpanda.audit_events, bigpanda.dashboards, bigpanda.incidents, bigpanda.monitors |
| `bigredcloud` | Bigredcloud source | bigredcloud.account, bigredcloud.analysiscategory, bigredcloud.bankaccount, bigredcloud.ownertypegroup |
| `bill_com` | Bill Com source | bill_com.accounts, bill_com.audit_events, bill_com.policies, bill_com.records, bill_com.users |
| `billbee` | Billbee source | billbee.addresses, billbee.cloudstorage, billbee.custom_field, billbee.customer, billbee.customer_addresses, billbee.image, billbee.layout, billbee.order, billbee.product, billbee.shipment, billbee.stock, billbee.webhook |
| `billingo` | Billingo source | billingo.bank_account, billingo.document, billingo.document_block, billingo.partner |
| `bitbucket_cloud` | Bitbucket Cloud source | bitbucket_cloud.audit_events, bitbucket_cloud.repositories, bitbucket_cloud.users |
| `bitrise` | Bitrise source | bitrise.audit_events, bitrise.deployments, bitrise.projects, bitrise.repositories, bitrise.users |
| `bitsight` | Bitsight source | bitsight.assets, bitsight.audit_events, bitsight.findings, bitsight.policies, bitsight.vulnerabilities |
| `bitwarden` | Bitwarden source | bitwarden.audit_events, bitwarden.collections, bitwarden.groups, bitwarden.policies, bitwarden.users |
| `bitwarden_enterprise` | Bitwarden Enterprise source | bitwarden_enterprise.audit_events, bitwarden_enterprise.secrets, bitwarden_enterprise.users |
| `black_kite` | Black Kite source | black_kite.assets, black_kite.audit_events, black_kite.findings, black_kite.policies, black_kite.vulnerabilities |
| `blackduck` | Blackduck source | blackduck.assets, blackduck.audit_events, blackduck.findings, blackduck.policies, blackduck.vulnerabilities |
| `bluejeans` | Bluejeans source | bluejeans.audit_events, bluejeans.documents, bluejeans.groups, bluejeans.users, bluejeans.workspaces |
| `boomi` | Boomi source | boomi.audit_events, boomi.deployments, boomi.projects, boomi.repositories, boomi.users |
| `botify` | Botify source | botify.analyses, botify.datamodel, botify.domain, botify.export, botify.filter, botify.orphan_url, botify.out_of_config, botify.percentile, botify.project, botify.report, botify.sitemap_only, botify.url |
| `box` | Box source | box.audit_events, box.content_assets, box.users |
| `braintree` | Braintree source | braintree.audit_events, braintree.customers, braintree.transactions |
| `braze` | Braze source | braze.accounts, braze.audit_events, braze.policies, braze.records, braze.users |
| `brex` | Brex source | brex.audit_events, brex.cards, brex.users |
| `brightflag` | Brightflag source | brightflag.accounts, brightflag.audit_events, brightflag.policies, brightflag.records, brightflag.users |
| `brinqa` | Brinqa source | brinqa.assets, brinqa.audit_events, brinqa.findings, brinqa.policies, brinqa.vulnerabilities |
| `britive` | Britive source | britive.applications, britive.audit_events, britive.groups, britive.roles, britive.users |
| `browserstack` | Browserstack source | browserstack.audit_events, browserstack.deployments, browserstack.projects, browserstack.repositories, browserstack.users |
| `buddy_ci` | Buddy Ci source | buddy_ci.audit_events, buddy_ci.deployments, buddy_ci.projects, buddy_ci.repositories, buddy_ci.users |
| `bugcrowd` | Bugcrowd source | bugcrowd.assets, bugcrowd.audit_events, bugcrowd.findings, bugcrowd.policies, bugcrowd.vulnerabilities |
| `bugsnag` | Bugsnag source | bugsnag.audit_events, bugsnag.errors, bugsnag.projects |
| `buildkite` | Buildkite source | buildkite.audit_events, buildkite.findings, buildkite.pipelines |
| `bulksms` | Bulksms source | bulksms.message, bulksms.relatedreceivedmessage, bulksms.send, bulksms.webhook |
| `bunq` | Bunq source | bunq.credential_password_ip, bunq.event, bunq.notification_filter_push, bunq.user |
| `burp_suite_enterprise` | Burp Suite Enterprise source | burp_suite_enterprise.assets, burp_suite_enterprise.audit_events, burp_suite_enterprise.findings, burp_suite_enterprise.policies, burp_suite_enterprise.vulnerabilities |
| `calcom` | Calcom source | calcom.audit_events, calcom.bookings, calcom.users |
| `calendly` | Calendly source | calendly.audit_events, calendly.documents, calendly.groups, calendly.users, calendly.workspaces |
| `callfire` | Callfire source | callfire.account, callfire.broadcast, callfire.call, callfire.credential |
| `callrail` | Callrail source | callrail.accounts, callrail.audit_events, callrail.policies, callrail.records, callrail.users |
| `campaign_monitor` | Campaign Monitor source | campaign_monitor.accounts, campaign_monitor.audit_events, campaign_monitor.policies, campaign_monitor.records, campaign_monitor.users |
| `canva_enterprise` | Canva Enterprise source | canva_enterprise.audit_events, canva_enterprise.documents, canva_enterprise.groups, canva_enterprise.users, canva_enterprise.workspaces |
| `carbon_black_cloud` | Carbon Black Cloud source | carbon_black_cloud.assets, carbon_black_cloud.audit_events, carbon_black_cloud.findings, carbon_black_cloud.policies, carbon_black_cloud.vulnerabilities |
| `caspio` | Caspio source | caspio.accounts, caspio.audit_events, caspio.policies, caspio.records, caspio.users |
| `cast_ai` | Cast Ai source | cast_ai.alerts, cast_ai.audit_events, cast_ai.dashboards, cast_ai.incidents, cast_ai.monitors |
| `catalyst` | Catalyst source | catalyst.accounts, catalyst.audit_events, catalyst.policies, catalyst.records, catalyst.users |
| `catchpoint` | Catchpoint source | catchpoint.alerts, catchpoint.audit_events, catchpoint.dashboards, catchpoint.incidents, catchpoint.monitors |
| `cato_networks` | Cato Networks source | cato_networks.assets, cato_networks.audit_events, cato_networks.findings, cato_networks.policies, cato_networks.vulnerabilities |
| `cenit` | Cenit source | cenit.connection, cenit.connection_role, cenit.data_type, cenit.flow, cenit.namespace, cenit.observer, cenit.scheduler, cenit.schema, cenit.setup_connection_role, cenit.setup_webhook, cenit.translator, cenit.webhook |
| `census` | Census source | census.accounts, census.audit_events, census.policies, census.records, census.users |
| `censys_asm` | Censys Asm source | censys_asm.assets, censys_asm.findings, censys_asm.vulnerabilities |
| `cerbos_cloud` | Cerbos Cloud source | cerbos_cloud.applications, cerbos_cloud.audit_events, cerbos_cloud.groups, cerbos_cloud.roles, cerbos_cloud.users |
| `cerby` | Cerby source | cerby.applications, cerby.audit_events, cerby.groups, cerby.roles, cerby.users |
| `cerebras` | Cerebras source | cerebras.api_keys, cerebras.model_deployments, cerebras.projects, cerebras.usage_reports |
| `cerebro` | Cerebro product access telemetry source backed by structured NDJSON archives | API access audit events |
| `ceridian_dayforce` | Ceridian Dayforce source | ceridian_dayforce.accounts, ceridian_dayforce.audit_events, ceridian_dayforce.policies, ceridian_dayforce.records, ceridian_dayforce.users |
| `chargebee` | Chargebee source | chargebee.audit_events, chargebee.customers, chargebee.subscriptions |
| `chargify` | Chargify source | chargify.accounts, chargify.audit_events, chargify.policies, chargify.records, chargify.users |
| `charthop` | Charthop source | charthop.accounts, charthop.audit_events, charthop.policies, charthop.records, charthop.users |
| `checkly` | Checkly source | checkly.alerts, checkly.audit_events, checkly.dashboards, checkly.incidents, checkly.monitors |
| `checkmarx_one` | Checkmarx One source | checkmarx_one.assets, checkmarx_one.findings, checkmarx_one.vulnerabilities |
| `checkout_com` | Checkout Com source | checkout_com.accounts, checkout_com.audit_events, checkout_com.policies, checkout_com.records, checkout_com.users |
| `checkr` | Checkr source | checkr.background_checks, checkr.candidates, checkr.users |
| `chili_piper` | Chili Piper source | chili_piper.audit_events, chili_piper.documents, chili_piper.groups, chili_piper.users, chili_piper.workspaces |
| `chorus` | Chorus source | chorus.accounts, chorus.audit_events, chorus.policies, chorus.records, chorus.users |
| `chronosphere` | Chronosphere source | chronosphere.alerts, chronosphere.audit_events, chronosphere.dashboards, chronosphere.incidents, chronosphere.monitors |
| `churnzero` | Churnzero source | churnzero.accounts, churnzero.audit_events, churnzero.policies, churnzero.records, churnzero.users |
| `circleci` | Circleci source | circleci.audit_events, circleci.findings, circleci.pipelines |
| `cisco_umbrella` | Cisco Umbrella source | cisco_umbrella.assets, cisco_umbrella.audit_events, cisco_umbrella.findings, cisco_umbrella.policies, cisco_umbrella.vulnerabilities |
| `clari` | Clari source | clari.accounts, clari.audit_events, clari.policies, clari.records, clari.users |
| `claroty` | Claroty source | claroty.assets, claroty.audit_events, claroty.findings, claroty.policies, claroty.vulnerabilities |
| `clearblade` | Clearblade source | clearblade.admin_audit, clearblade.audit, clearblade.connection, clearblade.deployment, clearblade.listindexe, clearblade.platform_system, clearblade.session_user, clearblade.system, clearblade.timer, clearblade.topic, clearblade.trigger, clearblade.user |
| `clever_cloud` | Clever Cloud source | clever_cloud.deployment, clever_cloud.email, clever_cloud.networkgroup, clever_cloud.token |
| `clickmeter` | Clickmeter source | clickmeter.aggregated_list, clickmeter.clickstream, clickmeter.conversions_hit, clickmeter.datapoint, clickmeter.datapoints_hit, clickmeter.group, clickmeter.groups_hit, clickmeter.hit, clickmeter.ipblacklist, clickmeter.list, clickmeter.summary_group, clickmeter.tags_group |
| `clicksend` | Clicksend source | clicksend.audit_events, clicksend.documents, clicksend.groups, clicksend.users, clicksend.workspaces |
| `clickup` | Clickup source | clickup.audit_events, clickup.projects, clickup.users |
| `close_crm` | Close Crm source | close_crm.accounts, close_crm.audit_events, close_crm.policies, close_crm.records, close_crm.users |
| `cloudbees_ci` | Cloudbees Ci source | cloudbees_ci.audit_events, cloudbees_ci.deployments, cloudbees_ci.projects, cloudbees_ci.repositories, cloudbees_ci.users |
| `cloudflare` | Cloudflare account and network source | accounts, members, roles, zones, DNS records, Gateway rules, Workers scripts |
| `cloudflare_workers_ai` | Cloudflare Workers Ai source | cloudflare_workers_ai.ai_gateways, cloudflare_workers_ai.gateway_evaluations, cloudflare_workers_ai.gateway_logs, cloudflare_workers_ai.gateway_provider_configs, cloudflare_workers_ai.model_catalog, cloudflare_workers_ai.vectorize_indexes |
| `cloudflare_zero_trust` | Cloudflare Zero Trust source | cloudflare_zero_trust.applications, cloudflare_zero_trust.audit_events, cloudflare_zero_trust.groups, cloudflare_zero_trust.roles, cloudflare_zero_trust.users |
| `cloudsmith` | Cloudsmith source | cloudsmith.audit_events, cloudsmith.deployments, cloudsmith.projects, cloudsmith.repositories, cloudsmith.users |
| `cloudtalk` | Cloudtalk source | cloudtalk.accounts, cloudtalk.audit_events, cloudtalk.policies, cloudtalk.records, cloudtalk.users |
| `coalesce_data` | Coalesce Data source | coalesce_data.accounts, coalesce_data.audit_events, coalesce_data.policies, coalesce_data.records, coalesce_data.users |
| `cobalt` | Cobalt source | cobalt.assets, cobalt.audit_events, cobalt.findings, cobalt.policies, cobalt.vulnerabilities |
| `cockroachdb_cloud` | Cockroachdb Cloud source | cockroachdb_cloud.assets, cockroachdb_cloud.audit_events, cockroachdb_cloud.vulnerabilities |
| `coda` | Coda source | coda.audit_events, coda.documents, coda.groups, coda.users, coda.workspaces |
| `codacy` | Codacy source | codacy.audit_events, codacy.deployments, codacy.projects, codacy.repositories, codacy.users |
| `codecov` | Codecov source | codecov.audit_events, codecov.deployments, codecov.projects, codecov.repositories, codecov.users |
| `codefresh` | Codefresh source | codefresh.audit_events, codefresh.builds, codefresh.projects |
| `codemagic` | Codemagic source | codemagic.audit_events, codemagic.deployments, codemagic.projects, codemagic.repositories, codemagic.users |
| `coder_cloud` | Coder Cloud source | coder_cloud.audit_events, coder_cloud.deployments, coder_cloud.projects, coder_cloud.repositories, coder_cloud.users |
| `cofense` | Cofense source | cofense.assets, cofense.audit_events, cofense.findings, cofense.policies, cofense.vulnerabilities |
| `cohere` | Cohere source | cohere.connectors, cohere.datasets, cohere.fine_tuned_models, cohere.model_catalog |
| `collibra` | Collibra source | collibra.accounts, collibra.audit_events, collibra.policies, collibra.records, collibra.users |
| `combell` | Combell source | combell.account, combell.account_2, combell.ssh, combell.user |
| `concur` | Concur source | concur.accounts, concur.audit_events, concur.policies, concur.records, concur.users |
| `configcat` | Configcat source | configcat.auditlog, configcat.member, configcat.organization, configcat.permission |
| `confluence` | Confluence source | confluence.audit_events, confluence.projects, confluence.users |
| `conga` | Conga source | conga.accounts, conga.audit_events, conga.policies, conga.records, conga.users |
| `conjur` | Conjur source | conjur.authenticator, conjur.resource, conjur.resource_2, conjur.resource_3 |
| `contentful` | Contentful source | contentful.audit_events, contentful.documents, contentful.groups, contentful.users, contentful.workspaces |
| `contractbook` | Contractbook source | contractbook.accounts, contractbook.audit_events, contractbook.policies, contractbook.records, contractbook.users |
| `contrast_security` | Contrast Security source | contrast_security.assets, contrast_security.audit_events, contrast_security.findings, contrast_security.policies, contrast_security.vulnerabilities |
| `copper_crm` | Copper Crm source | copper_crm.accounts, copper_crm.audit_events, copper_crm.policies, copper_crm.records, copper_crm.users |
| `coralogix` | Coralogix source | coralogix.alerts, coralogix.audit_events, coralogix.dashboards, coralogix.incidents, coralogix.monitors |
| `cornerstone_ondemand` | Cornerstone Ondemand source | cornerstone_ondemand.accounts, cornerstone_ondemand.audit_events, cornerstone_ondemand.policies, cornerstone_ondemand.records, cornerstone_ondemand.users |
| `cortex_xdr` | Cortex Xdr source | cortex_xdr.assets, cortex_xdr.findings, cortex_xdr.vulnerabilities |
| `cortex_xsoar` | Cortex Xsoar source | cortex_xsoar.assets, cortex_xsoar.audit_events, cortex_xsoar.findings |
| `cosmo` | Cosmo workflow and message source | messages, survey feedback, configured families |
| `coupa` | Coupa source | coupa.accounts, coupa.audit_events, coupa.policies, coupa.records, coupa.users |
| `crashlytics` | Crashlytics source | crashlytics.alerts, crashlytics.audit_events, crashlytics.dashboards, crashlytics.incidents, crashlytics.monitors |
| `creately` | Creately source | creately.audit_events, creately.documents, creately.groups, creately.users, creately.workspaces |
| `cribl_cloud` | Cribl Cloud source | cribl_cloud.alerts, cribl_cloud.audit_events, cribl_cloud.dashboards, cribl_cloud.incidents, cribl_cloud.monitors |
| `crowdstrike_falcon` | Crowdstrike Falcon source | crowdstrike_falcon.endpoint_devices, crowdstrike_falcon.findings, crowdstrike_falcon.vulnerabilities |
| `crowdstrike_identity` | Crowdstrike Identity source | crowdstrike_identity.assets, crowdstrike_identity.audit_events, crowdstrike_identity.findings, crowdstrike_identity.policies, crowdstrike_identity.vulnerabilities |
| `culture_amp` | Culture Amp source | culture_amp.accounts, culture_amp.audit_events, culture_amp.policies, culture_amp.records, culture_amp.users |
| `customer_io` | Customer Io source | customer_io.accounts, customer_io.audit_events, customer_io.policies, customer_io.records, customer_io.users |
| `cyberark_identity` | Cyberark Identity source | cyberark_identity.audit_events, cyberark_identity.groups, cyberark_identity.users |
| `cyberark_pam` | Cyberark Pam source | cyberark_pam.audit_events, cyberark_pam.secrets, cyberark_pam.users |
| `cycode` | Cycode source | cycode.assets, cycode.audit_events, cycode.findings, cycode.policies, cycode.vulnerabilities |
| `cyera` | Cyera source | cyera.assets, cyera.audit_events, cyera.findings, cyera.policies, cyera.vulnerabilities |
| `cyolo` | Cyolo source | cyolo.applications, cyolo.audit_events, cyolo.groups, cyolo.roles, cyolo.users |
| `dashlane_business` | Dashlane Business source | dashlane_business.applications, dashlane_business.audit_events, dashlane_business.groups, dashlane_business.roles, dashlane_business.users |
| `databricks` | Databricks source | databricks.assets, databricks.audit_events, databricks.model_serving_endpoints, databricks.vulnerabilities |
| `datadog` | Datadog observability and incident source | users, roles, teams, monitors, SLOs, dashboards, incidents, audit events |
| `datafold` | Datafold source | datafold.accounts, datafold.audit_events, datafold.policies, datafold.records, datafold.users |
| `dbt_cloud` | Dbt Cloud source | dbt_cloud.accounts, dbt_cloud.audit_events, dbt_cloud.policies, dbt_cloud.records, dbt_cloud.users |
| `dealhub` | Dealhub source | dealhub.accounts, dealhub.audit_events, dealhub.policies, dealhub.records, dealhub.users |
| `deel` | Deel source | deel.accounts, deel.audit_events, deel.policies, deel.records, deel.users |
| `deepseek` | Deepseek source | deepseek.account_balances, deepseek.model_catalog |
| `defectdojo_cloud` | Defectdojo Cloud source | defectdojo_cloud.assets, defectdojo_cloud.audit_events, defectdojo_cloud.findings, defectdojo_cloud.policies, defectdojo_cloud.vulnerabilities |
| `degreed` | Degreed source | degreed.accounts, degreed.audit_events, degreed.policies, degreed.records, degreed.users |
| `delinea` | Delinea source | delinea.applications, delinea.audit_events, delinea.groups, delinea.roles, delinea.users |
| `demandbase` | Demandbase source | demandbase.accounts, demandbase.audit_events, demandbase.policies, demandbase.records, demandbase.users |
| `depot` | Depot source | depot.audit_events, depot.deployments, depot.projects, depot.repositories, depot.users |
| `descope` | Descope source | descope.applications, descope.audit_events, descope.groups, descope.roles, descope.users |
| `detectify` | Detectify source | detectify.assets, detectify.findings, detectify.scan_profiles |
| `devcycle` | Devcycle source | devcycle.audit_events, devcycle.deployments, devcycle.projects, devcycle.repositories, devcycle.users |
| `device42` | Device42 source | device42.applications, device42.audit_events, device42.groups, device42.roles, device42.users |
| `devtron` | Devtron source | devtron.audit_events, devtron.deployments, devtron.projects, devtron.repositories, devtron.users |
| `dialpad` | Dialpad source | dialpad.audit_events, dialpad.documents, dialpad.groups, dialpad.users, dialpad.workspaces |
| `dig_security` | Dig Security source | dig_security.assets, dig_security.audit_events, dig_security.findings, dig_security.policies, dig_security.vulnerabilities |
| `digitalocean` | Digitalocean source | digitalocean.audit_events, digitalocean.droplets, digitalocean.teams |
| `discord` | Discord source | discord.audit_log, discord.member, discord.permission, discord.role |
| `discourse` | Discourse source | discourse.backups_json, discourse.groups_json, discourse.notifications_json, discourse.user_actions_json |
| `divvy` | Divvy source | divvy.accounts, divvy.audit_events, divvy.policies, divvy.records, divvy.users |
| `dixa` | Dixa source | dixa.accounts, dixa.audit_events, dixa.policies, dixa.records, dixa.users |
| `docebo` | Docebo source | docebo.accounts, docebo.audit_events, docebo.policies, docebo.records, docebo.users |
| `docker_hub` | Docker Hub source | docker_hub.audit_events, docker_hub.repositories, docker_hub.users |
| `document360` | Document360 source | document360.audit_events, document360.documents, document360.groups, document360.users, document360.workspaces |
| `docusign` | Docusign source | docusign.bcc_email_archive, docusign.permission_profile, docusign.request_log, docusign.signing_group |
| `domo` | Domo source | domo.accounts, domo.audit_events, domo.policies, domo.records, domo.users |
| `doppler` | Doppler secrets management source | secrets, projects, audit events |
| `dracoon` | Dracoon source | dracoon.channel, dracoon.event_type, dracoon.group, dracoon.user |
| `dragos_worldview` | Dragos Worldview source | dragos_worldview.assets, dragos_worldview.audit_events, dragos_worldview.findings, dragos_worldview.policies, dragos_worldview.vulnerabilities |
| `drata` | Drata source | drata.controls, drata.findings, drata.users |
| `drchrono` | Drchrono source | drchrono.allergy, drchrono.amendment, drchrono.appointment, drchrono.appointment_profile, drchrono.appointment_template, drchrono.care_team_member, drchrono.comm_log, drchrono.implantable_device, drchrono.patient_payment_log, drchrono.patient_risk_assessment, drchrono.user, drchrono.user_group |
| `drift` | Drift source | drift.audit_events, drift.documents, drift.groups, drift.users, drift.workspaces |
| `drone_cloud` | Drone Cloud source | drone_cloud.audit_events, drone_cloud.deployments, drone_cloud.projects, drone_cloud.repositories, drone_cloud.users |
| `dropbox_business` | Dropbox Business source | dropbox_business.audit_events, dropbox_business.content_assets, dropbox_business.users |
| `dropbox_sign` | Dropbox Sign source | dropbox_sign.audit_events, dropbox_sign.documents, dropbox_sign.groups, dropbox_sign.users, dropbox_sign.workspaces |
| `duo` | Duo identity, MFA, application, and audit source | users, groups, administrators, endpoints, phones, tokens, WebAuthn credentials, administrator roles, protected applications, activity logs, authentication logs |
| `dynamics_365_sales` | Dynamics 365 Sales source | dynamics_365_sales.accounts, dynamics_365_sales.audit_events, dynamics_365_sales.policies, dynamics_365_sales.records, dynamics_365_sales.users |
| `dynatrace` | Dynatrace source | dynatrace.alerts, dynatrace.audit_events, dynatrace.dashboards, dynatrace.incidents, dynatrace.monitors |
| `easyllama` | Easyllama source | easyllama.accounts, easyllama.audit_events, easyllama.policies, easyllama.records, easyllama.users |
| `eclypsium` | Eclypsium source | eclypsium.assets, eclypsium.audit_events, eclypsium.findings, eclypsium.policies, eclypsium.vulnerabilities |
| `egnyte` | Egnyte source | egnyte.audit_events, egnyte.documents, egnyte.groups, egnyte.users, egnyte.workspaces |
| `elastic_cloud` | Elastic Cloud source | elastic_cloud.alerts, elastic_cloud.audit_events, elastic_cloud.dashboards, elastic_cloud.incidents, elastic_cloud.monitors |
| `elastic_security` | Elastic Security source | elastic_security.assets, elastic_security.audit_events, elastic_security.findings |
| `elevenlabs` | Elevenlabs source | elevenlabs.auth_connections, elevenlabs.model_catalog, elevenlabs.service_account_api_keys, elevenlabs.service_accounts, elevenlabs.voices, elevenlabs.webhooks |
| `elmah` | Elmah source | elmah.deployment, elmah.log, elmah.message, elmah.uptimecheck |
| `emaildomainhealth` | Email domain authentication posture source (SPF, DKIM, DMARC, MX, MTA-STS) | health |
| `endor_labs` | Endor Labs source | endor_labs.assets, endor_labs.audit_events, endor_labs.findings, endor_labs.policies, endor_labs.vulnerabilities |
| `env0` | Env0 source | env0.audit_events, env0.deployments, env0.projects, env0.repositories, env0.users |
| `envkey` | Envkey source | envkey.applications, envkey.audit_events, envkey.groups, envkey.roles, envkey.users |
| `envoy` | Envoy source | envoy.audit_events, envoy.documents, envoy.groups, envoy.users, envoy.workspaces |
| `envoy_visitors` | Envoy Visitors source | envoy_visitors.accounts, envoy_visitors.audit_events, envoy_visitors.policies, envoy_visitors.records, envoy_visitors.users |
| `ethena` | Ethena source | ethena.course_assignments, ethena.training_statuses, ethena.users |
| `everlaw` | Everlaw source | everlaw.accounts, everlaw.audit_events, everlaw.policies, everlaw.records, everlaw.users |
| `evernote_teams` | Evernote Teams source | evernote_teams.audit_events, evernote_teams.documents, evernote_teams.groups, evernote_teams.users, evernote_teams.workspaces |
| `evidencecas` | EvidenceCAS content-addressed evidence reference source | object manifests |
| `evisort` | Evisort source | evisort.accounts, evisort.audit_events, evisort.policies, evisort.records, evisort.users |
| `exavault` | Exavault source | exavault.email_list, exavault.notification, exavault.session, exavault.ssh_key |
| `expel` | Expel source | expel.assets, expel.audit_events, expel.findings, expel.policies, expel.vulnerabilities |
| `expensify` | Expensify source | expensify.accounts, expensify.audit_events, expensify.policies, expensify.records, expensify.users |
| `fairmarkit` | Fairmarkit source | fairmarkit.accounts, fairmarkit.audit_events, fairmarkit.policies, fairmarkit.records, fairmarkit.users |
| `faros_ai` | Faros Ai source | faros_ai.assets, faros_ai.audit_events, faros_ai.findings, faros_ai.policies, faros_ai.vulnerabilities |
| `fastly` | Fastly source | fastly.acl_entries, fastly.audit_events, fastly.services |
| `fathom_video` | Fathom Video source | fathom_video.audit_events, fathom_video.documents, fathom_video.groups, fathom_video.users, fathom_video.workspaces |
| `featurebase` | Featurebase source | featurebase.audit_events, featurebase.deployments, featurebase.projects, featurebase.repositories, featurebase.users |
| `fifteenfive` | Fifteenfive source | fifteenfive.accounts, fifteenfive.audit_events, fifteenfive.policies, fifteenfive.records, fifteenfive.users |
| `figma` | Figma source | figma.audit_events, figma.projects, figma.users |
| `files_com` | Files Com source | files_com.action_notification_export_result, files_com.api_key, files_com.exavault_reserved, files_com.external_event, files_com.group, files_com.group_user, files_com.login, files_com.permission, files_com.site_api_key, files_com.user, files_com.user_api_key, files_com.user_group |
| `fire` | Fire source | fire.account, fire.aspsp, fire.batche, fire.user |
| `fireflies_ai` | Fireflies Ai source | fireflies_ai.audit_events, fireflies_ai.documents, fireflies_ai.groups, fireflies_ai.users, fireflies_ai.workspaces |
| `firefly` | Firefly source | firefly.audit_events, firefly.deployments, firefly.projects, firefly.repositories, firefly.users |
| `firehydrant` | Firehydrant source | firehydrant.alerts, firehydrant.audit_events, firehydrant.dashboards, firehydrant.incidents, firehydrant.monitors |
| `fireworks_ai` | Fireworks Ai source | fireworks_ai.audit_logs, fireworks_ai.billing_metrics, fireworks_ai.model_deployments, fireworks_ai.service_accounts |
| `firmalyzer` | Firmalyzer source | firmalyzer.account, firmalyzer.config_issue, firmalyzer.private_key, firmalyzer.risk |
| `five9` | Five9 source | five9.accounts, five9.audit_events, five9.policies, five9.records, five9.users |
| `fivetran` | Fivetran source | fivetran.account_info, fivetran.users, fivetran.user_connections, fivetran.user_groups, fivetran.roles, fivetran.teams, fivetran.team_users, fivetran.team_connections, fivetran.team_groups, fivetran.groups, fivetran.group_users, fivetran.group_connections, fivetran.group_public_keys, fivetran.group_service_accounts, fivetran.destinations, fivetran.connections, fivetran.connection_certificates, fivetran.connection_fingerprints, fivetran.connection_schemas, fivetran.connection_state, fivetran.connection_table_columns, fivetran.connector_sdk_packages, fivetran.destination_certificates, fivetran.destination_fingerprints, fivetran.account_log_service, fivetran.log_services, fivetran.webhooks, fivetran.external_secret_managers, fivetran.external_secret_manager_entities, fivetran.external_secret_manager_assignments, fivetran.private_links, fivetran.proxy_agents, fivetran.proxy_agent_connections, fivetran.hybrid_deployment_agents, fivetran.public_connector_types, fivetran.connector_metadata, fivetran.connector_metadata_details, fivetran.system_keys, fivetran.transformations, fivetran.transformation_projects, fivetran.transformation_package_metadata, fivetran.transformation_package_details |
| `flagsmith_cloud` | Flagsmith Cloud source | flagsmith_cloud.audit_events, flagsmith_cloud.deployments, flagsmith_cloud.projects, flagsmith_cloud.repositories, flagsmith_cloud.users |
| `fleetdm` | Fleetdm source | fleetdm.audit_activities, fleetdm.hosts, fleetdm.policies |
| `forethought` | Forethought source | forethought.accounts, forethought.audit_events, forethought.policies, forethought.records, forethought.users |
| `formstack` | Formstack source | formstack.accounts, formstack.audit_events, formstack.policies, formstack.records, formstack.users |
| `foxpass` | Foxpass source | foxpass.applications, foxpass.audit_events, foxpass.groups, foxpass.roles, foxpass.users |
| `freshbooks` | Freshbooks source | freshbooks.accounts, freshbooks.audit_events, freshbooks.policies, freshbooks.records, freshbooks.users |
| `freshdesk` | Freshdesk source | freshdesk.audit_events, freshdesk.documents, freshdesk.groups, freshdesk.users, freshdesk.workspaces |
| `freshsales` | Freshsales source | freshsales.accounts, freshsales.audit_events, freshsales.policies, freshsales.records, freshsales.users |
| `freshservice` | Freshservice source | freshservice.audit_events, freshservice.tickets, freshservice.users |
| `front` | Front source | front.audit_events, front.documents, front.groups, front.users, front.workspaces |
| `frontegg` | Frontegg source | frontegg.applications, frontegg.audit_events, frontegg.groups, frontegg.roles, frontegg.users |
| `frontify` | Frontify source | frontify.audit_events, frontify.documents, frontify.groups, frontify.users, frontify.workspaces |
| `fulfillment_com` | Fulfillment Com source | fulfillment_com.accounting, fulfillment_com.inventory, fulfillment_com.return, fulfillment_com.track |
| `fullstory` | Fullstory source | fullstory.alerts, fullstory.audit_events, fullstory.dashboards, fullstory.incidents, fullstory.monitors |
| `fusionauth` | Fusionauth source | fusionauth.applications, fusionauth.audit_events, fusionauth.groups, fusionauth.roles, fusionauth.users |
| `gainsight` | Gainsight source | gainsight.accounts, gainsight.audit_events, gainsight.policies, gainsight.records, gainsight.users |
| `gcp` | GCP IAM, Cloud Identity, service-account, and audit source | audit, groups, IAM role assignments, service accounts, resource exposure |
| `gem` | Gem source | gem.accounts, gem.audit_events, gem.policies, gem.records, gem.users |
| `genesys_cloud` | Genesys Cloud source | genesys_cloud.accounts, genesys_cloud.audit_events, genesys_cloud.policies, genesys_cloud.records, genesys_cloud.users |
| `gitbook` | Gitbook source | gitbook.audit_events, gitbook.documents, gitbook.groups, gitbook.users, gitbook.workspaces |
| `gitea` | Gitea source | gitea.email, gitea.search, gitea.team, gitea.timeline |
| `gitguardian` | Gitguardian source | gitguardian.audit_events, gitguardian.incidents, gitguardian.members |
| `gitguardian_secrets` | Gitguardian Secrets source | gitguardian_secrets.audit_events, gitguardian_secrets.secrets, gitguardian_secrets.sources |
| `github` | GitHub audit, repository, Dependabot, and pull request source | audit, repository, Dependabot alerts, pull requests; repository and optional org-inventory audit-log freshness probes |
| `gitlab` | Gitlab source | gitlab.audit_events, gitlab.repositories, gitlab.users |
| `gitpod` | Gitpod source | gitpod.audit_events, gitpod.deployments, gitpod.projects, gitpod.repositories, gitpod.users |
| `gladly` | Gladly source | gladly.audit_events, gladly.documents, gladly.groups, gladly.users, gladly.workspaces |
| `gocd` | Gocd source | gocd.audit_events, gocd.deployments, gocd.projects, gocd.repositories, gocd.users |
| `godaddy` | Godaddy source | godaddy.domain, godaddy.maintenance, godaddy.optin, godaddy.tld |
| `gong` | Gong source | gong.accounts, gong.audit_events, gong.policies, gong.records, gong.users |
| `google_analytics_360` | Google Analytics 360 source | google_analytics_360.accounts, google_analytics_360.audit_events, google_analytics_360.policies, google_analytics_360.records, google_analytics_360.users |
| `google_drive` | Google Drive source | google_drive.changes, google_drive.files, google_drive.shared_drives |
| `google_gemini` | Google Gemini source | google_gemini.batch_jobs, google_gemini.cached_contents, google_gemini.files, google_gemini.model_catalog, google_gemini.tuned_models |
| `google_play_console` | Google Play Console source | google_play_console.audit_events, google_play_console.deployments, google_play_console.projects, google_play_console.repositories, google_play_console.users |
| `google_secops_chronicle` | Google Secops Chronicle source | google_secops_chronicle.assets, google_secops_chronicle.audit_events, google_secops_chronicle.findings |
| `google_vertex_ai` | Google Vertex Ai source | google_vertex_ai.batch_prediction_jobs, google_vertex_ai.custom_jobs, google_vertex_ai.endpoints, google_vertex_ai.indexes, google_vertex_ai.models, google_vertex_ai.reasoning_engines |
| `googleworkspace` | Google Workspace Directory and Admin audit source | audit, groups, group members, role assignments, users |
| `gorgias` | Gorgias source | gorgias.audit_events, gorgias.documents, gorgias.groups, gorgias.users, gorgias.workspaces |
| `grafana_cloud` | Grafana Cloud source | grafana_cloud.assets, grafana_cloud.audit_events, grafana_cloud.findings |
| `grain` | Grain source | grain.audit_events, grain.documents, grain.groups, grain.users, grain.workspaces |
| `grammarly_business` | Grammarly Business source | grammarly_business.audit_events, grammarly_business.documents, grammarly_business.groups, grammarly_business.users, grammarly_business.workspaces |
| `gravitee_cloud` | Gravitee Cloud source | gravitee_cloud.audit_events, gravitee_cloud.deployments, gravitee_cloud.projects, gravitee_cloud.repositories, gravitee_cloud.users |
| `grc` | Governance/risk/compliance source | configured GRC families |
| `greenhouse` | Greenhouse source | greenhouse.accounts, greenhouse.audit_events, greenhouse.policies, greenhouse.records, greenhouse.users |
| `greythr` | Greythr source | greythr.accounts, greythr.audit_events, greythr.policies, greythr.records, greythr.users |
| `grip_security` | Grip Security source | grip_security.applications, grip_security.audit_events, grip_security.groups, grip_security.roles, grip_security.users |
| `groq` | Groq source | groq.batch_jobs, groq.files, groq.fine_tuning_jobs, groq.model_catalog |
| `groundcover` | Groundcover source | groundcover.alerts, groundcover.audit_events, groundcover.dashboards, groundcover.incidents, groundcover.monitors |
| `gsmtasks` | Gsmtasks source | gsmtasks.account, gsmtasks.account_role, gsmtasks.client_role, gsmtasks.device, gsmtasks.email, gsmtasks.formrule, gsmtasks.notification, gsmtasks.notification_template, gsmtasks.task_event, gsmtasks.task_event_track, gsmtasks.user, gsmtasks.users_on_duty_log |
| `guru` | Guru source | guru.audit_events, guru.documents, guru.groups, guru.users, guru.workspaces |
| `gusto` | Gusto source | gusto.accounts, gusto.audit_events, gusto.policies, gusto.records, gusto.users |
| `hackerone` | Hackerone source | hackerone.assets, hackerone.audit_events, hackerone.findings, hackerone.policies, hackerone.vulnerabilities |
| `hadrian_security` | Hadrian Security source | hadrian_security.assets, hadrian_security.audit_events, hadrian_security.findings, hadrian_security.policies, hadrian_security.vulnerabilities |
| `harness` | Harness source | harness.audit_events, harness.findings, harness.pipelines |
| `harness_platform` | Harness Platform source | harness_platform.audit_events, harness_platform.deployments, harness_platform.projects, harness_platform.repositories, harness_platform.users |
| `hashicorp_vault` | HashiCorp Vault secrets management source | identity entities, secret engines, audit devices |
| `haveibeenpwned` | Haveibeenpwned source | haveibeenpwned.affected_accounts, haveibeenpwned.audit_events, haveibeenpwned.breaches |
| `healthchecks` | Healthchecks source | healthchecks.alerts, healthchecks.audit_events, healthchecks.dashboards, healthchecks.incidents, healthchecks.monitors |
| `heap` | Heap source | heap.accounts, heap.audit_events, heap.policies, heap.records, heap.users |
| `helpscout` | Helpscout source | helpscout.audit_events, helpscout.documents, helpscout.groups, helpscout.users, helpscout.workspaces |
| `heroku` | Heroku source | heroku.apps, heroku.audit_events, heroku.collaborators |
| `hetzner` | Hetzner source | hetzner.certificate, hetzner.firewall, hetzner.placement_group, hetzner.ssh_key |
| `hevo_data` | Hevo Data source | hevo_data.accounts, hevo_data.audit_events, hevo_data.policies, hevo_data.records, hevo_data.users |
| `hexnode` | Hexnode source | hexnode.applications, hexnode.audit_events, hexnode.groups, hexnode.roles, hexnode.users |
| `hibob` | Hibob source | hibob.accounts, hibob.audit_events, hibob.policies, hibob.records, hibob.users |
| `hid_workforce_identity` | Hid Workforce Identity source | hid_workforce_identity.applications, hid_workforce_identity.audit_events, hid_workforce_identity.groups, hid_workforce_identity.roles, hid_workforce_identity.users |
| `highlight` | Highlight source | highlight.alerts, highlight.audit_events, highlight.dashboards, highlight.incidents, highlight.monitors |
| `highspot` | Highspot source | highspot.accounts, highspot.audit_events, highspot.policies, highspot.records, highspot.users |
| `hightail` | Hightail source | hightail.audit_events, hightail.documents, hightail.groups, hightail.users, hightail.workspaces |
| `hightouch` | Hightouch source | hightouch.accounts, hightouch.audit_events, hightouch.policies, hightouch.records, hightouch.users |
| `hitrust_mycsf` | Hitrust Mycsf source | hitrust_mycsf.assessments, hitrust_mycsf.controls, hitrust_mycsf.evidence |
| `hive` | Hive source | hive.audit_events, hive.documents, hive.groups, hive.users, hive.workspaces |
| `holm_security` | Holm Security source | holm_security.assets, holm_security.audit_events, holm_security.findings, holm_security.policies, holm_security.vulnerabilities |
| `honeybadger` | Honeybadger source | honeybadger.alerts, honeybadger.audit_events, honeybadger.dashboards, honeybadger.incidents, honeybadger.monitors |
| `honeycomb` | Honeycomb source | honeycomb.alerts, honeycomb.audit_events, honeycomb.dashboards, honeycomb.incidents, honeycomb.monitors |
| `hotjar` | Hotjar source | hotjar.accounts, hotjar.audit_events, hotjar.policies, hotjar.records, hotjar.users |
| `hubspot` | Hubspot source | hubspot.assets, hubspot.audit_events, hubspot.users |
| `hudsonrock` | Hudsonrock source | hudsonrock.audit_events, hudsonrock.domains, hudsonrock.infostealers |
| `huggingface` | Huggingface source | huggingface.audit_logs, huggingface.organization_members, huggingface.repositories, huggingface.resource_groups |
| `huntr` | Huntr source | huntr.assets, huntr.audit_events, huntr.findings, huntr.policies, huntr.vulnerabilities |
| `hyperdx` | Hyperdx source | hyperdx.alerts, hyperdx.audit_events, hyperdx.dashboards, hyperdx.incidents, hyperdx.monitors |
| `hyperproof` | Hyperproof source | hyperproof.assets, hyperproof.audit_events, hyperproof.findings, hyperproof.policies, hyperproof.vulnerabilities |
| `ibm_randori` | Ibm Randori source | ibm_randori.assets, ibm_randori.audit_events, ibm_randori.findings, ibm_randori.policies, ibm_randori.vulnerabilities |
| `ibm_watsonx_ai` | Ibm Watsonx Ai source | ibm_watsonx_ai.custom_models, ibm_watsonx_ai.deployments, ibm_watsonx_ai.foundation_model_specs, ibm_watsonx_ai.foundation_model_tasks, ibm_watsonx_ai.training_jobs |
| `icertis` | Icertis source | icertis.accounts, icertis.audit_events, icertis.policies, icertis.records, icertis.users |
| `icims` | Icims source | icims.accounts, icims.audit_events, icims.policies, icims.records, icims.users |
| `ilert` | Ilert source | ilert.alerts, ilert.audit_events, ilert.dashboards, ilert.incidents, ilert.monitors |
| `illumidesk` | Illumidesk source | illumidesk.application, illumidesk.card, illumidesk.deployment, illumidesk.email, illumidesk.entity, illumidesk.group, illumidesk.invoice, illumidesk.notification, illumidesk.profile, illumidesk.server_size, illumidesk.setting, illumidesk.team |
| `imanage_cloud` | Imanage Cloud source | imanage_cloud.accounts, imanage_cloud.audit_events, imanage_cloud.policies, imanage_cloud.records, imanage_cloud.users |
| `immuta` | Immuta source | immuta.accounts, immuta.audit_events, immuta.policies, immuta.records, immuta.users |
| `imprivata` | Imprivata source | imprivata.applications, imprivata.audit_events, imprivata.groups, imprivata.roles, imprivata.users |
| `incident_io` | Incident Io source | incident_io.alerts, incident_io.audit_events, incident_io.dashboards, incident_io.incidents, incident_io.monitors |
| `increase` | Increase source | increase.account, increase.account_number, increase.account_statement, increase.account_transfer, increase.ach_prenotification, increase.ach_transfer, increase.card, increase.digital_wallet_token, increase.event, increase.event_subscription, increase.external_account, increase.oauth_connection |
| `infisical` | Infisical source | infisical.audit_events, infisical.deployments, infisical.projects, infisical.repositories, infisical.users |
| `influxdata` | Influxdata source | influxdata.dbrp, influxdata.log, influxdata.secret, influxdata.user |
| `insomnia_cloud` | Insomnia Cloud source | insomnia_cloud.audit_events, insomnia_cloud.deployments, insomnia_cloud.projects, insomnia_cloud.repositories, insomnia_cloud.users |
| `intercom` | Intercom source | intercom.audit_events, intercom.documents, intercom.groups, intercom.users, intercom.workspaces |
| `intruder` | Intruder source | intruder.assets, intruder.audit_events, intruder.findings, intruder.policies, intruder.vulnerabilities |
| `invicti` | Invicti source | invicti.assets, invicti.audit_events, invicti.findings, invicti.policies, invicti.vulnerabilities |
| `iqualify` | Iqualify source | iqualify.courses, iqualify.current, iqualify.future, iqualify.group, iqualify.learner, iqualify.learners_progress, iqualify.progress, iqualify.pulses, iqualify.responses, iqualify.social_note, iqualify.unit_reaction, iqualify.user |
| `ironclad` | Ironclad source | ironclad.accounts, ironclad.audit_events, ironclad.policies, ironclad.records, ironclad.users |
| `island` | Island source | island.applications, island.audit_events, island.groups, island.roles, island.users |
| `iterable` | Iterable source | iterable.accounts, iterable.audit_events, iterable.policies, iterable.records, iterable.users |
| `jamf_pro` | Jamf Pro source | jamf_pro.applications, jamf_pro.audit_events, jamf_pro.groups, jamf_pro.roles, jamf_pro.users |
| `jamf_protect` | Jamf Protect source | jamf_protect.applications, jamf_protect.audit_events, jamf_protect.groups, jamf_protect.roles, jamf_protect.users |
| `jenkins` | Jenkins source | jenkins.audit_events, jenkins.findings, jenkins.pipelines |
| `jetbrains_space` | Jetbrains Space source | jetbrains_space.audit_events, jetbrains_space.deployments, jetbrains_space.projects, jetbrains_space.repositories, jetbrains_space.users |
| `jfrog_artifactory` | Jfrog Artifactory source | jfrog_artifactory.audit_events, jfrog_artifactory.deployments, jfrog_artifactory.projects, jfrog_artifactory.repositories, jfrog_artifactory.users |
| `jfrog_artifactory_xray` | Jfrog Artifactory Xray source | jfrog_artifactory_xray.assets, jfrog_artifactory_xray.findings, jfrog_artifactory_xray.vulnerabilities |
| `jfrog_xray` | Jfrog Xray source | jfrog_xray.audit_events, jfrog_xray.deployments, jfrog_xray.projects, jfrog_xray.repositories, jfrog_xray.users |
| `jira` | Jira source | jira.audit_events, jira.projects, jira.users |
| `journy_io` | Journy Io source | journy_io.account, journy_io.event, journy_io.segments_account, journy_io.segments_user, journy_io.user |
| `jumpcloud` | Jumpcloud source | jumpcloud.applications, jumpcloud.audit_events, jumpcloud.group_members, jumpcloud.groups, jumpcloud.system_groups, jumpcloud.systems, jumpcloud.users |
| `jumpseller` | Jumpseller source | jumpseller.checkout_custom_fields_json, jumpseller.countries_json, jumpseller.custom_fields_json, jumpseller.customer_categories_json, jumpseller.customers_json, jumpseller.fulfillments_json, jumpseller.hooks_json, jumpseller.jsapps_json, jumpseller.orders_json, jumpseller.pages_json, jumpseller.payment_methods_json, jumpseller.products_json |
| `justworks` | Justworks source | justworks.accounts, justworks.audit_events, justworks.policies, justworks.records, justworks.users |
| `k6_cloud` | K6 Cloud source | k6_cloud.audit_events, k6_cloud.deployments, k6_cloud.projects, k6_cloud.repositories, k6_cloud.users |
| `kandji` | Kandji device/application/vulnerability source | devices, applications, vulnerabilities |
| `keeper` | Keeper source | keeper.audit_events, keeper.secrets, keeper.users |
| `keeper_security` | Keeper Security source | keeper_security.applications, keeper_security.audit_events, keeper_security.groups, keeper_security.roles, keeper_security.users |
| `kenna_security` | Kenna Security source | kenna_security.assets, kenna_security.audit_events, kenna_security.findings, kenna_security.policies, kenna_security.vulnerabilities |
| `kentik` | Kentik source | kentik.alerts, kentik.audit_events, kentik.dashboards, kentik.incidents, kentik.monitors |
| `keycloak` | Keycloak source | keycloak.audit_events, keycloak.groups, keycloak.users |
| `klaviyo` | Klaviyo source | klaviyo.accounts, klaviyo.audit_events, klaviyo.policies, klaviyo.records, klaviyo.users |
| `knowbe4` | Knowbe4 source | knowbe4.groups, knowbe4.phishing_campaigns, knowbe4.training_enrollments, knowbe4.users |
| `kolide` | Kolide device posture source | configured catalog families |
| `kong_konnect` | Kong Konnect source | kong_konnect.audit_events, kong_konnect.deployments, kong_konnect.projects, kong_konnect.repositories, kong_konnect.users |
| `kubernetes` | Kubernetes inventory source | clusters, namespaces, pods, containers, service accounts, workloads, workload identity bindings |
| `kustomer` | Kustomer source | kustomer.audit_events, kustomer.documents, kustomer.groups, kustomer.users, kustomer.workspaces |
| `lacework` | Lacework source | lacework.assets, lacework.findings, lacework.vulnerabilities |
| `lambdatest` | Lambdatest source | lambdatest.location, lambdatest.profile, lambdatest.resolution, lambdatest.resource |
| `laminar_security` | Laminar Security source | laminar_security.assets, laminar_security.audit_events, laminar_security.findings, laminar_security.policies, laminar_security.vulnerabilities |
| `langchain` | LangChain LangSmith governance and observability source | organization, workspaces, members, roles, service keys, service accounts, tracing projects, runs, feedback, datasets, usage limits, audit logs |
| `langfuse` | Langfuse LLM observability and prompt-management source | projects, project memberships, project API keys, traces, observations, scores, prompts, sessions, metrics, annotation queues |
| `last9` | Last9 source | last9.alerts, last9.audit_events, last9.dashboards, last9.incidents, last9.monitors |
| `lastpass_business` | Lastpass Business source | lastpass_business.audit_events, lastpass_business.secrets, lastpass_business.users |
| `lattice` | Lattice source | lattice.accounts, lattice.audit_events, lattice.policies, lattice.records, lattice.users |
| `launchdarkly` | Launchdarkly source | launchdarkly.audit_events, launchdarkly.repositories, launchdarkly.users |
| `leapsome` | Leapsome source | leapsome.accounts, leapsome.audit_events, leapsome.policies, leapsome.records, leapsome.users |
| `learnifier` | Learnifier source | learnifier.coursedesign, learnifier.globalusergroup, learnifier.member, learnifier.orgunit, learnifier.orgunits_usergroup, learnifier.participant, learnifier.project, learnifier.teammember, learnifier.user, learnifier.usergroup, learnifier.usergroups_member |
| `legit_security` | Legit Security source | legit_security.assets, legit_security.audit_events, legit_security.findings, legit_security.policies, legit_security.vulnerabilities |
| `lessonly` | Lessonly source | lessonly.accounts, lessonly.audit_events, lessonly.policies, lessonly.records, lessonly.users |
| `lever` | Lever source | lever.accounts, lever.audit_events, lever.policies, lever.records, lever.users |
| `lightstep` | Lightstep source | lightstep.alerts, lightstep.audit_events, lightstep.dashboards, lightstep.incidents, lightstep.monitors |
| `linear` | Linear source | linear.audit_events, linear.projects, linear.users |
| `linksquares` | Linksquares source | linksquares.accounts, linksquares.audit_events, linksquares.policies, linksquares.records, linksquares.users |
| `linode` | Linode source | linode.credential, linode.event, linode.issue, linode.user |
| `livestorm` | Livestorm source | livestorm.audit_events, livestorm.documents, livestorm.groups, livestorm.users, livestorm.workspaces |
| `logicgate` | Logicgate source | logicgate.assets, logicgate.audit_events, logicgate.findings, logicgate.policies, logicgate.vulnerabilities |
| `logicmonitor` | Logicmonitor source | logicmonitor.alerts, logicmonitor.audit_events, logicmonitor.dashboards, logicmonitor.incidents, logicmonitor.monitors |
| `logrocket` | Logrocket source | logrocket.alerts, logrocket.audit_events, logrocket.dashboards, logrocket.incidents, logrocket.monitors |
| `logz_io` | Logz Io source | logz_io.alerts, logz_io.audit_events, logz_io.dashboards, logz_io.incidents, logz_io.monitors |
| `loket` | Loket source | loket.actualorganizationalentity, loket.customnotification, loket.emailidentity, loket.integration |
| `looker` | Looker source | looker.accounts, looker.audit_events, looker.policies, looker.records, looker.users |
| `loom` | Loom source | loom.audit_events, loom.documents, loom.groups, loom.users, loom.workspaces |
| `lucidchart` | Lucidchart source | lucidchart.audit_events, lucidchart.documents, lucidchart.groups, lucidchart.users, lucidchart.workspaces |
| `lucidscale` | Lucidscale source | lucidscale.audit_events, lucidscale.documents, lucidscale.groups, lucidscale.users, lucidscale.workspaces |
| `lumos_identity` | Lumos Identity source | lumos_identity.applications, lumos_identity.audit_events, lumos_identity.groups, lumos_identity.roles, lumos_identity.users |
| `mabl` | Mabl source | mabl.audit_events, mabl.deployments, mabl.projects, mabl.repositories, mabl.users |
| `magento` | Magento source | magento.attribute, magento.coupons_search, magento.role, magento.search |
| `mailchimp` | Mailchimp source | mailchimp.audit_events, mailchimp.lists, mailchimp.members |
| `mailscript` | Mailscript source | mailscript.action, mailscript.addresses, mailscript.domain, mailscript.input, mailscript.integration, mailscript.key, mailscript.trigger, mailscript.verification, mailscript.verify, mailscript.workflow, mailscript.workspace |
| `manageengine_endpoint_central` | Manageengine Endpoint Central source | manageengine_endpoint_central.applications, manageengine_endpoint_central.audit_events, manageengine_endpoint_central.groups, manageengine_endpoint_central.roles, manageengine_endpoint_central.users |
| `mandiant_advantage` | Mandiant Advantage source | mandiant_advantage.assets, mandiant_advantage.audit_events, mandiant_advantage.findings, mandiant_advantage.policies, mandiant_advantage.vulnerabilities |
| `marketo` | Marketo source | marketo.accounts, marketo.audit_events, marketo.policies, marketo.records, marketo.users |
| `mastodon` | Mastodon source | mastodon.account, mastodon.activity, mastodon.notification, mastodon.verify_credential |
| `material_security` | Material Security source | material_security.assets, material_security.audit_events, material_security.findings, material_security.policies, material_security.vulnerabilities |
| `matillion` | Matillion source | matillion.accounts, matillion.audit_events, matillion.policies, matillion.records, matillion.users |
| `maxio` | Maxio source | maxio.accounts, maxio.audit_events, maxio.policies, maxio.records, maxio.users |
| `meistertask` | Meistertask source | meistertask.audit_events, meistertask.documents, meistertask.groups, meistertask.users, meistertask.workspaces |
| `mend_io` | Mend Io source | mend_io.assets, mend_io.findings, mend_io.vulnerabilities |
| `mentimeter` | Mentimeter source | mentimeter.audit_events, mentimeter.documents, mentimeter.groups, mentimeter.users, mentimeter.workspaces |
| `meraki` | Cisco Meraki Dashboard API source | event types, organizations, Meraki auth users, access policies |
| `mercury` | Mercury source | mercury.accounts, mercury.transactions, mercury.users |
| `mesh_payments` | Mesh Payments source | mesh_payments.accounts, mesh_payments.audit_events, mesh_payments.policies, mesh_payments.records, mesh_payments.users |
| `metaplane` | Metaplane source | metaplane.accounts, metaplane.audit_events, metaplane.policies, metaplane.records, metaplane.users |
| `mezmo` | Mezmo source | mezmo.alerts, mezmo.audit_events, mezmo.dashboards, mezmo.incidents, mezmo.monitors |
| `microsoft_365` | Microsoft 365 source | microsoft_365.audit_events, microsoft_365.content_assets, microsoft_365.users |
| `microsoft_defender_for_cloud` | Microsoft Defender For Cloud source | microsoft_defender_for_cloud.assets, microsoft_defender_for_cloud.findings, microsoft_defender_for_cloud.vulnerabilities |
| `microsoft_defender_for_cloud_apps` | Microsoft Defender For Cloud Apps source | microsoft_defender_for_cloud_apps.assets, microsoft_defender_for_cloud_apps.findings, microsoft_defender_for_cloud_apps.vulnerabilities |
| `microsoft_defender_for_endpoint` | Microsoft Defender For Endpoint source | microsoft_defender_for_endpoint.endpoint_devices, microsoft_defender_for_endpoint.findings, microsoft_defender_for_endpoint.vulnerabilities |
| `microsoft_entra_id` | Microsoft Entra Id source | microsoft_entra_id.audit_events, microsoft_entra_id.groups, microsoft_entra_id.users |
| `microsoft_foundry` | Microsoft Foundry source | microsoft_foundry.agents, microsoft_foundry.connections, microsoft_foundry.datasets, microsoft_foundry.evaluations, microsoft_foundry.indexes |
| `microsoft_sentinel` | Microsoft Sentinel source | microsoft_sentinel.assets, microsoft_sentinel.audit_events, microsoft_sentinel.findings |
| `microsoft_teams` | Microsoft Teams source | microsoft_teams.audit_events, microsoft_teams.content_assets, microsoft_teams.users |
| `mimecast` | Mimecast source | mimecast.assets, mimecast.audit_events, mimecast.findings, mimecast.policies, mimecast.vulnerabilities |
| `miradore` | Miradore source | miradore.applications, miradore.audit_events, miradore.groups, miradore.roles, miradore.users |
| `miro` | Miro source | miro.audit_events, miro.projects, miro.users |
| `mist` | Mist source | mist.alarmtemplate, mist.call_event, mist.secpolicy, mist.sitegroup |
| `mistral` | Mistral source | mistral.api_keys, mistral.audit_logs, mistral.usage_reports, mistral.workspaces |
| `mobileiron` | Mobileiron source | mobileiron.applications, mobileiron.audit_events, mobileiron.groups, mobileiron.roles, mobileiron.users |
| `mode_analytics` | Mode Analytics source | mode_analytics.accounts, mode_analytics.audit_events, mode_analytics.policies, mode_analytics.records, mode_analytics.users |
| `monday_com` | Monday Com source | monday_com.audit_events, monday_com.projects, monday_com.users |
| `mongodb_atlas` | Mongodb Atlas source | mongodb_atlas.assets, mongodb_atlas.audit_events, mongodb_atlas.vulnerabilities |
| `monte_carlo_data` | Monte Carlo Data source | monte_carlo_data.accounts, monte_carlo_data.audit_events, monte_carlo_data.policies, monte_carlo_data.records, monte_carlo_data.users |
| `moogsoft` | Moogsoft source | moogsoft.alerts, moogsoft.audit_events, moogsoft.dashboards, moogsoft.incidents, moogsoft.monitors |
| `mosyle` | Mosyle source | mosyle.applications, mosyle.audit_events, mosyle.groups, mosyle.roles, mosyle.users |
| `motaword` | Motaword source | motaword.activities_comment, motaword.activity, motaword.blog, motaword.comment, motaword.corporate_user, motaword.corporate_user_group, motaword.corporates_user, motaword.permission, motaword.projects_activity, motaword.user, motaword.user_group, motaword.user_group_2 |
| `mparticle` | Mparticle source | mparticle.accounts, mparticle.audit_events, mparticle.policies, mparticle.records, mparticle.users |
| `mulesoft_anypoint` | Mulesoft Anypoint source | mulesoft_anypoint.audit_events, mulesoft_anypoint.deployments, mulesoft_anypoint.projects, mulesoft_anypoint.repositories, mulesoft_anypoint.users |
| `multiplier` | Multiplier source | multiplier.accounts, multiplier.audit_events, multiplier.policies, multiplier.records, multiplier.users |
| `mural` | Mural source | mural.audit_events, mural.documents, mural.groups, mural.users, mural.workspaces |
| `n_auth` | N Auth source | n_auth.account, n_auth.apikey, n_auth.permission, n_auth.user |
| `namely` | Namely source | namely.accounts, namely.audit_events, namely.policies, namely.records, namely.users |
| `navan` | Navan source | navan.accounts, navan.audit_events, navan.policies, navan.records, navan.users |
| `netboxdemo` | Netboxdemo source | netboxdemo.cluster_group, netboxdemo.connected_device, netboxdemo.device_role, netboxdemo.secret |
| `netdocuments` | Netdocuments source | netdocuments.accounts, netdocuments.audit_events, netdocuments.policies, netdocuments.records, netdocuments.users |
| `netlicensing` | Netlicensing source | netlicensing.license, netlicensing.licensee, netlicensing.licensetemplate, netlicensing.token |
| `netlify` | Netlify source | netlify.audit_events, netlify.deployments, netlify.projects, netlify.repositories, netlify.users |
| `netskope` | Netskope source | netskope.assets, netskope.audit_events, netskope.findings, netskope.policies, netskope.vulnerabilities |
| `netspi_platform` | Netspi Platform source | netspi_platform.assets, netspi_platform.audit_events, netspi_platform.findings, netspi_platform.policies, netspi_platform.vulnerabilities |
| `netsuite` | Netsuite source | netsuite.assets, netsuite.audit_events, netsuite.users |
| `neutrinoapi` | Neutrinoapi source | neutrinoapi.bin_lookup, neutrinoapi.geocode_address, neutrinoapi.host_reputation, neutrinoapi.ip_blocklist |
| `new_relic` | New Relic source | new_relic.assets, new_relic.audit_events, new_relic.findings |
| `nice_cxone` | Nice Cxone source | nice_cxone.accounts, nice_cxone.audit_events, nice_cxone.policies, nice_cxone.records, nice_cxone.users |
| `noetic_cyber` | Noetic Cyber source | noetic_cyber.assets, noetic_cyber.audit_events, noetic_cyber.findings, noetic_cyber.policies, noetic_cyber.vulnerabilities |
| `noname_security` | Noname Security source | noname_security.assets, noname_security.audit_events, noname_security.findings, noname_security.policies, noname_security.vulnerabilities |
| `noosh` | Noosh source | noosh.automaticinvitation, noosh.billingrecipient, noosh.clientworkgroup, noosh.clientworkgroups_projecthomeuserfield, noosh.memberrole, noosh.projecthomeuserfield, noosh.supplierworkgroup, noosh.teammember, noosh.teammembersofclientproject, noosh.teamtemplate, noosh.workgroup, noosh.workgroupmember |
| `nordigen` | Nordigen source | nordigen.account, nordigen.creditor, nordigen.enduser, nordigen.institution |
| `nordlayer` | Nordlayer source | nordlayer.applications, nordlayer.audit_events, nordlayer.groups, nordlayer.roles, nordlayer.users |
| `normalyze` | Normalyze source | normalyze.assets, normalyze.audit_events, normalyze.findings, normalyze.policies, normalyze.vulnerabilities |
| `notion` | Notion source | notion.audit_events, notion.projects, notion.users |
| `nucleus_security` | Nucleus Security source | nucleus_security.assets, nucleus_security.audit_events, nucleus_security.findings, nucleus_security.policies, nucleus_security.vulnerabilities |
| `nuclino` | Nuclino source | nuclino.audit_events, nuclino.documents, nuclino.groups, nuclino.users, nuclino.workspaces |
| `nudge_security` | Nudge Security source | nudge_security.applications, nudge_security.audit_events, nudge_security.groups, nudge_security.roles, nudge_security.users |
| `observe_platform` | Observe Platform source | observe_platform.alerts, observe_platform.audit_events, observe_platform.dashboards, observe_platform.incidents, observe_platform.monitors |
| `obsidian_security` | Obsidian Security source | obsidian_security.assets, obsidian_security.audit_events, obsidian_security.findings, obsidian_security.policies, obsidian_security.vulnerabilities |
| `octopus_deploy` | Octopus Deploy source | octopus_deploy.audit_events, octopus_deploy.deployments, octopus_deploy.projects, octopus_deploy.repositories, octopus_deploy.users |
| `office_space` | Office Space source | office_space.audit_events, office_space.documents, office_space.groups, office_space.users, office_space.workspaces |
| `okta` | Okta audit, identity inventory, app, group, authenticator, assignment, and admin role source | audit, users, groups, applications, assignments, admin roles, authenticators, threat insight |
| `omada_identity` | Omada Identity source | omada_identity.applications, omada_identity.audit_events, omada_identity.groups, omada_identity.roles, omada_identity.users |
| `omni_analytics` | Omni Analytics source | omni_analytics.accounts, omni_analytics.audit_events, omni_analytics.policies, omni_analytics.records, omni_analytics.users |
| `onelogin` | OneLogin identity, app, privilege, MFA, assignment, policy, and audit source | users, groups, roles, apps, privileges, mappings, app rules, MFA devices, user/role/app/privilege assignments, audit events |
| `onepassword_business` | Onepassword Business source | onepassword_business.audit_events, onepassword_business.secrets, onepassword_business.users |
| `onetrust` | Onetrust source | onetrust.controls, onetrust.findings, onetrust.users |
| `opal_security` | Opal Security source | opal_security.applications, opal_security.audit_events, opal_security.groups, opal_security.roles, opal_security.users |
| `openai` | OpenAI organization governance source | audit logs, users, invites, groups, roles, projects, project access, service accounts, API keys, usage/costs, retention, spend alerts, certificates, rate limits, model/tool permissions |
| `opendatasoft` | Opendatasoft source | opendatasoft.aggregate, opendatasoft.attachment, opendatasoft.dataset, opendatasoft.datasets_aggregate, opendatasoft.datasets_facet, opendatasoft.facet, opendatasoft.metadata_template, opendatasoft.page, opendatasoft.record, opendatasoft.resource, opendatasoft.resource_2, opendatasoft.reuses |
| `openfintech` | Openfintech source | openfintech.bank, openfintech.country, openfintech.currency, openfintech.organization |
| `openpolicy` | Openpolicy source | openpolicy.data, openpolicy.policy, openpolicy.query, openpolicy.v1_policy |
| `openrouter` | Openrouter source | openrouter.api_keys, openrouter.organization_members, openrouter.provider_keys, openrouter.usage_reports |
| `opsgenie` | Opsgenie source | opsgenie.audit_events, opsgenie.tickets, opsgenie.users |
| `opslevel` | Opslevel source | opslevel.audit_events, opslevel.deployments, opslevel.projects, opslevel.repositories, opslevel.users |
| `optimizely_feature_experimentation` | Optimizely Feature Experimentation source | optimizely_feature_experimentation.audit_events, optimizely_feature_experimentation.deployments, optimizely_feature_experimentation.projects, optimizely_feature_experimentation.repositories, optimizely_feature_experimentation.users |
| `oracle_hcm` | Oracle Hcm source | oracle_hcm.accounts, oracle_hcm.audit_events, oracle_hcm.policies, oracle_hcm.records, oracle_hcm.users |
| `orca` | Orca source | orca.assets, orca.findings, orca.vulnerabilities |
| `orca_security` | Orca Security source | orca_security.assets, orca_security.audit_events, orca_security.findings, orca_security.policies, orca_security.vulnerabilities |
| `ordway` | Ordway source | ordway.accounts, ordway.audit_events, ordway.policies, ordway.records, ordway.users |
| `osisoft` | Osisoft source | osisoft.analysisruleplugin, osisoft.assetserver, osisoft.baseelementtemplate, osisoft.elements_eventframe, osisoft.elementtemplate, osisoft.eventframe, osisoft.eventframeattribute, osisoft.eventframes_eventframe, osisoft.eventframes_eventframeattribute, osisoft.notificationcontacttemplates_search, osisoft.search, osisoft.securityidentity |
| `otter_ai` | Otter Ai source | otter_ai.audit_events, otter_ai.documents, otter_ai.groups, otter_ai.users, otter_ai.workspaces |
| `outreach` | Outreach source | outreach.accounts, outreach.audit_events, outreach.policies, outreach.records, outreach.users |
| `oyster_hr` | Oyster Hr source | oyster_hr.accounts, oyster_hr.audit_events, oyster_hr.policies, oyster_hr.records, oyster_hr.users |
| `paddle` | Paddle source | paddle.accounts, paddle.audit_events, paddle.policies, paddle.records, paddle.users |
| `pagerduty` | PagerDuty incident management source | users, teams, services, schedules, escalation policies, integrations, vendors |
| `pandadoc` | Pandadoc source | pandadoc.accounts, pandadoc.audit_events, pandadoc.policies, pandadoc.records, pandadoc.users |
| `panopticon` | Panopticon security operations API source | cases by default; alerts and IOCs explicitly |
| `panther` | Panther source | panther.assets, panther.audit_events, panther.findings |
| `pathlock` | Pathlock source | pathlock.applications, pathlock.audit_events, pathlock.groups, pathlock.roles, pathlock.users |
| `paychex_flex` | Paychex Flex source | paychex_flex.accounts, paychex_flex.audit_events, paychex_flex.policies, paychex_flex.records, paychex_flex.users |
| `paycom` | Paycom source | paycom.accounts, paycom.audit_events, paycom.policies, paycom.records, paycom.users |
| `paylocity` | Paylocity source | paylocity.accounts, paylocity.audit_events, paylocity.policies, paylocity.records, paylocity.users |
| `paylocity_time` | Paylocity Time source | paylocity_time.accounts, paylocity_time.audit_events, paylocity_time.policies, paylocity_time.records, paylocity_time.users |
| `pendo` | Pendo source | pendo.account, pendo.feature, pendo.search, pendo.user |
| `perfecto` | Perfecto source | perfecto.audit_events, perfecto.deployments, perfecto.projects, perfecto.repositories, perfecto.users |
| `perforce_helix_cloud` | Perforce Helix Cloud source | perforce_helix_cloud.audit_events, perforce_helix_cloud.deployments, perforce_helix_cloud.projects, perforce_helix_cloud.repositories, perforce_helix_cloud.users |
| `performyard` | Performyard source | performyard.accounts, performyard.audit_events, performyard.policies, performyard.records, performyard.users |
| `perimeter81` | Perimeter81 source | perimeter81.applications, perimeter81.audit_events, perimeter81.groups, perimeter81.roles, perimeter81.users |
| `permit_io` | Permit Io source | permit_io.applications, permit_io.audit_events, permit_io.groups, permit_io.roles, permit_io.users |
| `perplexity` | Perplexity source | perplexity.api_groups, perplexity.api_keys, perplexity.team_members, perplexity.usage_reports |
| `personio` | Personio source | personio.accounts, personio.audit_events, personio.policies, personio.records, personio.users |
| `pinecone` | Pinecone source | pinecone.backups, pinecone.collections, pinecone.indexes, pinecone.restore_jobs |
| `pingdom` | Pingdom source | pingdom.alerts, pingdom.audit_events, pingdom.dashboards, pingdom.incidents, pingdom.monitors |
| `pingone` | Pingone source | pingone.audit_events, pingone.groups, pingone.users |
| `pipedrive` | Pipedrive source | pipedrive.accounts, pipedrive.audit_events, pipedrive.policies, pipedrive.records, pipedrive.users |
| `pitch` | Pitch source | pitch.audit_events, pitch.documents, pitch.groups, pitch.users, pitch.workspaces |
| `planview_adaptivework` | Planview Adaptivework source | planview_adaptivework.audit_events, planview_adaptivework.documents, planview_adaptivework.groups, planview_adaptivework.users, planview_adaptivework.workspaces |
| `platform_sh` | Platform Sh source | platform_sh.audit_events, platform_sh.deployments, platform_sh.projects, platform_sh.repositories, platform_sh.users |
| `plextrac` | Plextrac source | plextrac.assets, plextrac.audit_events, plextrac.findings, plextrac.policies, plextrac.vulnerabilities |
| `portable` | Portable source | portable.accounts, portable.audit_events, portable.policies, portable.records, portable.users |
| `portainer_cloud` | Portainer Cloud source | portainer_cloud.audit_events, portainer_cloud.deployments, portainer_cloud.projects, portainer_cloud.repositories, portainer_cloud.users |
| `portswigger_enterprise` | Portswigger Enterprise source | portswigger_enterprise.assets, portswigger_enterprise.audit_events, portswigger_enterprise.findings, portswigger_enterprise.policies, portswigger_enterprise.vulnerabilities |
| `postman` | Postman source | postman.audit_events, postman.collections, postman.environments |
| `postmark` | Postmark source | postmark.audit_events, postmark.domains, postmark.servers |
| `power_bi` | Power Bi source | power_bi.accounts, power_bi.audit_events, power_bi.policies, power_bi.records, power_bi.users |
| `prisma_cloud` | Prisma Cloud source | prisma_cloud.assets, prisma_cloud.findings, prisma_cloud.vulnerabilities |
| `privacera` | Privacera source | privacera.assets, privacera.audit_events, privacera.findings, privacera.policies, privacera.vulnerabilities |
| `probely` | Probely web vulnerability scanning source | findings needing attention, events, users, frameworks |
| `procurify` | Procurify source | procurify.accounts, procurify.audit_events, procurify.policies, procurify.records, procurify.users |
| `productboard` | Productboard source | productboard.audit_events, productboard.deployments, productboard.projects, productboard.repositories, productboard.users |
| `productiv` | Productiv source | productiv.applications, productiv.audit_events, productiv.groups, productiv.roles, productiv.users |
| `proofpoint` | Proofpoint source | proofpoint.assets, proofpoint.audit_events, proofpoint.findings, proofpoint.policies, proofpoint.vulnerabilities |
| `proposify` | Proposify source | proposify.accounts, proposify.audit_events, proposify.policies, proposify.records, proposify.users |
| `pulumi_cloud` | Pulumi Cloud source | pulumi_cloud.audit_events, pulumi_cloud.repositories, pulumi_cloud.users |
| `push_security` | Push Security source | push_security.applications, push_security.audit_events, push_security.groups, push_security.roles, push_security.users |
| `qdrant_cloud` | Qdrant Cloud source | qdrant_cloud.account_members, qdrant_cloud.accounts, qdrant_cloud.backup_restores, qdrant_cloud.backup_schedules, qdrant_cloud.backups, qdrant_cloud.clusters, qdrant_cloud.database_api_keys, qdrant_cloud.roles |
| `qodo` | Qodo source | qodo.audit_events, qodo.deployments, qodo.projects, qodo.repositories, qodo.users |
| `qualtrics` | Qualtrics source | qualtrics.accounts, qualtrics.audit_events, qualtrics.policies, qualtrics.records, qualtrics.users |
| `qualys_vm` | Qualys Vm source | qualys_vm.assets, qualys_vm.audit_events, qualys_vm.findings, qualys_vm.policies, qualys_vm.vulnerabilities |
| `qualys_vmdr` | Qualys Vmdr source | qualys_vmdr.assets, qualys_vmdr.findings, qualys_vmdr.vulnerabilities |
| `quay` | Quay source | quay.audit_events, quay.deployments, quay.projects, quay.repositories, quay.users |
| `quickbase` | Quickbase source | quickbase.accounts, quickbase.audit_events, quickbase.policies, quickbase.records, quickbase.users |
| `quickbooks_online` | Quickbooks Online source | quickbooks_online.accounts, quickbooks_online.audit_events, quickbooks_online.policies, quickbooks_online.records, quickbooks_online.users |
| `quip` | Quip source | quip.audit_events, quip.documents, quip.groups, quip.users, quip.workspaces |
| `rally` | Rally source | rally.audit_events, rally.deployments, rally.projects, rally.repositories, rally.users |
| `ramp` | Ramp source | ramp.cards, ramp.transactions, ramp.users |
| `rapid7_insightidr` | Rapid7 Insightidr source | rapid7_insightidr.assets, rapid7_insightidr.audit_events, rapid7_insightidr.findings, rapid7_insightidr.policies, rapid7_insightidr.vulnerabilities |
| `rapid7_insightvm` | Rapid7 Insightvm source | rapid7_insightvm.assets, rapid7_insightvm.findings, rapid7_insightvm.vulnerabilities |
| `raygun` | Raygun source | raygun.audit_events, raygun.deployments, raygun.projects, raygun.repositories, raygun.users |
| `readme` | Readme source | readme.audit_events, readme.deployments, readme.projects, readme.repositories, readme.users |
| `rebilly` | Rebilly source | rebilly.aml, rebilly.authentication_token, rebilly.bank_account, rebilly.customer_timeline_custom_event |
| `recharge` | Recharge source | recharge.accounts, recharge.audit_events, recharge.policies, recharge.records, recharge.users |
| `reco_security` | Reco Security source | reco_security.assets, reco_security.audit_events, reco_security.findings, reco_security.policies, reco_security.vulnerabilities |
| `recorded_future` | Recorded Future source | recorded_future.assets, recorded_future.findings, recorded_future.vulnerabilities |
| `recurly` | Recurly source | recurly.accounts, recurly.audit_events, recurly.policies, recurly.records, recurly.users |
| `red_canary` | Red Canary source | red_canary.assets, red_canary.audit_events, red_canary.findings, red_canary.policies, red_canary.vulnerabilities |
| `redhat` | Redhat source | redhat.advisory, redhat.package, redhat.systems_advisory, redhat.v1_package |
| `redirection_io` | Redirection Io source | redirection_io.agent_rule, redirection_io.agent_rule_complexe, redirection_io.agent_rule_straight, redirection_io.aggregate_log, redirection_io.export_rule, redirection_io.log, redirection_io.notification, redirection_io.rule, redirection_io.rule_change, redirection_io.rule_set_version, redirection_io.smart_list, redirection_io.user |
| `relativity_one` | Relativity One source | relativity_one.accounts, relativity_one.audit_events, relativity_one.policies, relativity_one.records, relativity_one.users |
| `remote_com` | Remote Com source | remote_com.accounts, remote_com.audit_events, remote_com.policies, remote_com.records, remote_com.users |
| `render_cloud` | Render Cloud source | render_cloud.audit_events, render_cloud.deployments, render_cloud.projects, render_cloud.repositories, render_cloud.users |
| `replicate` | Replicate source | replicate.collections, replicate.deployments, replicate.models, replicate.predictions |
| `replicated` | Replicated source | replicated.audit_events, replicated.deployments, replicated.projects, replicated.repositories, replicated.users |
| `resend` | Resend source | resend.api_keys, resend.audit_events, resend.domains |
| `retool` | Retool source | retool.audit_events, retool.deployments, retool.projects, retool.repositories, retool.users |
| `revenuecat` | Revenuecat source | revenuecat.accounts, revenuecat.audit_events, revenuecat.policies, revenuecat.records, revenuecat.users |
| `ringcentral` | Ringcentral source | ringcentral.audit_events, ringcentral.documents, ringcentral.groups, ringcentral.users, ringcentral.workspaces |
| `rippling` | Rippling source | rippling.background_checks, rippling.devices, rippling.users |
| `riskiq` | Riskiq source | riskiq.assets, riskiq.audit_events, riskiq.findings, riskiq.policies, riskiq.vulnerabilities |
| `riskonnect` | Riskonnect source | riskonnect.assets, riskonnect.audit_events, riskonnect.findings, riskonnect.policies, riskonnect.vulnerabilities |
| `rivery` | Rivery source | rivery.accounts, rivery.audit_events, rivery.policies, rivery.records, rivery.users |
| `robin` | Robin source | robin.audit_events, robin.documents, robin.groups, robin.users, robin.workspaces |
| `rollbar` | Rollbar source | rollbar.alerts, rollbar.audit_events, rollbar.dashboards, rollbar.incidents, rollbar.monitors |
| `rootly` | Rootly source | rootly.alerts, rootly.audit_events, rootly.dashboards, rootly.incidents, rootly.monitors |
| `rudderstack` | Rudderstack source | rudderstack.accounts, rudderstack.audit_events, rudderstack.policies, rudderstack.records, rudderstack.users |
| `runscope` | Runscope source | runscope.agent, runscope.bucket, runscope.buckets_test, runscope.environment, runscope.integration, runscope.metric, runscope.people, runscope.test |
| `runzero` | Runzero source | runzero.assets, runzero.audit_events, runzero.findings, runzero.policies, runzero.vulnerabilities |
| `safe_base` | Safe Base source | safe_base.assets, safe_base.audit_events, safe_base.findings, safe_base.policies, safe_base.vulnerabilities |
| `sage_intacct` | Sage Intacct source | sage_intacct.accounts, sage_intacct.audit_events, sage_intacct.policies, sage_intacct.records, sage_intacct.users |
| `sailpoint_identitynow` | SailPoint Identity Security Cloud source | sailpoint_identitynow.access_profile_entitlements, sailpoint_identitynow.access_profiles, sailpoint_identitynow.access_request_status, sailpoint_identitynow.account_activities, sailpoint_identitynow.account_entitlements, sailpoint_identitynow.accounts, sailpoint_identitynow.campaigns, sailpoint_identitynow.certification_access_review_items, sailpoint_identitynow.certifications, sailpoint_identitynow.entitlements, sailpoint_identitynow.identities, sailpoint_identitynow.identity_entitlements, sailpoint_identitynow.identity_profiles, sailpoint_identitynow.identity_role_assignments, sailpoint_identitynow.lifecycle_states, sailpoint_identitynow.personal_access_tokens, sailpoint_identitynow.role_assigned_identities, sailpoint_identitynow.role_dimensions, sailpoint_identitynow.role_entitlements, sailpoint_identitynow.roles, sailpoint_identitynow.segments, sailpoint_identitynow.source_health, sailpoint_identitynow.source_provisioning_policies, sailpoint_identitynow.source_schedules, sailpoint_identitynow.source_schemas, sailpoint_identitynow.sources, sailpoint_identitynow.workgroup_members, sailpoint_identitynow.workgroups |
| `sakari` | Sakari source | sakari.campaign, sakari.contact, sakari.conversation, sakari.webhook |
| `salesforce` | Salesforce source | salesforce.assets, salesforce.audit_events, salesforce.users |
| `salesforce_cpq` | Salesforce Cpq source | salesforce_cpq.accounts, salesforce_cpq.audit_events, salesforce_cpq.policies, salesforce_cpq.records, salesforce_cpq.users |
| `saleshood` | Saleshood source | saleshood.accounts, saleshood.audit_events, saleshood.policies, saleshood.records, saleshood.users |
| `salesloft` | Salesloft source | salesloft.account_stages_json, salesloft.cadence_memberships_json, salesloft.crm_activity_fields_json, salesloft.groups_json |
| `salt_security` | Salt Security source | salt_security.assets, salt_security.audit_events, salt_security.findings, salt_security.policies, salt_security.vulnerabilities |
| `sauce_labs` | Sauce Labs source | sauce_labs.audit_events, sauce_labs.deployments, sauce_labs.projects, sauce_labs.repositories, sauce_labs.users |
| `saviynt` | Saviynt source | saviynt.applications, saviynt.audit_events, saviynt.groups, saviynt.roles, saviynt.users |
| `scalefusion` | Scalefusion source | scalefusion.applications, scalefusion.audit_events, scalefusion.groups, scalefusion.roles, scalefusion.users |
| `scalr` | Scalr source | scalr.audit_events, scalr.deployments, scalr.projects, scalr.repositories, scalr.users |
| `sdk` | Generic SDK push source for onboarded applications | validates pushed integration config; optional declared inventory URN discovery; preview reads are empty |
| `secureframe` | Secureframe source | secureframe.controls, secureframe.findings, secureframe.users |
| `securiti` | Securiti source | securiti.assets, securiti.audit_events, securiti.findings, securiti.policies, securiti.vulnerabilities |
| `securityscorecard` | Securityscorecard source | securityscorecard.assets, securityscorecard.audit_events, securityscorecard.findings, securityscorecard.policies, securityscorecard.vulnerabilities |
| `securonix` | Securonix source | securonix.assets, securonix.audit_events, securonix.findings, securonix.policies, securonix.vulnerabilities |
| `segment` | Segment source | segment.sources, segment.users, segment.workspaces |
| `seismic` | Seismic source | seismic.accounts, seismic.audit_events, seismic.policies, seismic.records, seismic.users |
| `semaphore_ci` | Semaphore Ci source | semaphore_ci.audit_events, semaphore_ci.deployments, semaphore_ci.projects, semaphore_ci.repositories, semaphore_ci.users |
| `semgrep` | Semgrep source | semgrep.assets, semgrep.audit_events, semgrep.findings, semgrep.policies, semgrep.vulnerabilities |
| `sendgrid` | Sendgrid source | sendgrid.activity, sendgrid.api_key, sendgrid.group, sendgrid.invalid_email |
| `sendoso` | Sendoso source | sendoso.accounts, sendoso.audit_events, sendoso.policies, sendoso.records, sendoso.users |
| `sentinelone` | SentinelOne endpoint posture and threat source | agents, threats, activities, applications, exclusions, groups, sites |
| `securitytoolingmap` | Security tooling inventory source | configured tooling-map families |
| `sentra` | Sentra source | sentra.assets, sentra.audit_events, sentra.findings, sentra.policies, sentra.vulnerabilities |
| `sentry` | Sentry source | sentry.assets, sentry.findings, sentry.vulnerabilities |
| `servicenow` | Servicenow source | servicenow.audit_events, servicenow.tickets, servicenow.users |
| `servicenow_grc` | Servicenow Grc source | servicenow_grc.assets, servicenow_grc.audit_events, servicenow_grc.findings, servicenow_grc.policies, servicenow_grc.vulnerabilities |
| `sevenrooms` | Sevenrooms source | sevenrooms.accounts, sevenrooms.audit_events, sevenrooms.policies, sevenrooms.records, sevenrooms.users |
| `sharefile` | Sharefile source | sharefile.audit_events, sharefile.documents, sharefile.groups, sharefile.users, sharefile.workspaces |
| `shipengine` | Shipengine source | shipengine.package, shipengine.track, shipengine.tracking, shipengine.webhook |
| `shorebird` | Shorebird source | shorebird.audit_events, shorebird.deployments, shorebird.projects, shorebird.repositories, shorebird.users |
| `shortcut` | Shortcut source | shortcut.audit_events, shortcut.deployments, shortcut.projects, shortcut.repositories, shortcut.users |
| `showpad` | Showpad source | showpad.accounts, showpad.audit_events, showpad.policies, showpad.records, showpad.users |
| `sigma_computing` | Sigma Computing source | sigma_computing.accounts, sigma_computing.audit_events, sigma_computing.policies, sigma_computing.records, sigma_computing.users |
| `signl4` | Signl4 source | signl4.image, signl4.membership, signl4.team, signl4.user |
| `silverfort` | Silverfort source | silverfort.applications, silverfort.audit_events, silverfort.groups, silverfort.roles, silverfort.users |
| `simplemdm` | Simplemdm source | simplemdm.applications, simplemdm.audit_events, simplemdm.groups, simplemdm.roles, simplemdm.users |
| `sinao` | Sinao source | sinao.access, sinao.account, sinao.accountcategory, sinao.accounting_entry, sinao.apps_organization, sinao.invite, sinao.organization, sinao.person, sinao.product, sinao.productcategory, sinao.productstock, sinao.rule |
| `sirionlabs` | Sirionlabs source | sirionlabs.accounts, sirionlabs.audit_events, sirionlabs.policies, sirionlabs.records, sirionlabs.users |
| `sisense` | Sisense source | sisense.accounts, sisense.audit_events, sisense.policies, sisense.records, sisense.users |
| `sixsense` | Sixsense source | sixsense.accounts, sixsense.audit_events, sixsense.policies, sixsense.records, sixsense.users |
| `skedda` | Skedda source | skedda.audit_events, skedda.documents, skedda.groups, skedda.users, skedda.workspaces |
| `skillsoft_percipio` | Skillsoft Percipio source | skillsoft_percipio.accounts, skillsoft_percipio.audit_events, skillsoft_percipio.policies, skillsoft_percipio.records, skillsoft_percipio.users |
| `slab` | Slab source | slab.audit_events, slab.documents, slab.groups, slab.users, slab.workspaces |
| `slack` | Slack workspace, membership, and audit source | teams, users, channels, user groups, access logs, channel members, user group members, audit logs |
| `slideroom` | Slideroom source | slideroom.attributes_name, slideroom.export, slideroom.name |
| `slite` | Slite source | slite.audit_events, slite.documents, slite.groups, slite.users, slite.workspaces |
| `smartrecruiters` | Smartrecruiters source | smartrecruiters.accounts, smartrecruiters.audit_events, smartrecruiters.policies, smartrecruiters.records, smartrecruiters.users |
| `smartsheet` | Smartsheet source | smartsheet.audit_events, smartsheet.documents, smartsheet.groups, smartsheet.users, smartsheet.workspaces |
| `smartsuite` | Smartsuite source | smartsuite.accounts, smartsuite.audit_events, smartsuite.policies, smartsuite.records, smartsuite.users |
| `snowflake` | Snowflake source | snowflake.assets, snowflake.audit_events, snowflake.cortex_search_services, snowflake.vulnerabilities |
| `snyk` | Snyk source | snyk.orgs, snyk.groups, snyk.projects, snyk.targets, snyk.assets, snyk.findings, snyk.vulnerabilities, snyk.org_memberships, snyk.service_accounts, snyk.audit_logs, snyk.collections, snyk.cloud_environments, snyk.cloud_resources, snyk.cloud_scans, snyk.group_memberships, snyk.group_service_accounts, snyk.group_audit_logs, snyk.asset_project_relationships, snyk.asset_target_relationships |
| `soda_cloud` | Soda Cloud source | soda_cloud.accounts, soda_cloud.audit_events, soda_cloud.policies, soda_cloud.records, soda_cloud.users |
| `sonarcloud` | Sonarcloud source | sonarcloud.assets, sonarcloud.findings, sonarcloud.vulnerabilities |
| `sonatype_lifecycle` | Sonatype Lifecycle source | sonatype_lifecycle.assets, sonatype_lifecycle.audit_events, sonatype_lifecycle.findings, sonatype_lifecycle.policies, sonatype_lifecycle.vulnerabilities |
| `sonrai_security` | Sonrai Security source | sonrai_security.applications, sonrai_security.audit_events, sonrai_security.groups, sonrai_security.roles, sonrai_security.users |
| `sophos_central` | Sophos Central source | sophos_central.assets, sophos_central.audit_events, sophos_central.findings, sophos_central.policies, sophos_central.vulnerabilities |
| `soti_mobicontrol` | Soti Mobicontrol source | soti_mobicontrol.applications, soti_mobicontrol.audit_events, soti_mobicontrol.groups, soti_mobicontrol.roles, soti_mobicontrol.users |
| `sourcegraph` | Sourcegraph source | sourcegraph.audit_events, sourcegraph.deployments, sourcegraph.projects, sourcegraph.repositories, sourcegraph.users |
| `sourcewhale` | Sourcewhale source | sourcewhale.accounts, sourcewhale.audit_events, sourcewhale.policies, sourcewhale.records, sourcewhale.users |
| `spacelift` | Spacelift source | spacelift.audit_events, spacelift.deployments, spacelift.projects, spacelift.repositories, spacelift.users |
| `spendesk` | Spendesk source | spendesk.accounts, spendesk.audit_events, spendesk.policies, spendesk.records, spendesk.users |
| `split_io` | Split Io source | split_io.audit_events, split_io.deployments, split_io.projects, split_io.repositories, split_io.users |
| `splunk_cloud` | Splunk Cloud source | splunk_cloud.assets, splunk_cloud.audit_events, splunk_cloud.findings |
| `splunk_observability` | Splunk Observability source | splunk_observability.alerts, splunk_observability.audit_events, splunk_observability.dashboards, splunk_observability.incidents, splunk_observability.monitors |
| `springhealth` | Springhealth source | springhealth.accounts, springhealth.audit_events, springhealth.policies, springhealth.records, springhealth.users |
| `sprinklr` | Sprinklr source | sprinklr.accounts, sprinklr.audit_events, sprinklr.policies, sprinklr.records, sprinklr.users |
| `sprinto` | Sprinto source | sprinto.assets, sprinto.audit_events, sprinto.findings, sprinto.policies, sprinto.vulnerabilities |
| `sprout_social` | Sprout Social source | sprout_social.audit_events, sprout_social.documents, sprout_social.groups, sprout_social.users, sprout_social.workspaces |
| `squadcast` | Squadcast source | squadcast.alerts, squadcast.audit_events, squadcast.dashboards, squadcast.incidents, squadcast.monitors |
| `square` | Square source | square.activity, square.bank_account, square.group, square.team_member_booking_profile |
| `stability_ai` | Stability Ai source | stability_ai.account, stability_ai.account_balance, stability_ai.engines |
| `stackblitz` | Stackblitz source | stackblitz.audit_events, stackblitz.deployments, stackblitz.projects, stackblitz.repositories, stackblitz.users |
| `stackhawk` | Stackhawk source | stackhawk.assets, stackhawk.audit_events, stackhawk.findings, stackhawk.policies, stackhawk.vulnerabilities |
| `statsig` | Statsig source | statsig.audit_events, statsig.deployments, statsig.projects, statsig.repositories, statsig.users |
| `statuscake` | Statuscake source | statuscake.alerts, statuscake.audit_events, statuscake.dashboards, statuscake.incidents, statuscake.monitors |
| `statuspage` | Statuspage source | statuspage.audit_events, statuspage.tickets, statuspage.users |
| `stigg` | Stigg source | stigg.alerts, stigg.audit_events, stigg.dashboards, stigg.incidents, stigg.monitors |
| `stitch` | Stitch source | stitch.accounts, stitch.audit_events, stitch.policies, stitch.records, stitch.users |
| `stoplight` | Stoplight source | stoplight.audit_events, stoplight.deployments, stoplight.projects, stoplight.repositories, stoplight.users |
| `stream_io_api` | Stream Io Api source | stream_io_api.device, stream_io_api.member, stream_io_api.query_banned_user, stream_io_api.role |
| `stripe` | Stripe source | stripe.assets, stripe.audit_events, stripe.users |
| `strongdm` | Strongdm source | strongdm.audit_events, strongdm.groups, strongdm.users |
| `stytch` | Stytch source | stytch.applications, stytch.audit_events, stytch.groups, stytch.roles, stytch.users |
| `successfactors` | Successfactors source | successfactors.accounts, successfactors.audit_events, successfactors.policies, successfactors.records, successfactors.users |
| `sumo_logic` | Sumo Logic source | sumo_logic.assets, sumo_logic.audit_events, sumo_logic.findings |
| `surveymonkey` | Surveymonkey source | surveymonkey.accounts, surveymonkey.audit_events, surveymonkey.policies, surveymonkey.records, surveymonkey.users |
| `svix` | Svix source | svix.endpoint, svix.event_type, svix.msg, svix.msg_endpoint |
| `swaggerhub` | Swaggerhub source | swaggerhub.audit_events, swaggerhub.deployments, swaggerhub.projects, swaggerhub.repositories, swaggerhub.users |
| `swif_ai` | Swif Ai source | swif_ai.device_compliance, swif_ai.devices, swif_ai.users |
| `synack` | Synack source | synack.assets, synack.audit_events, synack.findings, synack.policies, synack.vulnerabilities |
| `sync_com` | Sync Com source | sync_com.audit_events, sync_com.documents, sync_com.groups, sync_com.users, sync_com.workspaces |
| `sysdig_secure` | Sysdig Secure source | sysdig_secure.assets, sysdig_secure.findings, sysdig_secure.vulnerabilities |
| `tableau_cloud` | Tableau Cloud source | tableau_cloud.accounts, tableau_cloud.audit_events, tableau_cloud.policies, tableau_cloud.records, tableau_cloud.users |
| `tailscale` | Tailscale network source | tailnets, users, devices, groups, tags, services, grants |
| `talkdesk` | Talkdesk source | talkdesk.audit_events, talkdesk.documents, talkdesk.groups, talkdesk.users, talkdesk.workspaces |
| `tallyfy` | Tallyfy source | tallyfy.accounts, tallyfy.audit_events, tallyfy.policies, tallyfy.records, tallyfy.users |
| `tanium_cloud` | Tanium Cloud source | tanium_cloud.assets, tanium_cloud.audit_events, tanium_cloud.findings, tanium_cloud.policies, tanium_cloud.vulnerabilities |
| `taxamo` | Taxamo source | taxamo.payment, taxamo.refund, taxamo.transaction, taxamo.vy |
| `teamcity_cloud` | Teamcity Cloud source | teamcity_cloud.audit_events, teamcity_cloud.deployments, teamcity_cloud.projects, teamcity_cloud.repositories, teamcity_cloud.users |
| `teampay` | Teampay source | teampay.accounts, teampay.audit_events, teampay.policies, teampay.records, teampay.users |
| `teamwork` | Teamwork source | teamwork.audit_events, teamwork.documents, teamwork.groups, teamwork.users, teamwork.workspaces |
| `teamwork_projects` | Teamwork Projects source | teamwork_projects.audit_events, teamwork_projects.documents, teamwork_projects.groups, teamwork_projects.users, teamwork_projects.workspaces |
| `telemetryhub` | Telemetryhub source | telemetryhub.alerts, telemetryhub.audit_events, telemetryhub.dashboards, telemetryhub.incidents, telemetryhub.monitors |
| `teleport` | Teleport source | teleport.audit_events, teleport.groups, teleport.users |
| `telnyx` | Telnyx source | telnyx.billing_group, telnyx.call_control_application, telnyx.call_event, telnyx.credential_connection, telnyx.detail_records_report, telnyx.managed_account, telnyx.notification_channel, telnyx.notification_event, telnyx.notification_event_condition, telnyx.sim_card_group, telnyx.sim_card_group_action, telnyx.wireless_connectivity_log |
| `tenable_io` | Tenable Io source | tenable_io.assets, tenable_io.findings, tenable_io.vulnerabilities |
| `terraform_cloud` | Terraform Cloud source | terraform_cloud.audit_events, terraform_cloud.repositories, terraform_cloud.users |
| `testim` | Testim source | testim.audit_events, testim.deployments, testim.projects, testim.repositories, testim.users |
| `tettra` | Tettra source | tettra.audit_events, tettra.documents, tettra.groups, tettra.users, tettra.workspaces |
| `thoropass` | Thoropass source | thoropass.assets, thoropass.audit_events, thoropass.findings, thoropass.policies, thoropass.vulnerabilities |
| `thoughtspot` | Thoughtspot source | thoughtspot.accounts, thoughtspot.audit_events, thoughtspot.policies, thoughtspot.records, thoughtspot.users |
| `thousandeyes` | Thousandeyes source | thousandeyes.alerts, thousandeyes.audit_events, thousandeyes.dashboards, thousandeyes.incidents, thousandeyes.monitors |
| `threatjammer` | Threatjammer source | threatjammer.activity, threatjammer.all, threatjammer.ip, threatjammer.reported_ip |
| `three_sixty_learning` | Three Sixty Learning source | three_sixty_learning.accounts, three_sixty_learning.audit_events, three_sixty_learning.policies, three_sixty_learning.records, three_sixty_learning.users |
| `tines` | Tines source | tines.assets, tines.audit_events, tines.findings |
| `together_ai` | Together Ai source | together_ai.api_keys, together_ai.fine_tuning_jobs, together_ai.projects, together_ai.usage_reports |
| `torii` | Torii source | torii.applications, torii.audit_events, torii.groups, torii.roles, torii.users |
| `torq` | Torq source | torq.assets, torq.audit_events, torq.findings |
| `traceable_ai` | Traceable Ai source | traceable_ai.assets, traceable_ai.audit_events, traceable_ai.findings, traceable_ai.policies, traceable_ai.vulnerabilities |
| `travis_ci` | Travis Ci source | travis_ci.audit_events, travis_ci.deployments, travis_ci.projects, travis_ci.repositories, travis_ci.users |
| `tray_io` | Tray Io source | tray_io.audit_events, tray_io.deployments, tray_io.projects, tray_io.repositories, tray_io.users |
| `trello` | Trello source | trello.audit_events, trello.documents, trello.groups, trello.users, trello.workspaces |
| `tresorit` | Tresorit source | tresorit.audit_events, tresorit.documents, tresorit.groups, tresorit.users, tresorit.workspaces |
| `trivy` | Trivy report source | image scans, image packages, image vulnerabilities, fixes |
| `trufflehog_enterprise` | Trufflehog Enterprise source | trufflehog_enterprise.assets, trufflehog_enterprise.audit_events, trufflehog_enterprise.findings, trufflehog_enterprise.policies, trufflehog_enterprise.vulnerabilities |
| `truora` | Truora source | truora.check, truora.config, truora.hook, truora.report |
| `trustarc` | Trustarc source | trustarc.assets, trustarc.audit_events, trustarc.findings, trustarc.policies, trustarc.vulnerabilities |
| `trustedendpoint` | Trusted Endpoint posture, AI trust, GRC evidence, and trust-gate source | metadata-only endpoint posture, AI risk, evidence, findings, and action outcomes |
| `trustpilot` | Trustpilot source | trustpilot.accounts, trustpilot.audit_events, trustpilot.policies, trustpilot.records, trustpilot.users |
| `tugboat_logic` | Tugboat Logic source | tugboat_logic.assets, tugboat_logic.audit_events, tugboat_logic.findings, tugboat_logic.policies, tugboat_logic.vulnerabilities |
| `twilio` | Twilio source | twilio.accounts, twilio.audit_events, twilio.keys |
| `twitter` | Twitter source | twitter.dm_event, twitter.job, twitter.list_membership, twitter.member |
| `tyk` | Tyk source | tyk.api, tyk.client, tyk.key |
| `typeform` | Typeform source | typeform.accounts, typeform.audit_events, typeform.policies, typeform.records, typeform.users |
| `typefully` | Typefully source | typefully.audit_events, typefully.documents, typefully.groups, typefully.users, typefully.workspaces |
| `udemy_business` | Udemy Business source | udemy_business.accounts, udemy_business.audit_events, udemy_business.policies, udemy_business.records, udemy_business.users |
| `ujet` | Ujet source | ujet.accounts, ujet.audit_events, ujet.policies, ujet.records, ujet.users |
| `ukg_pro` | Ukg Pro source | ukg_pro.accounts, ukg_pro.audit_events, ukg_pro.policies, ukg_pro.records, ukg_pro.users |
| `unleash_cloud` | Unleash Cloud source | unleash_cloud.audit_events, unleash_cloud.deployments, unleash_cloud.projects, unleash_cloud.repositories, unleash_cloud.users |
| `upguard` | Upguard source | upguard.assets, upguard.audit_events, upguard.findings, upguard.policies, upguard.vulnerabilities |
| `uptime_com` | Uptime Com source | uptime_com.alerts, uptime_com.audit_events, uptime_com.dashboards, uptime_com.incidents, uptime_com.monitors |
| `uptimerobot` | Uptimerobot source | uptimerobot.alert_contacts, uptimerobot.audit_events, uptimerobot.monitors |
| `uptrace` | Uptrace source | uptrace.alerts, uptrace.audit_events, uptrace.dashboards, uptrace.incidents, uptrace.monitors |
| `userpilot` | Userpilot source | userpilot.accounts, userpilot.audit_events, userpilot.policies, userpilot.records, userpilot.users |
| `uservoice` | Uservoice source | uservoice.audit_events, uservoice.documents, uservoice.groups, uservoice.users, uservoice.workspaces |
| `valence_security` | Valence Security source | valence_security.assets, valence_security.audit_events, valence_security.findings, valence_security.policies, valence_security.vulnerabilities |
| `vanta` | Vanta source | vanta.controls, vanta.findings, vanta.users |
| `varicent` | Varicent source | varicent.accounts, varicent.audit_events, varicent.policies, varicent.records, varicent.users |
| `velopayments` | Velopayments source | velopayments.delta, velopayments.paymentchannelrule, velopayments.sourceaccount, velopayments.webhook |
| `veracode` | Veracode source | veracode.assets, veracode.findings, veracode.vulnerabilities |
| `vercel` | Vercel source | vercel.audit_events, vercel.deployments, vercel.projects |
| `victoriametrics_cloud` | Victoriametrics Cloud source | victoriametrics_cloud.accounts, victoriametrics_cloud.audit_events, victoriametrics_cloud.policies, victoriametrics_cloud.records, victoriametrics_cloud.users |
| `victorops` | Victorops source | victorops.incident, victorops.log, victorops.team, victorops.user |
| `vidyard` | Vidyard source | vidyard.audit_events, vidyard.documents, vidyard.groups, vidyard.users, vidyard.workspaces |
| `virustotal` | Virustotal source | virustotal.assets, virustotal.findings, virustotal.vulnerabilities |
| `visiblethread` | Visiblethread source | visiblethread.document, visiblethread.document_2, visiblethread.webscan, visiblethread.weburl |
| `vitally` | Vitally source | vitally.accounts, vitally.audit_events, vitally.policies, vitally.records, vitally.users |
| `vulncheck` | Vulncheck source | vulncheck.assets, vulncheck.audit_events, vulncheck.findings, vulncheck.policies, vulncheck.vulnerabilities |
| `vulnview` | Vulnerability and attack-surface source | sites, scans, vulnerabilities, assets, DNS alerts |
| `webex` | Webex source | webex.audit_events, webex.documents, webex.groups, webex.users, webex.workspaces |
| `whatsapp` | Whatsapp source | whatsapp.group, whatsapp.group_2, whatsapp.invite, whatsapp.user |
| `whereby` | Whereby source | whereby.audit_events, whereby.documents, whereby.groups, whereby.users, whereby.workspaces |
| `whistic` | Whistic source | whistic.assets, whistic.audit_events, whistic.findings, whistic.policies, whistic.vulnerabilities |
| `wing_security` | Wing Security source | wing_security.assets, wing_security.audit_events, wing_security.findings, wing_security.policies, wing_security.vulnerabilities |
| `winsms` | Winsms source | winsms.incoming, winsms.optout, winsms.sms_incoming, winsms.subaccount |
| `wistia` | Wistia source | wistia.audit_events, wistia.documents, wistia.groups, wistia.users, wistia.workspaces |
| `wiz` | Wiz source | wiz.assets, wiz.findings, wiz.vulnerabilities |
| `workable` | Workable source | workable.accounts, workable.audit_events, workable.policies, workable.records, workable.users |
| `workato` | Workato source | workato.audit_events, workato.deployments, workato.projects, workato.repositories, workato.users |
| `workday` | Workday source | workday.audit_events, workday.groups, workday.users |
| `workfront` | Workfront source | workfront.audit_events, workfront.documents, workfront.groups, workfront.users, workfront.workspaces |
| `workos` | Workos source | workos.audit_events, workos.groups, workos.users |
| `workplace_from_meta` | Workplace From Meta source | workplace_from_meta.audit_events, workplace_from_meta.documents, workplace_from_meta.groups, workplace_from_meta.users, workplace_from_meta.workspaces |
| `wrike` | Wrike source | wrike.audit_events, wrike.documents, wrike.groups, wrike.users, wrike.workspaces |
| `writer` | Writer AI Studio source | models, Knowledge Graphs, files, no-code agents, application graph associations, async application jobs |
| `xai` | Xai source | xai.api_keys, xai.audit_logs, xai.model_access, xai.usage_reports |
| `xero` | Xero source | xero.accounts, xero.audit_events, xero.policies, xero.records, xero.users |
| `xmatters` | Xmatters source | xmatters.alerts, xmatters.audit_events, xmatters.dashboards, xmatters.incidents, xmatters.monitors |
| `xtrf_eu` | Xtrf Eu source | xtrf_eu.active, xtrf_eu.all, xtrf_eu.customer, xtrf_eu.customers_id, xtrf_eu.id, xtrf_eu.id_2, xtrf_eu.invoices_id, xtrf_eu.persons_id, xtrf_eu.projects_id, xtrf_eu.providers_id, xtrf_eu.quotes_id, xtrf_eu.user |
| `yardi_voyager` | Yardi Voyager source | yardi_voyager.accounts, yardi_voyager.audit_events, yardi_voyager.policies, yardi_voyager.records, yardi_voyager.users |
| `zapier_enterprise` | Zapier Enterprise source | zapier_enterprise.audit_events, zapier_enterprise.deployments, zapier_enterprise.projects, zapier_enterprise.repositories, zapier_enterprise.users |
| `zeet` | Zeet source | zeet.audit_events, zeet.deployments, zeet.projects, zeet.repositories, zeet.users |
| `zendesk` | Zendesk source | zendesk.audit_events, zendesk.tickets, zendesk.users |
| `zendesk_sell` | Zendesk Sell source | zendesk_sell.accounts, zendesk_sell.audit_events, zendesk_sell.policies, zendesk_sell.records, zendesk_sell.users |
| `zenefits` | Zenefits source | zenefits.accounts, zenefits.audit_events, zenefits.policies, zenefits.records, zenefits.users |
| `zerofox` | Zerofox source | zerofox.assets, zerofox.audit_events, zerofox.findings, zerofox.policies, zerofox.vulnerabilities |
| `zilla_security` | Zilla Security source | zilla_security.applications, zilla_security.audit_events, zilla_security.groups, zilla_security.roles, zilla_security.users |
| `ziphq` | Ziphq source | ziphq.accounts, ziphq.audit_events, ziphq.policies, ziphq.records, ziphq.users |
| `zoho_books` | Zoho Books source | zoho_books.accounts, zoho_books.audit_events, zoho_books.policies, zoho_books.records, zoho_books.users |
| `zoho_crm` | Zoho Crm source | zoho_crm.accounts, zoho_crm.audit_events, zoho_crm.policies, zoho_crm.records, zoho_crm.users |
| `zoho_mail` | Zoho Mail source | zoho_mail.audit_events, zoho_mail.documents, zoho_mail.groups, zoho_mail.users, zoho_mail.workspaces |
| `zoho_projects` | Zoho Projects source | zoho_projects.audit_events, zoho_projects.documents, zoho_projects.groups, zoho_projects.users, zoho_projects.workspaces |
| `zoho_sprints` | Zoho Sprints source | zoho_sprints.audit_events, zoho_sprints.documents, zoho_sprints.groups, zoho_sprints.users, zoho_sprints.workspaces |
| `zoho_workdrive` | Zoho Workdrive source | zoho_workdrive.audit_events, zoho_workdrive.documents, zoho_workdrive.groups, zoho_workdrive.users, zoho_workdrive.workspaces |
| `zoom` | Zoom source | zoom.audit_events, zoom.content_assets, zoom.users |
| `zoom_phone` | Zoom Phone source | zoom_phone.audit_events, zoom_phone.documents, zoom_phone.groups, zoom_phone.users, zoom_phone.workspaces |
| `zoominfo` | Zoominfo source | zoominfo.accounts, zoominfo.audit_events, zoominfo.policies, zoominfo.records, zoominfo.users |
| `zscaler_internet_access` | Zscaler Internet Access source | zscaler_internet_access.applications, zscaler_internet_access.audit_events, zscaler_internet_access.groups, zscaler_internet_access.roles, zscaler_internet_access.users |
| `zscaler_private_access` | Zscaler Private Access source | zscaler_private_access.applications, zscaler_private_access.audit_events, zscaler_private_access.groups, zscaler_private_access.roles, zscaler_private_access.users |
| `zuora` | Zuora source | zuora.account, zuora.accounting_code, zuora.accounting_period, zuora.callout, zuora.email, zuora.email_template, zuora.event_trigger, zuora.hostedpage, zuora.notification_definition, zuora.product, zuora.revenue_event, zuora.revenue_schedule |
| `zylo` | Zylo source | zylo.applications, zylo.audit_events, zylo.groups, zylo.roles, zylo.users |
