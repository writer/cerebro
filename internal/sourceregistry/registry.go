package sourceregistry

import (
	"context"
	"fmt"

	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcecdk"
	abnormalsecuritysource "github.com/writer/cerebro/sources/abnormal_security"
	abuseipdbsource "github.com/writer/cerebro/sources/abuseipdb"
	activecampaignsource "github.com/writer/cerebro/sources/activecampaign"
	activtraksource "github.com/writer/cerebro/sources/activtrak"
	acunetixsource "github.com/writer/cerebro/sources/acunetix"
	adasupportsource "github.com/writer/cerebro/sources/ada_support"
	addigysource "github.com/writer/cerebro/sources/addigy"
	adobeworkfrontsource "github.com/writer/cerebro/sources/adobe_workfront"
	adpworkforcenowsource "github.com/writer/cerebro/sources/adp_workforce_now"
	agiloftsource "github.com/writer/cerebro/sources/agiloft"
	ahasource "github.com/writer/cerebro/sources/aha"
	airbasesource "github.com/writer/cerebro/sources/airbase"
	airbrakesource "github.com/writer/cerebro/sources/airbrake"
	airbytecloudsource "github.com/writer/cerebro/sources/airbyte_cloud"
	aircallsource "github.com/writer/cerebro/sources/aircall"
	airfocussource "github.com/writer/cerebro/sources/airfocus"
	airtablesource "github.com/writer/cerebro/sources/airtable"
	akeneosource "github.com/writer/cerebro/sources/akeneo"
	akeylesssource "github.com/writer/cerebro/sources/akeyless"
	alationsource "github.com/writer/cerebro/sources/alation"
	alchemersource "github.com/writer/cerebro/sources/alchemer"
	alteryxsource "github.com/writer/cerebro/sources/alteryx"
	amplitudesource "github.com/writer/cerebro/sources/amplitude"
	anchoresource "github.com/writer/cerebro/sources/anchore"
	anecdotessource "github.com/writer/cerebro/sources/anecdotes"
	anomalithreatstreamsource "github.com/writer/cerebro/sources/anomali_threatstream"
	anomalosource "github.com/writer/cerebro/sources/anomalo"
	anthropicsource "github.com/writer/cerebro/sources/anthropic"
	apachesource "github.com/writer/cerebro/sources/apache"
	apactasource "github.com/writer/cerebro/sources/apacta"
	api2cartsource "github.com/writer/cerebro/sources/api2cart"
	apidecksource "github.com/writer/cerebro/sources/apideck"
	apigeesource "github.com/writer/cerebro/sources/apigee"
	apiirosource "github.com/writer/cerebro/sources/apiiro"
	apollosource "github.com/writer/cerebro/sources/apollo"
	appcirclesource "github.com/writer/cerebro/sources/appcircle"
	appdynamicssource "github.com/writer/cerebro/sources/appdynamics"
	appfoliosource "github.com/writer/cerebro/sources/appfolio"
	appgatesource "github.com/writer/cerebro/sources/appgate"
	applitoolssource "github.com/writer/cerebro/sources/applitools"
	appomnisource "github.com/writer/cerebro/sources/appomni"
	appveyorsource "github.com/writer/cerebro/sources/appveyor"
	appwritesource "github.com/writer/cerebro/sources/appwrite"
	aquasecuritysource "github.com/writer/cerebro/sources/aqua_security"
	archetypesource "github.com/writer/cerebro/sources/archetype"
	arcticwolfsource "github.com/writer/cerebro/sources/arctic_wolf"
	argocdsource "github.com/writer/cerebro/sources/argo_cd"
	armissource "github.com/writer/cerebro/sources/armis"
	armoplatformsource "github.com/writer/cerebro/sources/armo_platform"
	armorcodesource "github.com/writer/cerebro/sources/armorcode"
	arnicasecuritysource "github.com/writer/cerebro/sources/arnica_security"
	asanasource "github.com/writer/cerebro/sources/asana"
	ashbysource "github.com/writer/cerebro/sources/ashby"
	astrixsecuritysource "github.com/writer/cerebro/sources/astrix_security"
	atlansource "github.com/writer/cerebro/sources/atlan"
	attackiqsource "github.com/writer/cerebro/sources/attackiq"
	auditboardsource "github.com/writer/cerebro/sources/auditboard"
	aureliussource "github.com/writer/cerebro/sources/aurelius"
	auth0source "github.com/writer/cerebro/sources/auth0"
	authentikcloudsource "github.com/writer/cerebro/sources/authentik_cloud"
	autotasksource "github.com/writer/cerebro/sources/autotask"
	avaturesource "github.com/writer/cerebro/sources/avature"
	avazasource "github.com/writer/cerebro/sources/avaza"
	awssource "github.com/writer/cerebro/sources/aws"
	awsbedrocksource "github.com/writer/cerebro/sources/aws_bedrock"
	axiomsource "github.com/writer/cerebro/sources/axiom"
	axoniussource "github.com/writer/cerebro/sources/axonius"
	azuresource "github.com/writer/cerebro/sources/azure"
	azuredevopssource "github.com/writer/cerebro/sources/azure_devops"
	azureopenaisource "github.com/writer/cerebro/sources/azure_openai"
	backstagesource "github.com/writer/cerebro/sources/backstage"
	bamboohrsource "github.com/writer/cerebro/sources/bamboohr"
	basecampsource "github.com/writer/cerebro/sources/basecamp"
	baselimesource "github.com/writer/cerebro/sources/baselime"
	bazaarvoicesource "github.com/writer/cerebro/sources/bazaarvoice"
	beelinesource "github.com/writer/cerebro/sources/beeline"
	beezupsource "github.com/writer/cerebro/sources/beezup"
	betterstacksource "github.com/writer/cerebro/sources/better_stack"
	bettercloudsource "github.com/writer/cerebro/sources/bettercloud"
	beyondtrustsource "github.com/writer/cerebro/sources/beyondtrust"
	biapisource "github.com/writer/cerebro/sources/biapi"
	bigfixsource "github.com/writer/cerebro/sources/bigfix"
	bigidsource "github.com/writer/cerebro/sources/bigid"
	bigpandasource "github.com/writer/cerebro/sources/bigpanda"
	bigredcloudsource "github.com/writer/cerebro/sources/bigredcloud"
	billcomsource "github.com/writer/cerebro/sources/bill_com"
	billbeesource "github.com/writer/cerebro/sources/billbee"
	billingosource "github.com/writer/cerebro/sources/billingo"
	bitbucketcloudsource "github.com/writer/cerebro/sources/bitbucket_cloud"
	bitrisesource "github.com/writer/cerebro/sources/bitrise"
	bitsightsource "github.com/writer/cerebro/sources/bitsight"
	bitwardensource "github.com/writer/cerebro/sources/bitwarden"
	bitwardenenterprisesource "github.com/writer/cerebro/sources/bitwarden_enterprise"
	blackkitesource "github.com/writer/cerebro/sources/black_kite"
	blackducksource "github.com/writer/cerebro/sources/blackduck"
	bluejeanssource "github.com/writer/cerebro/sources/bluejeans"
	boomisource "github.com/writer/cerebro/sources/boomi"
	botifysource "github.com/writer/cerebro/sources/botify"
	boxsource "github.com/writer/cerebro/sources/box"
	braintreesource "github.com/writer/cerebro/sources/braintree"
	brazesource "github.com/writer/cerebro/sources/braze"
	brexsource "github.com/writer/cerebro/sources/brex"
	brightflagsource "github.com/writer/cerebro/sources/brightflag"
	brinqasource "github.com/writer/cerebro/sources/brinqa"
	britivesource "github.com/writer/cerebro/sources/britive"
	browserstacksource "github.com/writer/cerebro/sources/browserstack"
	buddycisource "github.com/writer/cerebro/sources/buddy_ci"
	bugcrowdsource "github.com/writer/cerebro/sources/bugcrowd"
	bugsnagsource "github.com/writer/cerebro/sources/bugsnag"
	buildkitesource "github.com/writer/cerebro/sources/buildkite"
	bulksmssource "github.com/writer/cerebro/sources/bulksms"
	bunqsource "github.com/writer/cerebro/sources/bunq"
	burpsuiteenterprisesource "github.com/writer/cerebro/sources/burp_suite_enterprise"
	calcomsource "github.com/writer/cerebro/sources/calcom"
	calendlysource "github.com/writer/cerebro/sources/calendly"
	callfiresource "github.com/writer/cerebro/sources/callfire"
	callrailsource "github.com/writer/cerebro/sources/callrail"
	campaignmonitorsource "github.com/writer/cerebro/sources/campaign_monitor"
	canvaenterprisesource "github.com/writer/cerebro/sources/canva_enterprise"
	carbonblackcloudsource "github.com/writer/cerebro/sources/carbon_black_cloud"
	caspiosource "github.com/writer/cerebro/sources/caspio"
	castaisource "github.com/writer/cerebro/sources/cast_ai"
	catalogruntimesource "github.com/writer/cerebro/sources/catalogruntime"
	catalystsource "github.com/writer/cerebro/sources/catalyst"
	catchpointsource "github.com/writer/cerebro/sources/catchpoint"
	catonetworkssource "github.com/writer/cerebro/sources/cato_networks"
	cenitsource "github.com/writer/cerebro/sources/cenit"
	censussource "github.com/writer/cerebro/sources/census"
	censysasmsource "github.com/writer/cerebro/sources/censys_asm"
	cerboscloudsource "github.com/writer/cerebro/sources/cerbos_cloud"
	cerbysource "github.com/writer/cerebro/sources/cerby"
	cerebrassource "github.com/writer/cerebro/sources/cerebras"
	cerebrosource "github.com/writer/cerebro/sources/cerebro"
	ceridiandayforcesource "github.com/writer/cerebro/sources/ceridian_dayforce"
	chargebeesource "github.com/writer/cerebro/sources/chargebee"
	chargifysource "github.com/writer/cerebro/sources/chargify"
	charthopsource "github.com/writer/cerebro/sources/charthop"
	checklysource "github.com/writer/cerebro/sources/checkly"
	checkmarxonesource "github.com/writer/cerebro/sources/checkmarx_one"
	checkoutcomsource "github.com/writer/cerebro/sources/checkout_com"
	checkrsource "github.com/writer/cerebro/sources/checkr"
	chilipipersource "github.com/writer/cerebro/sources/chili_piper"
	chorussource "github.com/writer/cerebro/sources/chorus"
	chronospheresource "github.com/writer/cerebro/sources/chronosphere"
	churnzerosource "github.com/writer/cerebro/sources/churnzero"
	circlecisource "github.com/writer/cerebro/sources/circleci"
	ciscoumbrellasource "github.com/writer/cerebro/sources/cisco_umbrella"
	clarisource "github.com/writer/cerebro/sources/clari"
	clarotysource "github.com/writer/cerebro/sources/claroty"
	clearbladesource "github.com/writer/cerebro/sources/clearblade"
	clevercloudsource "github.com/writer/cerebro/sources/clever_cloud"
	clickmetersource "github.com/writer/cerebro/sources/clickmeter"
	clicksendsource "github.com/writer/cerebro/sources/clicksend"
	clickupsource "github.com/writer/cerebro/sources/clickup"
	closecrmsource "github.com/writer/cerebro/sources/close_crm"
	cloudbeescisource "github.com/writer/cerebro/sources/cloudbees_ci"
	cloudflaresource "github.com/writer/cerebro/sources/cloudflare"
	cloudflareworkersaisource "github.com/writer/cerebro/sources/cloudflare_workers_ai"
	cloudflarezerotrustsource "github.com/writer/cerebro/sources/cloudflare_zero_trust"
	cloudsmithsource "github.com/writer/cerebro/sources/cloudsmith"
	cloudtalksource "github.com/writer/cerebro/sources/cloudtalk"
	coalescedatasource "github.com/writer/cerebro/sources/coalesce_data"
	cobaltsource "github.com/writer/cerebro/sources/cobalt"
	cockroachdbcloudsource "github.com/writer/cerebro/sources/cockroachdb_cloud"
	codasource "github.com/writer/cerebro/sources/coda"
	codacysource "github.com/writer/cerebro/sources/codacy"
	codecovsource "github.com/writer/cerebro/sources/codecov"
	codefreshsource "github.com/writer/cerebro/sources/codefresh"
	codemagicsource "github.com/writer/cerebro/sources/codemagic"
	codercloudsource "github.com/writer/cerebro/sources/coder_cloud"
	cofensesource "github.com/writer/cerebro/sources/cofense"
	coheresource "github.com/writer/cerebro/sources/cohere"
	collibrasource "github.com/writer/cerebro/sources/collibra"
	combellsource "github.com/writer/cerebro/sources/combell"
	concursource "github.com/writer/cerebro/sources/concur"
	configcatsource "github.com/writer/cerebro/sources/configcat"
	confluencesource "github.com/writer/cerebro/sources/confluence"
	congasource "github.com/writer/cerebro/sources/conga"
	conjursource "github.com/writer/cerebro/sources/conjur"
	contentfulsource "github.com/writer/cerebro/sources/contentful"
	contractbooksource "github.com/writer/cerebro/sources/contractbook"
	contrastsecuritysource "github.com/writer/cerebro/sources/contrast_security"
	coppercrmsource "github.com/writer/cerebro/sources/copper_crm"
	coralogixsource "github.com/writer/cerebro/sources/coralogix"
	cornerstoneondemandsource "github.com/writer/cerebro/sources/cornerstone_ondemand"
	cortexxdrsource "github.com/writer/cerebro/sources/cortex_xdr"
	cortexxsoarsource "github.com/writer/cerebro/sources/cortex_xsoar"
	cosmosource "github.com/writer/cerebro/sources/cosmo"
	coupasource "github.com/writer/cerebro/sources/coupa"
	crashlyticssource "github.com/writer/cerebro/sources/crashlytics"
	createlysource "github.com/writer/cerebro/sources/creately"
	criblcloudsource "github.com/writer/cerebro/sources/cribl_cloud"
	crowdstrikefalconsource "github.com/writer/cerebro/sources/crowdstrike_falcon"
	crowdstrikeidentitysource "github.com/writer/cerebro/sources/crowdstrike_identity"
	cultureampsource "github.com/writer/cerebro/sources/culture_amp"
	customeriosource "github.com/writer/cerebro/sources/customer_io"
	cyberarkidentitysource "github.com/writer/cerebro/sources/cyberark_identity"
	cyberarkpamsource "github.com/writer/cerebro/sources/cyberark_pam"
	cycodesource "github.com/writer/cerebro/sources/cycode"
	cyerasource "github.com/writer/cerebro/sources/cyera"
	cyolosource "github.com/writer/cerebro/sources/cyolo"
	dashlanebusinesssource "github.com/writer/cerebro/sources/dashlane_business"
	databrickssource "github.com/writer/cerebro/sources/databricks"
	datadogsource "github.com/writer/cerebro/sources/datadog"
	datafoldsource "github.com/writer/cerebro/sources/datafold"
	dbtcloudsource "github.com/writer/cerebro/sources/dbt_cloud"
	dealhubsource "github.com/writer/cerebro/sources/dealhub"
	deelsource "github.com/writer/cerebro/sources/deel"
	deepseeksource "github.com/writer/cerebro/sources/deepseek"
	defectdojocloudsource "github.com/writer/cerebro/sources/defectdojo_cloud"
	degreedsource "github.com/writer/cerebro/sources/degreed"
	delineasource "github.com/writer/cerebro/sources/delinea"
	demandbasesource "github.com/writer/cerebro/sources/demandbase"
	depotsource "github.com/writer/cerebro/sources/depot"
	descopesource "github.com/writer/cerebro/sources/descope"
	detectifysource "github.com/writer/cerebro/sources/detectify"
	devcyclesource "github.com/writer/cerebro/sources/devcycle"
	device42source "github.com/writer/cerebro/sources/device42"
	devtronsource "github.com/writer/cerebro/sources/devtron"
	dialpadsource "github.com/writer/cerebro/sources/dialpad"
	digsecuritysource "github.com/writer/cerebro/sources/dig_security"
	digitaloceansource "github.com/writer/cerebro/sources/digitalocean"
	discordsource "github.com/writer/cerebro/sources/discord"
	discoursesource "github.com/writer/cerebro/sources/discourse"
	divvysource "github.com/writer/cerebro/sources/divvy"
	dixasource "github.com/writer/cerebro/sources/dixa"
	docebosource "github.com/writer/cerebro/sources/docebo"
	dockerhubsource "github.com/writer/cerebro/sources/docker_hub"
	document360source "github.com/writer/cerebro/sources/document360"
	docusignsource "github.com/writer/cerebro/sources/docusign"
	domosource "github.com/writer/cerebro/sources/domo"
	dopplersource "github.com/writer/cerebro/sources/doppler"
	dracoonsource "github.com/writer/cerebro/sources/dracoon"
	dragosworldviewsource "github.com/writer/cerebro/sources/dragos_worldview"
	dratasource "github.com/writer/cerebro/sources/drata"
	drchronosource "github.com/writer/cerebro/sources/drchrono"
	driftsource "github.com/writer/cerebro/sources/drift"
	dronecloudsource "github.com/writer/cerebro/sources/drone_cloud"
	dropboxbusinesssource "github.com/writer/cerebro/sources/dropbox_business"
	dropboxsignsource "github.com/writer/cerebro/sources/dropbox_sign"
	duosource "github.com/writer/cerebro/sources/duo"
	duosecuritysource "github.com/writer/cerebro/sources/duo_security"
	dynamics365salessource "github.com/writer/cerebro/sources/dynamics_365_sales"
	dynatracesource "github.com/writer/cerebro/sources/dynatrace"
	easyllamasource "github.com/writer/cerebro/sources/easyllama"
	eclypsiumsource "github.com/writer/cerebro/sources/eclypsium"
	egnytesource "github.com/writer/cerebro/sources/egnyte"
	elasticcloudsource "github.com/writer/cerebro/sources/elastic_cloud"
	elasticsecuritysource "github.com/writer/cerebro/sources/elastic_security"
	elevenlabssource "github.com/writer/cerebro/sources/elevenlabs"
	elmahsource "github.com/writer/cerebro/sources/elmah"
	emaildomainhealthsource "github.com/writer/cerebro/sources/emaildomainhealth"
	endorlabssource "github.com/writer/cerebro/sources/endor_labs"
	env0source "github.com/writer/cerebro/sources/env0"
	envkeysource "github.com/writer/cerebro/sources/envkey"
	envoysource "github.com/writer/cerebro/sources/envoy"
	envoyvisitorssource "github.com/writer/cerebro/sources/envoy_visitors"
	ethenasource "github.com/writer/cerebro/sources/ethena"
	everlawsource "github.com/writer/cerebro/sources/everlaw"
	evernoteteamssource "github.com/writer/cerebro/sources/evernote_teams"
	evidencecassource "github.com/writer/cerebro/sources/evidencecas"
	evisortsource "github.com/writer/cerebro/sources/evisort"
	exavaultsource "github.com/writer/cerebro/sources/exavault"
	expelsource "github.com/writer/cerebro/sources/expel"
	expensifysource "github.com/writer/cerebro/sources/expensify"
	fairmarkitsource "github.com/writer/cerebro/sources/fairmarkit"
	farosaisource "github.com/writer/cerebro/sources/faros_ai"
	fastlysource "github.com/writer/cerebro/sources/fastly"
	fathomvideosource "github.com/writer/cerebro/sources/fathom_video"
	featurebasesource "github.com/writer/cerebro/sources/featurebase"
	fifteenfivesource "github.com/writer/cerebro/sources/fifteenfive"
	figmasource "github.com/writer/cerebro/sources/figma"
	filescomsource "github.com/writer/cerebro/sources/files_com"
	firesource "github.com/writer/cerebro/sources/fire"
	firefliesaisource "github.com/writer/cerebro/sources/fireflies_ai"
	fireflysource "github.com/writer/cerebro/sources/firefly"
	firehydrantsource "github.com/writer/cerebro/sources/firehydrant"
	fireworksaisource "github.com/writer/cerebro/sources/fireworks_ai"
	firmalyzersource "github.com/writer/cerebro/sources/firmalyzer"
	five9source "github.com/writer/cerebro/sources/five9"
	fivetransource "github.com/writer/cerebro/sources/fivetran"
	flagsmithcloudsource "github.com/writer/cerebro/sources/flagsmith_cloud"
	fleetdmsource "github.com/writer/cerebro/sources/fleetdm"
	forethoughtsource "github.com/writer/cerebro/sources/forethought"
	formstacksource "github.com/writer/cerebro/sources/formstack"
	foxpasssource "github.com/writer/cerebro/sources/foxpass"
	freshbookssource "github.com/writer/cerebro/sources/freshbooks"
	freshdesksource "github.com/writer/cerebro/sources/freshdesk"
	freshsalessource "github.com/writer/cerebro/sources/freshsales"
	freshservicesource "github.com/writer/cerebro/sources/freshservice"
	frontsource "github.com/writer/cerebro/sources/front"
	fronteggsource "github.com/writer/cerebro/sources/frontegg"
	frontifysource "github.com/writer/cerebro/sources/frontify"
	fulfillmentcomsource "github.com/writer/cerebro/sources/fulfillment_com"
	fullstorysource "github.com/writer/cerebro/sources/fullstory"
	fusionauthsource "github.com/writer/cerebro/sources/fusionauth"
	gainsightsource "github.com/writer/cerebro/sources/gainsight"
	gcpsource "github.com/writer/cerebro/sources/gcp"
	gemsource "github.com/writer/cerebro/sources/gem"
	genesyscloudsource "github.com/writer/cerebro/sources/genesys_cloud"
	gitbooksource "github.com/writer/cerebro/sources/gitbook"
	giteasource "github.com/writer/cerebro/sources/gitea"
	gitguardiansource "github.com/writer/cerebro/sources/gitguardian"
	gitguardiansecretssource "github.com/writer/cerebro/sources/gitguardian_secrets"
	githubsource "github.com/writer/cerebro/sources/github"
	gitlabsource "github.com/writer/cerebro/sources/gitlab"
	gitpodsource "github.com/writer/cerebro/sources/gitpod"
	gladlysource "github.com/writer/cerebro/sources/gladly"
	gocdsource "github.com/writer/cerebro/sources/gocd"
	godaddysource "github.com/writer/cerebro/sources/godaddy"
	gongsource "github.com/writer/cerebro/sources/gong"
	googleanalytics360source "github.com/writer/cerebro/sources/google_analytics_360"
	googledrivesource "github.com/writer/cerebro/sources/google_drive"
	googlegeminisource "github.com/writer/cerebro/sources/google_gemini"
	googleplayconsolesource "github.com/writer/cerebro/sources/google_play_console"
	googlesecopschroniclesource "github.com/writer/cerebro/sources/google_secops_chronicle"
	googlevertexaisource "github.com/writer/cerebro/sources/google_vertex_ai"
	googleworkspacesource "github.com/writer/cerebro/sources/googleworkspace"
	gorgiassource "github.com/writer/cerebro/sources/gorgias"
	grafanacloudsource "github.com/writer/cerebro/sources/grafana_cloud"
	grainsource "github.com/writer/cerebro/sources/grain"
	grammarlybusinesssource "github.com/writer/cerebro/sources/grammarly_business"
	graviteecloudsource "github.com/writer/cerebro/sources/gravitee_cloud"
	grcsource "github.com/writer/cerebro/sources/grc"
	greenhousesource "github.com/writer/cerebro/sources/greenhouse"
	greythrsource "github.com/writer/cerebro/sources/greythr"
	gripsecuritysource "github.com/writer/cerebro/sources/grip_security"
	groqsource "github.com/writer/cerebro/sources/groq"
	groundcoversource "github.com/writer/cerebro/sources/groundcover"
	gsmtaskssource "github.com/writer/cerebro/sources/gsmtasks"
	gurusource "github.com/writer/cerebro/sources/guru"
	gustosource "github.com/writer/cerebro/sources/gusto"
	hackeronesource "github.com/writer/cerebro/sources/hackerone"
	hadriansecuritysource "github.com/writer/cerebro/sources/hadrian_security"
	harnesssource "github.com/writer/cerebro/sources/harness"
	harnessplatformsource "github.com/writer/cerebro/sources/harness_platform"
	hashicorpvaultsource "github.com/writer/cerebro/sources/hashicorp_vault"
	haveibeenpwnedsource "github.com/writer/cerebro/sources/haveibeenpwned"
	healthcheckssource "github.com/writer/cerebro/sources/healthchecks"
	heapsource "github.com/writer/cerebro/sources/heap"
	helpscoutsource "github.com/writer/cerebro/sources/helpscout"
	herokusource "github.com/writer/cerebro/sources/heroku"
	hetznersource "github.com/writer/cerebro/sources/hetzner"
	hevodatasource "github.com/writer/cerebro/sources/hevo_data"
	hexnodesource "github.com/writer/cerebro/sources/hexnode"
	hibobsource "github.com/writer/cerebro/sources/hibob"
	hidworkforceidentitysource "github.com/writer/cerebro/sources/hid_workforce_identity"
	highlightsource "github.com/writer/cerebro/sources/highlight"
	highspotsource "github.com/writer/cerebro/sources/highspot"
	hightailsource "github.com/writer/cerebro/sources/hightail"
	hightouchsource "github.com/writer/cerebro/sources/hightouch"
	hitrustmycsfsource "github.com/writer/cerebro/sources/hitrust_mycsf"
	hivesource "github.com/writer/cerebro/sources/hive"
	holmsecuritysource "github.com/writer/cerebro/sources/holm_security"
	honeybadgersource "github.com/writer/cerebro/sources/honeybadger"
	honeycombsource "github.com/writer/cerebro/sources/honeycomb"
	hotjarsource "github.com/writer/cerebro/sources/hotjar"
	hubspotsource "github.com/writer/cerebro/sources/hubspot"
	hudsonrocksource "github.com/writer/cerebro/sources/hudsonrock"
	huggingfacesource "github.com/writer/cerebro/sources/huggingface"
	huntrsource "github.com/writer/cerebro/sources/huntr"
	hyperdxsource "github.com/writer/cerebro/sources/hyperdx"
	hyperproofsource "github.com/writer/cerebro/sources/hyperproof"
	ibmrandorisource "github.com/writer/cerebro/sources/ibm_randori"
	ibmwatsonxaisource "github.com/writer/cerebro/sources/ibm_watsonx_ai"
	icertissource "github.com/writer/cerebro/sources/icertis"
	icimssource "github.com/writer/cerebro/sources/icims"
	ilertsource "github.com/writer/cerebro/sources/ilert"
	illumidesksource "github.com/writer/cerebro/sources/illumidesk"
	imanagecloudsource "github.com/writer/cerebro/sources/imanage_cloud"
	immutasource "github.com/writer/cerebro/sources/immuta"
	imprivatasource "github.com/writer/cerebro/sources/imprivata"
	incidentiosource "github.com/writer/cerebro/sources/incident_io"
	increasesource "github.com/writer/cerebro/sources/increase"
	infisicalsource "github.com/writer/cerebro/sources/infisical"
	influxdatasource "github.com/writer/cerebro/sources/influxdata"
	insomniacloudsource "github.com/writer/cerebro/sources/insomnia_cloud"
	intercomsource "github.com/writer/cerebro/sources/intercom"
	intrudersource "github.com/writer/cerebro/sources/intruder"
	invictisource "github.com/writer/cerebro/sources/invicti"
	iqualifysource "github.com/writer/cerebro/sources/iqualify"
	ironcladsource "github.com/writer/cerebro/sources/ironclad"
	islandsource "github.com/writer/cerebro/sources/island"
	iterablesource "github.com/writer/cerebro/sources/iterable"
	jamfprosource "github.com/writer/cerebro/sources/jamf_pro"
	jamfprotectsource "github.com/writer/cerebro/sources/jamf_protect"
	jenkinssource "github.com/writer/cerebro/sources/jenkins"
	jetbrainsspacesource "github.com/writer/cerebro/sources/jetbrains_space"
	jfrogartifactorysource "github.com/writer/cerebro/sources/jfrog_artifactory"
	jfrogartifactoryxraysource "github.com/writer/cerebro/sources/jfrog_artifactory_xray"
	jfrogxraysource "github.com/writer/cerebro/sources/jfrog_xray"
	jirasource "github.com/writer/cerebro/sources/jira"
	journyiosource "github.com/writer/cerebro/sources/journy_io"
	jumpcloudsource "github.com/writer/cerebro/sources/jumpcloud"
	jumpsellersource "github.com/writer/cerebro/sources/jumpseller"
	justworkssource "github.com/writer/cerebro/sources/justworks"
	k6cloudsource "github.com/writer/cerebro/sources/k6_cloud"
	kandjisource "github.com/writer/cerebro/sources/kandji"
	keepersource "github.com/writer/cerebro/sources/keeper"
	keepersecuritysource "github.com/writer/cerebro/sources/keeper_security"
	kennasecuritysource "github.com/writer/cerebro/sources/kenna_security"
	kentiksource "github.com/writer/cerebro/sources/kentik"
	keycloaksource "github.com/writer/cerebro/sources/keycloak"
	klaviyosource "github.com/writer/cerebro/sources/klaviyo"
	knowbe4source "github.com/writer/cerebro/sources/knowbe4"
	kolidesource "github.com/writer/cerebro/sources/kolide"
	kongkonnectsource "github.com/writer/cerebro/sources/kong_konnect"
	kubernetessource "github.com/writer/cerebro/sources/kubernetes"
	kustomersource "github.com/writer/cerebro/sources/kustomer"
	laceworksource "github.com/writer/cerebro/sources/lacework"
	lambdatestsource "github.com/writer/cerebro/sources/lambdatest"
	laminarsecuritysource "github.com/writer/cerebro/sources/laminar_security"
	langchainsource "github.com/writer/cerebro/sources/langchain"
	langfusesource "github.com/writer/cerebro/sources/langfuse"
	last9source "github.com/writer/cerebro/sources/last9"
	lastpassbusinesssource "github.com/writer/cerebro/sources/lastpass_business"
	latticesource "github.com/writer/cerebro/sources/lattice"
	launchdarklysource "github.com/writer/cerebro/sources/launchdarkly"
	leapsomesource "github.com/writer/cerebro/sources/leapsome"
	learnifiersource "github.com/writer/cerebro/sources/learnifier"
	legitsecuritysource "github.com/writer/cerebro/sources/legit_security"
	lessonlysource "github.com/writer/cerebro/sources/lessonly"
	leversource "github.com/writer/cerebro/sources/lever"
	lightstepsource "github.com/writer/cerebro/sources/lightstep"
	linearsource "github.com/writer/cerebro/sources/linear"
	linksquaressource "github.com/writer/cerebro/sources/linksquares"
	linodesource "github.com/writer/cerebro/sources/linode"
	livestormsource "github.com/writer/cerebro/sources/livestorm"
	logicgatesource "github.com/writer/cerebro/sources/logicgate"
	logicmonitorsource "github.com/writer/cerebro/sources/logicmonitor"
	logrocketsource "github.com/writer/cerebro/sources/logrocket"
	logziosource "github.com/writer/cerebro/sources/logz_io"
	loketsource "github.com/writer/cerebro/sources/loket"
	lookersource "github.com/writer/cerebro/sources/looker"
	loomsource "github.com/writer/cerebro/sources/loom"
	lucidchartsource "github.com/writer/cerebro/sources/lucidchart"
	lucidscalesource "github.com/writer/cerebro/sources/lucidscale"
	lumosidentitysource "github.com/writer/cerebro/sources/lumos_identity"
	mablsource "github.com/writer/cerebro/sources/mabl"
	magentosource "github.com/writer/cerebro/sources/magento"
	mailchimpsource "github.com/writer/cerebro/sources/mailchimp"
	mailscriptsource "github.com/writer/cerebro/sources/mailscript"
	manageengineendpointcentralsource "github.com/writer/cerebro/sources/manageengine_endpoint_central"
	mandiantadvantagesource "github.com/writer/cerebro/sources/mandiant_advantage"
	marketosource "github.com/writer/cerebro/sources/marketo"
	mastodonsource "github.com/writer/cerebro/sources/mastodon"
	materialsecuritysource "github.com/writer/cerebro/sources/material_security"
	matillionsource "github.com/writer/cerebro/sources/matillion"
	maxiosource "github.com/writer/cerebro/sources/maxio"
	meistertasksource "github.com/writer/cerebro/sources/meistertask"
	mendiosource "github.com/writer/cerebro/sources/mend_io"
	mentimetersource "github.com/writer/cerebro/sources/mentimeter"
	merakisource "github.com/writer/cerebro/sources/meraki"
	mercurysource "github.com/writer/cerebro/sources/mercury"
	meshpaymentssource "github.com/writer/cerebro/sources/mesh_payments"
	metaplanesource "github.com/writer/cerebro/sources/metaplane"
	mezmosource "github.com/writer/cerebro/sources/mezmo"
	microsoft365source "github.com/writer/cerebro/sources/microsoft_365"
	microsoftdefenderforcloudsource "github.com/writer/cerebro/sources/microsoft_defender_for_cloud"
	microsoftdefenderforcloudappssource "github.com/writer/cerebro/sources/microsoft_defender_for_cloud_apps"
	microsoftdefenderforendpointsource "github.com/writer/cerebro/sources/microsoft_defender_for_endpoint"
	microsoftentraidsource "github.com/writer/cerebro/sources/microsoft_entra_id"
	microsoftfoundrysource "github.com/writer/cerebro/sources/microsoft_foundry"
	microsoftsentinelsource "github.com/writer/cerebro/sources/microsoft_sentinel"
	microsoftteamssource "github.com/writer/cerebro/sources/microsoft_teams"
	mimecastsource "github.com/writer/cerebro/sources/mimecast"
	miradoresource "github.com/writer/cerebro/sources/miradore"
	mirosource "github.com/writer/cerebro/sources/miro"
	mistsource "github.com/writer/cerebro/sources/mist"
	mistralsource "github.com/writer/cerebro/sources/mistral"
	mobileironsource "github.com/writer/cerebro/sources/mobileiron"
	modeanalyticssource "github.com/writer/cerebro/sources/mode_analytics"
	mondaycomsource "github.com/writer/cerebro/sources/monday_com"
	mongodbatlassource "github.com/writer/cerebro/sources/mongodb_atlas"
	montecarlodatasource "github.com/writer/cerebro/sources/monte_carlo_data"
	moogsoftsource "github.com/writer/cerebro/sources/moogsoft"
	mosylesource "github.com/writer/cerebro/sources/mosyle"
	motawordsource "github.com/writer/cerebro/sources/motaword"
	mparticlesource "github.com/writer/cerebro/sources/mparticle"
	mulesoftanypointsource "github.com/writer/cerebro/sources/mulesoft_anypoint"
	multipliersource "github.com/writer/cerebro/sources/multiplier"
	muralsource "github.com/writer/cerebro/sources/mural"
	nauthsource "github.com/writer/cerebro/sources/n_auth"
	namelysource "github.com/writer/cerebro/sources/namely"
	navansource "github.com/writer/cerebro/sources/navan"
	netboxdemosource "github.com/writer/cerebro/sources/netboxdemo"
	netdocumentssource "github.com/writer/cerebro/sources/netdocuments"
	netlicensingsource "github.com/writer/cerebro/sources/netlicensing"
	netlifysource "github.com/writer/cerebro/sources/netlify"
	netskopesource "github.com/writer/cerebro/sources/netskope"
	netspiplatformsource "github.com/writer/cerebro/sources/netspi_platform"
	netsuitesource "github.com/writer/cerebro/sources/netsuite"
	neutrinoapisource "github.com/writer/cerebro/sources/neutrinoapi"
	newrelicsource "github.com/writer/cerebro/sources/new_relic"
	nicecxonesource "github.com/writer/cerebro/sources/nice_cxone"
	noeticcybersource "github.com/writer/cerebro/sources/noetic_cyber"
	nonamesecuritysource "github.com/writer/cerebro/sources/noname_security"
	nooshsource "github.com/writer/cerebro/sources/noosh"
	nordigensource "github.com/writer/cerebro/sources/nordigen"
	nordlayersource "github.com/writer/cerebro/sources/nordlayer"
	normalyzesource "github.com/writer/cerebro/sources/normalyze"
	notionsource "github.com/writer/cerebro/sources/notion"
	nucleussecuritysource "github.com/writer/cerebro/sources/nucleus_security"
	nuclinosource "github.com/writer/cerebro/sources/nuclino"
	nudgesecuritysource "github.com/writer/cerebro/sources/nudge_security"
	observeplatformsource "github.com/writer/cerebro/sources/observe_platform"
	obsidiansecuritysource "github.com/writer/cerebro/sources/obsidian_security"
	octopusdeploysource "github.com/writer/cerebro/sources/octopus_deploy"
	officespacesource "github.com/writer/cerebro/sources/office_space"
	oktasource "github.com/writer/cerebro/sources/okta"
	omadaidentitysource "github.com/writer/cerebro/sources/omada_identity"
	omnianalyticssource "github.com/writer/cerebro/sources/omni_analytics"
	oneloginsource "github.com/writer/cerebro/sources/onelogin"
	onepasswordbusinesssource "github.com/writer/cerebro/sources/onepassword_business"
	onetrustsource "github.com/writer/cerebro/sources/onetrust"
	opalsecuritysource "github.com/writer/cerebro/sources/opal_security"
	openaisource "github.com/writer/cerebro/sources/openai"
	opendatasoftsource "github.com/writer/cerebro/sources/opendatasoft"
	openfintechsource "github.com/writer/cerebro/sources/openfintech"
	openpolicysource "github.com/writer/cerebro/sources/openpolicy"
	openroutersource "github.com/writer/cerebro/sources/openrouter"
	opsgeniesource "github.com/writer/cerebro/sources/opsgenie"
	opslevelsource "github.com/writer/cerebro/sources/opslevel"
	optimizelyfeatureexperimentationsource "github.com/writer/cerebro/sources/optimizely_feature_experimentation"
	oraclehcmsource "github.com/writer/cerebro/sources/oracle_hcm"
	orcasource "github.com/writer/cerebro/sources/orca"
	orcasecuritysource "github.com/writer/cerebro/sources/orca_security"
	ordwaysource "github.com/writer/cerebro/sources/ordway"
	osisoftsource "github.com/writer/cerebro/sources/osisoft"
	otteraisource "github.com/writer/cerebro/sources/otter_ai"
	outreachsource "github.com/writer/cerebro/sources/outreach"
	oysterhrsource "github.com/writer/cerebro/sources/oyster_hr"
	paddlesource "github.com/writer/cerebro/sources/paddle"
	pagerdutysource "github.com/writer/cerebro/sources/pagerduty"
	pandadocsource "github.com/writer/cerebro/sources/pandadoc"
	panopticonsource "github.com/writer/cerebro/sources/panopticon"
	panthersource "github.com/writer/cerebro/sources/panther"
	pathlocksource "github.com/writer/cerebro/sources/pathlock"
	paychexflexsource "github.com/writer/cerebro/sources/paychex_flex"
	paycomsource "github.com/writer/cerebro/sources/paycom"
	paylocitysource "github.com/writer/cerebro/sources/paylocity"
	paylocitytimesource "github.com/writer/cerebro/sources/paylocity_time"
	pendosource "github.com/writer/cerebro/sources/pendo"
	perfectosource "github.com/writer/cerebro/sources/perfecto"
	perforcehelixcloudsource "github.com/writer/cerebro/sources/perforce_helix_cloud"
	performyardsource "github.com/writer/cerebro/sources/performyard"
	perimeter81source "github.com/writer/cerebro/sources/perimeter81"
	permitiosource "github.com/writer/cerebro/sources/permit_io"
	perplexitysource "github.com/writer/cerebro/sources/perplexity"
	personiosource "github.com/writer/cerebro/sources/personio"
	pineconesource "github.com/writer/cerebro/sources/pinecone"
	pingdomsource "github.com/writer/cerebro/sources/pingdom"
	pingonesource "github.com/writer/cerebro/sources/pingone"
	pipedrivesource "github.com/writer/cerebro/sources/pipedrive"
	pitchsource "github.com/writer/cerebro/sources/pitch"
	planviewadaptiveworksource "github.com/writer/cerebro/sources/planview_adaptivework"
	platformshsource "github.com/writer/cerebro/sources/platform_sh"
	plextracsource "github.com/writer/cerebro/sources/plextrac"
	portablesource "github.com/writer/cerebro/sources/portable"
	portainercloudsource "github.com/writer/cerebro/sources/portainer_cloud"
	portswiggerenterprisesource "github.com/writer/cerebro/sources/portswigger_enterprise"
	postmansource "github.com/writer/cerebro/sources/postman"
	postmarksource "github.com/writer/cerebro/sources/postmark"
	powerbisource "github.com/writer/cerebro/sources/power_bi"
	prismacloudsource "github.com/writer/cerebro/sources/prisma_cloud"
	privacerasource "github.com/writer/cerebro/sources/privacera"
	probelysource "github.com/writer/cerebro/sources/probely"
	procurifysource "github.com/writer/cerebro/sources/procurify"
	productboardsource "github.com/writer/cerebro/sources/productboard"
	productivsource "github.com/writer/cerebro/sources/productiv"
	proofpointsource "github.com/writer/cerebro/sources/proofpoint"
	proposifysource "github.com/writer/cerebro/sources/proposify"
	pulumicloudsource "github.com/writer/cerebro/sources/pulumi_cloud"
	pushsecuritysource "github.com/writer/cerebro/sources/push_security"
	qdrantcloudsource "github.com/writer/cerebro/sources/qdrant_cloud"
	qodosource "github.com/writer/cerebro/sources/qodo"
	qualtricssource "github.com/writer/cerebro/sources/qualtrics"
	qualysvmsource "github.com/writer/cerebro/sources/qualys_vm"
	qualysvmdrsource "github.com/writer/cerebro/sources/qualys_vmdr"
	quaysource "github.com/writer/cerebro/sources/quay"
	quickbasesource "github.com/writer/cerebro/sources/quickbase"
	quickbooksonlinesource "github.com/writer/cerebro/sources/quickbooks_online"
	quipsource "github.com/writer/cerebro/sources/quip"
	rallysource "github.com/writer/cerebro/sources/rally"
	rampsource "github.com/writer/cerebro/sources/ramp"
	rapid7insightidrsource "github.com/writer/cerebro/sources/rapid7_insightidr"
	rapid7insightvmsource "github.com/writer/cerebro/sources/rapid7_insightvm"
	raygunsource "github.com/writer/cerebro/sources/raygun"
	readmesource "github.com/writer/cerebro/sources/readme"
	rebillysource "github.com/writer/cerebro/sources/rebilly"
	rechargesource "github.com/writer/cerebro/sources/recharge"
	recosecuritysource "github.com/writer/cerebro/sources/reco_security"
	recordedfuturesource "github.com/writer/cerebro/sources/recorded_future"
	recurlysource "github.com/writer/cerebro/sources/recurly"
	redcanarysource "github.com/writer/cerebro/sources/red_canary"
	redhatsource "github.com/writer/cerebro/sources/redhat"
	redirectioniosource "github.com/writer/cerebro/sources/redirection_io"
	relativityonesource "github.com/writer/cerebro/sources/relativity_one"
	remotecomsource "github.com/writer/cerebro/sources/remote_com"
	rendercloudsource "github.com/writer/cerebro/sources/render_cloud"
	replicatesource "github.com/writer/cerebro/sources/replicate"
	replicatedsource "github.com/writer/cerebro/sources/replicated"
	resendsource "github.com/writer/cerebro/sources/resend"
	retoolsource "github.com/writer/cerebro/sources/retool"
	revenuecatsource "github.com/writer/cerebro/sources/revenuecat"
	ringcentralsource "github.com/writer/cerebro/sources/ringcentral"
	ripplingsource "github.com/writer/cerebro/sources/rippling"
	riskiqsource "github.com/writer/cerebro/sources/riskiq"
	riskonnectsource "github.com/writer/cerebro/sources/riskonnect"
	riverysource "github.com/writer/cerebro/sources/rivery"
	robinsource "github.com/writer/cerebro/sources/robin"
	rollbarsource "github.com/writer/cerebro/sources/rollbar"
	rootlysource "github.com/writer/cerebro/sources/rootly"
	rudderstacksource "github.com/writer/cerebro/sources/rudderstack"
	runscopesource "github.com/writer/cerebro/sources/runscope"
	runzerosource "github.com/writer/cerebro/sources/runzero"
	safebasesource "github.com/writer/cerebro/sources/safe_base"
	sageintacctsource "github.com/writer/cerebro/sources/sage_intacct"
	sailpointidentitynowsource "github.com/writer/cerebro/sources/sailpoint_identitynow"
	sakarisource "github.com/writer/cerebro/sources/sakari"
	salesforcesource "github.com/writer/cerebro/sources/salesforce"
	salesforcecpqsource "github.com/writer/cerebro/sources/salesforce_cpq"
	saleshoodsource "github.com/writer/cerebro/sources/saleshood"
	salesloftsource "github.com/writer/cerebro/sources/salesloft"
	saltsecuritysource "github.com/writer/cerebro/sources/salt_security"
	saucelabssource "github.com/writer/cerebro/sources/sauce_labs"
	saviyntsource "github.com/writer/cerebro/sources/saviynt"
	scalefusionsource "github.com/writer/cerebro/sources/scalefusion"
	scalrsource "github.com/writer/cerebro/sources/scalr"
	sdksource "github.com/writer/cerebro/sources/sdk"
	secureframesource "github.com/writer/cerebro/sources/secureframe"
	securitisource "github.com/writer/cerebro/sources/securiti"
	securityscorecardsource "github.com/writer/cerebro/sources/securityscorecard"
	securitytoolingmapsource "github.com/writer/cerebro/sources/securitytoolingmap"
	securonixsource "github.com/writer/cerebro/sources/securonix"
	segmentsource "github.com/writer/cerebro/sources/segment"
	seismicsource "github.com/writer/cerebro/sources/seismic"
	semaphorecisource "github.com/writer/cerebro/sources/semaphore_ci"
	semgrepsource "github.com/writer/cerebro/sources/semgrep"
	sendgridsource "github.com/writer/cerebro/sources/sendgrid"
	sendososource "github.com/writer/cerebro/sources/sendoso"
	sentinelonesource "github.com/writer/cerebro/sources/sentinelone"
	sentrasource "github.com/writer/cerebro/sources/sentra"
	sentrysource "github.com/writer/cerebro/sources/sentry"
	servicenowsource "github.com/writer/cerebro/sources/servicenow"
	servicenowgrcsource "github.com/writer/cerebro/sources/servicenow_grc"
	sevenroomssource "github.com/writer/cerebro/sources/sevenrooms"
	sharefilesource "github.com/writer/cerebro/sources/sharefile"
	shipenginesource "github.com/writer/cerebro/sources/shipengine"
	shorebirdsource "github.com/writer/cerebro/sources/shorebird"
	shortcutsource "github.com/writer/cerebro/sources/shortcut"
	showpadsource "github.com/writer/cerebro/sources/showpad"
	sigmacomputingsource "github.com/writer/cerebro/sources/sigma_computing"
	signl4source "github.com/writer/cerebro/sources/signl4"
	silverfortsource "github.com/writer/cerebro/sources/silverfort"
	simplemdmsource "github.com/writer/cerebro/sources/simplemdm"
	sinaosource "github.com/writer/cerebro/sources/sinao"
	sirionlabssource "github.com/writer/cerebro/sources/sirionlabs"
	sisensesource "github.com/writer/cerebro/sources/sisense"
	sixsensesource "github.com/writer/cerebro/sources/sixsense"
	skeddasource "github.com/writer/cerebro/sources/skedda"
	skillsoftpercipiosource "github.com/writer/cerebro/sources/skillsoft_percipio"
	slabsource "github.com/writer/cerebro/sources/slab"
	slacksource "github.com/writer/cerebro/sources/slack"
	slideroomsource "github.com/writer/cerebro/sources/slideroom"
	slitesource "github.com/writer/cerebro/sources/slite"
	smartrecruiterssource "github.com/writer/cerebro/sources/smartrecruiters"
	smartsheetsource "github.com/writer/cerebro/sources/smartsheet"
	smartsuitesource "github.com/writer/cerebro/sources/smartsuite"
	snowflakesource "github.com/writer/cerebro/sources/snowflake"
	snyksource "github.com/writer/cerebro/sources/snyk"
	sodacloudsource "github.com/writer/cerebro/sources/soda_cloud"
	sonarcloudsource "github.com/writer/cerebro/sources/sonarcloud"
	sonatypelifecyclesource "github.com/writer/cerebro/sources/sonatype_lifecycle"
	sonraisecuritysource "github.com/writer/cerebro/sources/sonrai_security"
	sophoscentralsource "github.com/writer/cerebro/sources/sophos_central"
	sotimobicontrolsource "github.com/writer/cerebro/sources/soti_mobicontrol"
	sourcegraphsource "github.com/writer/cerebro/sources/sourcegraph"
	sourcewhalesource "github.com/writer/cerebro/sources/sourcewhale"
	spaceliftsource "github.com/writer/cerebro/sources/spacelift"
	spendesksource "github.com/writer/cerebro/sources/spendesk"
	splitiosource "github.com/writer/cerebro/sources/split_io"
	splunkcloudsource "github.com/writer/cerebro/sources/splunk_cloud"
	splunkobservabilitysource "github.com/writer/cerebro/sources/splunk_observability"
	springhealthsource "github.com/writer/cerebro/sources/springhealth"
	sprinklrsource "github.com/writer/cerebro/sources/sprinklr"
	sprintosource "github.com/writer/cerebro/sources/sprinto"
	sproutsocialsource "github.com/writer/cerebro/sources/sprout_social"
	squadcastsource "github.com/writer/cerebro/sources/squadcast"
	squaresource "github.com/writer/cerebro/sources/square"
	stabilityaisource "github.com/writer/cerebro/sources/stability_ai"
	stackblitzsource "github.com/writer/cerebro/sources/stackblitz"
	stackhawksource "github.com/writer/cerebro/sources/stackhawk"
	statsigsource "github.com/writer/cerebro/sources/statsig"
	statuscakesource "github.com/writer/cerebro/sources/statuscake"
	statuspagesource "github.com/writer/cerebro/sources/statuspage"
	stiggsource "github.com/writer/cerebro/sources/stigg"
	stitchsource "github.com/writer/cerebro/sources/stitch"
	stoplightsource "github.com/writer/cerebro/sources/stoplight"
	streamioapisource "github.com/writer/cerebro/sources/stream_io_api"
	stripesource "github.com/writer/cerebro/sources/stripe"
	strongdmsource "github.com/writer/cerebro/sources/strongdm"
	stytchsource "github.com/writer/cerebro/sources/stytch"
	successfactorssource "github.com/writer/cerebro/sources/successfactors"
	sumologicsource "github.com/writer/cerebro/sources/sumo_logic"
	surveymonkeysource "github.com/writer/cerebro/sources/surveymonkey"
	svixsource "github.com/writer/cerebro/sources/svix"
	swaggerhubsource "github.com/writer/cerebro/sources/swaggerhub"
	swifaisource "github.com/writer/cerebro/sources/swif_ai"
	synacksource "github.com/writer/cerebro/sources/synack"
	synccomsource "github.com/writer/cerebro/sources/sync_com"
	sysdigsecuresource "github.com/writer/cerebro/sources/sysdig_secure"
	tableaucloudsource "github.com/writer/cerebro/sources/tableau_cloud"
	tailscalesource "github.com/writer/cerebro/sources/tailscale"
	talkdesksource "github.com/writer/cerebro/sources/talkdesk"
	tallyfysource "github.com/writer/cerebro/sources/tallyfy"
	taniumcloudsource "github.com/writer/cerebro/sources/tanium_cloud"
	taxamosource "github.com/writer/cerebro/sources/taxamo"
	teamcitycloudsource "github.com/writer/cerebro/sources/teamcity_cloud"
	teampaysource "github.com/writer/cerebro/sources/teampay"
	teamworksource "github.com/writer/cerebro/sources/teamwork"
	teamworkprojectssource "github.com/writer/cerebro/sources/teamwork_projects"
	telemetryhubsource "github.com/writer/cerebro/sources/telemetryhub"
	teleportsource "github.com/writer/cerebro/sources/teleport"
	telnyxsource "github.com/writer/cerebro/sources/telnyx"
	tenableiosource "github.com/writer/cerebro/sources/tenable_io"
	terraformcloudsource "github.com/writer/cerebro/sources/terraform_cloud"
	testimsource "github.com/writer/cerebro/sources/testim"
	tettrasource "github.com/writer/cerebro/sources/tettra"
	thoropasssource "github.com/writer/cerebro/sources/thoropass"
	thoughtspotsource "github.com/writer/cerebro/sources/thoughtspot"
	thousandeyessource "github.com/writer/cerebro/sources/thousandeyes"
	threatjammersource "github.com/writer/cerebro/sources/threatjammer"
	threesixtylearningsource "github.com/writer/cerebro/sources/three_sixty_learning"
	tinessource "github.com/writer/cerebro/sources/tines"
	togetheraisource "github.com/writer/cerebro/sources/together_ai"
	toriisource "github.com/writer/cerebro/sources/torii"
	torqsource "github.com/writer/cerebro/sources/torq"
	traceableaisource "github.com/writer/cerebro/sources/traceable_ai"
	traviscisource "github.com/writer/cerebro/sources/travis_ci"
	trayiosource "github.com/writer/cerebro/sources/tray_io"
	trellosource "github.com/writer/cerebro/sources/trello"
	tresoritsource "github.com/writer/cerebro/sources/tresorit"
	trivysource "github.com/writer/cerebro/sources/trivy"
	trufflehogenterprisesource "github.com/writer/cerebro/sources/trufflehog_enterprise"
	truorasource "github.com/writer/cerebro/sources/truora"
	trustarcsource "github.com/writer/cerebro/sources/trustarc"
	trustedendpointsource "github.com/writer/cerebro/sources/trustedendpoint"
	trustpilotsource "github.com/writer/cerebro/sources/trustpilot"
	tugboatlogicsource "github.com/writer/cerebro/sources/tugboat_logic"
	twiliosource "github.com/writer/cerebro/sources/twilio"
	twittersource "github.com/writer/cerebro/sources/twitter"
	tyksource "github.com/writer/cerebro/sources/tyk"
	typeformsource "github.com/writer/cerebro/sources/typeform"
	typefullysource "github.com/writer/cerebro/sources/typefully"
	udemybusinesssource "github.com/writer/cerebro/sources/udemy_business"
	ujetsource "github.com/writer/cerebro/sources/ujet"
	ukgprosource "github.com/writer/cerebro/sources/ukg_pro"
	unleashcloudsource "github.com/writer/cerebro/sources/unleash_cloud"
	upguardsource "github.com/writer/cerebro/sources/upguard"
	uptimecomsource "github.com/writer/cerebro/sources/uptime_com"
	uptimerobotsource "github.com/writer/cerebro/sources/uptimerobot"
	uptracesource "github.com/writer/cerebro/sources/uptrace"
	userpilotsource "github.com/writer/cerebro/sources/userpilot"
	uservoicesource "github.com/writer/cerebro/sources/uservoice"
	valencesecuritysource "github.com/writer/cerebro/sources/valence_security"
	vantasource "github.com/writer/cerebro/sources/vanta"
	varicentsource "github.com/writer/cerebro/sources/varicent"
	velopaymentssource "github.com/writer/cerebro/sources/velopayments"
	veracodesource "github.com/writer/cerebro/sources/veracode"
	vercelsource "github.com/writer/cerebro/sources/vercel"
	victoriametricscloudsource "github.com/writer/cerebro/sources/victoriametrics_cloud"
	victoropssource "github.com/writer/cerebro/sources/victorops"
	vidyardsource "github.com/writer/cerebro/sources/vidyard"
	virustotalsource "github.com/writer/cerebro/sources/virustotal"
	visiblethreadsource "github.com/writer/cerebro/sources/visiblethread"
	vitallysource "github.com/writer/cerebro/sources/vitally"
	vulnchecksource "github.com/writer/cerebro/sources/vulncheck"
	vulnviewsource "github.com/writer/cerebro/sources/vulnview"
	webexsource "github.com/writer/cerebro/sources/webex"
	whatsappsource "github.com/writer/cerebro/sources/whatsapp"
	wherebysource "github.com/writer/cerebro/sources/whereby"
	whisticsource "github.com/writer/cerebro/sources/whistic"
	wingsecuritysource "github.com/writer/cerebro/sources/wing_security"
	winsmssource "github.com/writer/cerebro/sources/winsms"
	wistiasource "github.com/writer/cerebro/sources/wistia"
	wizsource "github.com/writer/cerebro/sources/wiz"
	workablesource "github.com/writer/cerebro/sources/workable"
	workatosource "github.com/writer/cerebro/sources/workato"
	workdaysource "github.com/writer/cerebro/sources/workday"
	workfrontsource "github.com/writer/cerebro/sources/workfront"
	workossource "github.com/writer/cerebro/sources/workos"
	workplacefrommetasource "github.com/writer/cerebro/sources/workplace_from_meta"
	wrikesource "github.com/writer/cerebro/sources/wrike"
	writersource "github.com/writer/cerebro/sources/writer"
	xaisource "github.com/writer/cerebro/sources/xai"
	xerosource "github.com/writer/cerebro/sources/xero"
	xmatterssource "github.com/writer/cerebro/sources/xmatters"
	xtrfeusource "github.com/writer/cerebro/sources/xtrf_eu"
	yardivoyagersource "github.com/writer/cerebro/sources/yardi_voyager"
	zapierenterprisesource "github.com/writer/cerebro/sources/zapier_enterprise"
	zeetsource "github.com/writer/cerebro/sources/zeet"
	zendesksource "github.com/writer/cerebro/sources/zendesk"
	zendesksellsource "github.com/writer/cerebro/sources/zendesk_sell"
	zenefitssource "github.com/writer/cerebro/sources/zenefits"
	zerofoxsource "github.com/writer/cerebro/sources/zerofox"
	zillasecuritysource "github.com/writer/cerebro/sources/zilla_security"
	ziphqsource "github.com/writer/cerebro/sources/ziphq"
	zohobookssource "github.com/writer/cerebro/sources/zoho_books"
	zohocrmsource "github.com/writer/cerebro/sources/zoho_crm"
	zohomailsource "github.com/writer/cerebro/sources/zoho_mail"
	zohoprojectssource "github.com/writer/cerebro/sources/zoho_projects"
	zohosprintssource "github.com/writer/cerebro/sources/zoho_sprints"
	zohoworkdrivesource "github.com/writer/cerebro/sources/zoho_workdrive"
	zoomsource "github.com/writer/cerebro/sources/zoom"
	zoomphonesource "github.com/writer/cerebro/sources/zoom_phone"
	zoominfosource "github.com/writer/cerebro/sources/zoominfo"
	zscalerinternetaccesssource "github.com/writer/cerebro/sources/zscaler_internet_access"
	zscalerprivateaccesssource "github.com/writer/cerebro/sources/zscaler_private_access"
	zuorasource "github.com/writer/cerebro/sources/zuora"
	zylosource "github.com/writer/cerebro/sources/zylo"
)

type DefinitionFixtureReadResult = catalogruntimesource.FixtureReadResult

type builtinSourceLoader struct {
	name string
	load func() (sourcecdk.Source, error)
}

var builtinSourceLoaders = []builtinSourceLoader{
	{
		name: "abnormal_security",
		load: func() (sourcecdk.Source, error) {
			return abnormalsecuritysource.New()
		},
	},
	{
		name: "abuseipdb",
		load: func() (sourcecdk.Source, error) {
			return abuseipdbsource.New()
		},
	},
	{
		name: "activecampaign",
		load: func() (sourcecdk.Source, error) {
			return activecampaignsource.New()
		},
	},
	{
		name: "activtrak",
		load: func() (sourcecdk.Source, error) {
			return activtraksource.New()
		},
	},
	{
		name: "acunetix",
		load: func() (sourcecdk.Source, error) {
			return acunetixsource.New()
		},
	},
	{
		name: "ada_support",
		load: func() (sourcecdk.Source, error) {
			return adasupportsource.New()
		},
	},
	{
		name: "addigy",
		load: func() (sourcecdk.Source, error) {
			return addigysource.New()
		},
	},
	{
		name: "adobe_workfront",
		load: func() (sourcecdk.Source, error) {
			return adobeworkfrontsource.New()
		},
	},
	{
		name: "adp_workforce_now",
		load: func() (sourcecdk.Source, error) {
			return adpworkforcenowsource.New()
		},
	},
	{
		name: "agiloft",
		load: func() (sourcecdk.Source, error) {
			return agiloftsource.New()
		},
	},
	{
		name: "aha",
		load: func() (sourcecdk.Source, error) {
			return ahasource.New()
		},
	},
	{
		name: "airbase",
		load: func() (sourcecdk.Source, error) {
			return airbasesource.New()
		},
	},
	{
		name: "airbrake",
		load: func() (sourcecdk.Source, error) {
			return airbrakesource.New()
		},
	},
	{
		name: "airbyte_cloud",
		load: func() (sourcecdk.Source, error) {
			return airbytecloudsource.New()
		},
	},
	{
		name: "aircall",
		load: func() (sourcecdk.Source, error) {
			return aircallsource.New()
		},
	},
	{
		name: "airfocus",
		load: func() (sourcecdk.Source, error) {
			return airfocussource.New()
		},
	},
	{
		name: "airtable",
		load: func() (sourcecdk.Source, error) {
			return airtablesource.New()
		},
	},
	{
		name: "akeneo",
		load: func() (sourcecdk.Source, error) {
			return akeneosource.New()
		},
	},
	{
		name: "akeyless",
		load: func() (sourcecdk.Source, error) {
			return akeylesssource.New()
		},
	},
	{
		name: "alation",
		load: func() (sourcecdk.Source, error) {
			return alationsource.New()
		},
	},
	{
		name: "alchemer",
		load: func() (sourcecdk.Source, error) {
			return alchemersource.New()
		},
	},
	{
		name: "alteryx",
		load: func() (sourcecdk.Source, error) {
			return alteryxsource.New()
		},
	},
	{
		name: "amplitude",
		load: func() (sourcecdk.Source, error) {
			return amplitudesource.New()
		},
	},
	{
		name: "anchore",
		load: func() (sourcecdk.Source, error) {
			return anchoresource.New()
		},
	},
	{
		name: "anecdotes",
		load: func() (sourcecdk.Source, error) {
			return anecdotessource.New()
		},
	},
	{
		name: "anomali_threatstream",
		load: func() (sourcecdk.Source, error) {
			return anomalithreatstreamsource.New()
		},
	},
	{
		name: "anomalo",
		load: func() (sourcecdk.Source, error) {
			return anomalosource.New()
		},
	},
	{
		name: "anthropic",
		load: func() (sourcecdk.Source, error) {
			return anthropicsource.New()
		},
	},
	{
		name: "apache",
		load: func() (sourcecdk.Source, error) {
			return apachesource.New()
		},
	},
	{
		name: "apacta",
		load: func() (sourcecdk.Source, error) {
			return apactasource.New()
		},
	},
	{
		name: "api2cart",
		load: func() (sourcecdk.Source, error) {
			return api2cartsource.New()
		},
	},
	{
		name: "apideck",
		load: func() (sourcecdk.Source, error) {
			return apidecksource.New()
		},
	},
	{
		name: "apigee",
		load: func() (sourcecdk.Source, error) {
			return apigeesource.New()
		},
	},
	{
		name: "apiiro",
		load: func() (sourcecdk.Source, error) {
			return apiirosource.New()
		},
	},
	{
		name: "apollo",
		load: func() (sourcecdk.Source, error) {
			return apollosource.New()
		},
	},
	{
		name: "appcircle",
		load: func() (sourcecdk.Source, error) {
			return appcirclesource.New()
		},
	},
	{
		name: "appdynamics",
		load: func() (sourcecdk.Source, error) {
			return appdynamicssource.New()
		},
	},
	{
		name: "appfolio",
		load: func() (sourcecdk.Source, error) {
			return appfoliosource.New()
		},
	},
	{
		name: "appgate",
		load: func() (sourcecdk.Source, error) {
			return appgatesource.New()
		},
	},
	{
		name: "applitools",
		load: func() (sourcecdk.Source, error) {
			return applitoolssource.New()
		},
	},
	{
		name: "appomni",
		load: func() (sourcecdk.Source, error) {
			return appomnisource.New()
		},
	},
	{
		name: "appveyor",
		load: func() (sourcecdk.Source, error) {
			return appveyorsource.New()
		},
	},
	{
		name: "appwrite",
		load: func() (sourcecdk.Source, error) {
			return appwritesource.New()
		},
	},
	{
		name: "aqua_security",
		load: func() (sourcecdk.Source, error) {
			return aquasecuritysource.New()
		},
	},
	{
		name: "archetype",
		load: func() (sourcecdk.Source, error) {
			return archetypesource.New()
		},
	},
	{
		name: "arctic_wolf",
		load: func() (sourcecdk.Source, error) {
			return arcticwolfsource.New()
		},
	},
	{
		name: "argo_cd",
		load: func() (sourcecdk.Source, error) {
			return argocdsource.New()
		},
	},
	{
		name: "armis",
		load: func() (sourcecdk.Source, error) {
			return armissource.New()
		},
	},
	{
		name: "armo_platform",
		load: func() (sourcecdk.Source, error) {
			return armoplatformsource.New()
		},
	},
	{
		name: "armorcode",
		load: func() (sourcecdk.Source, error) {
			return armorcodesource.New()
		},
	},
	{
		name: "arnica_security",
		load: func() (sourcecdk.Source, error) {
			return arnicasecuritysource.New()
		},
	},
	{
		name: "asana",
		load: func() (sourcecdk.Source, error) {
			return asanasource.New()
		},
	},
	{
		name: "ashby",
		load: func() (sourcecdk.Source, error) {
			return ashbysource.New()
		},
	},
	{
		name: "astrix_security",
		load: func() (sourcecdk.Source, error) {
			return astrixsecuritysource.New()
		},
	},
	{
		name: "atlan",
		load: func() (sourcecdk.Source, error) {
			return atlansource.New()
		},
	},
	{
		name: "attackiq",
		load: func() (sourcecdk.Source, error) {
			return attackiqsource.New()
		},
	},
	{
		name: "auditboard",
		load: func() (sourcecdk.Source, error) {
			return auditboardsource.New()
		},
	},
	{
		name: "aurelius",
		load: func() (sourcecdk.Source, error) {
			return aureliussource.New()
		},
	},
	{
		name: "auth0",
		load: func() (sourcecdk.Source, error) {
			return auth0source.New()
		},
	},
	{
		name: "authentik_cloud",
		load: func() (sourcecdk.Source, error) {
			return authentikcloudsource.New()
		},
	},
	{
		name: "autotask",
		load: func() (sourcecdk.Source, error) {
			return autotasksource.New()
		},
	},
	{
		name: "avature",
		load: func() (sourcecdk.Source, error) {
			return avaturesource.New()
		},
	},
	{
		name: "avaza",
		load: func() (sourcecdk.Source, error) {
			return avazasource.New()
		},
	},
	{
		name: "aws",
		load: func() (sourcecdk.Source, error) {
			return awssource.New()
		},
	},
	{
		name: "aws_bedrock",
		load: func() (sourcecdk.Source, error) {
			return awsbedrocksource.New()
		},
	},
	{
		name: "axiom",
		load: func() (sourcecdk.Source, error) {
			return axiomsource.New()
		},
	},
	{
		name: "axonius",
		load: func() (sourcecdk.Source, error) {
			return axoniussource.New()
		},
	},
	{
		name: "azure",
		load: func() (sourcecdk.Source, error) {
			return azuresource.New()
		},
	},
	{
		name: "azure_devops",
		load: func() (sourcecdk.Source, error) {
			return azuredevopssource.New()
		},
	},
	{
		name: "azure_openai",
		load: func() (sourcecdk.Source, error) {
			return azureopenaisource.New()
		},
	},
	{
		name: "backstage",
		load: func() (sourcecdk.Source, error) {
			return backstagesource.New()
		},
	},
	{
		name: "bamboohr",
		load: func() (sourcecdk.Source, error) {
			return bamboohrsource.New()
		},
	},
	{
		name: "basecamp",
		load: func() (sourcecdk.Source, error) {
			return basecampsource.New()
		},
	},
	{
		name: "baselime",
		load: func() (sourcecdk.Source, error) {
			return baselimesource.New()
		},
	},
	{
		name: "bazaarvoice",
		load: func() (sourcecdk.Source, error) {
			return bazaarvoicesource.New()
		},
	},
	{
		name: "beeline",
		load: func() (sourcecdk.Source, error) {
			return beelinesource.New()
		},
	},
	{
		name: "beezup",
		load: func() (sourcecdk.Source, error) {
			return beezupsource.New()
		},
	},
	{
		name: "better_stack",
		load: func() (sourcecdk.Source, error) {
			return betterstacksource.New()
		},
	},
	{
		name: "bettercloud",
		load: func() (sourcecdk.Source, error) {
			return bettercloudsource.New()
		},
	},
	{
		name: "beyondtrust",
		load: func() (sourcecdk.Source, error) {
			return beyondtrustsource.New()
		},
	},
	{
		name: "biapi",
		load: func() (sourcecdk.Source, error) {
			return biapisource.New()
		},
	},
	{
		name: "bigfix",
		load: func() (sourcecdk.Source, error) {
			return bigfixsource.New()
		},
	},
	{
		name: "bigid",
		load: func() (sourcecdk.Source, error) {
			return bigidsource.New()
		},
	},
	{
		name: "bigpanda",
		load: func() (sourcecdk.Source, error) {
			return bigpandasource.New()
		},
	},
	{
		name: "bigredcloud",
		load: func() (sourcecdk.Source, error) {
			return bigredcloudsource.New()
		},
	},
	{
		name: "bill_com",
		load: func() (sourcecdk.Source, error) {
			return billcomsource.New()
		},
	},
	{
		name: "billbee",
		load: func() (sourcecdk.Source, error) {
			return billbeesource.New()
		},
	},
	{
		name: "billingo",
		load: func() (sourcecdk.Source, error) {
			return billingosource.New()
		},
	},
	{
		name: "bitbucket_cloud",
		load: func() (sourcecdk.Source, error) {
			return bitbucketcloudsource.New()
		},
	},
	{
		name: "bitrise",
		load: func() (sourcecdk.Source, error) {
			return bitrisesource.New()
		},
	},
	{
		name: "bitsight",
		load: func() (sourcecdk.Source, error) {
			return bitsightsource.New()
		},
	},
	{
		name: "bitwarden",
		load: func() (sourcecdk.Source, error) {
			return bitwardensource.New()
		},
	},
	{
		name: "bitwarden_enterprise",
		load: func() (sourcecdk.Source, error) {
			return bitwardenenterprisesource.New()
		},
	},
	{
		name: "black_kite",
		load: func() (sourcecdk.Source, error) {
			return blackkitesource.New()
		},
	},
	{
		name: "blackduck",
		load: func() (sourcecdk.Source, error) {
			return blackducksource.New()
		},
	},
	{
		name: "bluejeans",
		load: func() (sourcecdk.Source, error) {
			return bluejeanssource.New()
		},
	},
	{
		name: "boomi",
		load: func() (sourcecdk.Source, error) {
			return boomisource.New()
		},
	},
	{
		name: "botify",
		load: func() (sourcecdk.Source, error) {
			return botifysource.New()
		},
	},
	{
		name: "box",
		load: func() (sourcecdk.Source, error) {
			return boxsource.New()
		},
	},
	{
		name: "braintree",
		load: func() (sourcecdk.Source, error) {
			return braintreesource.New()
		},
	},
	{
		name: "braze",
		load: func() (sourcecdk.Source, error) {
			return brazesource.New()
		},
	},
	{
		name: "brex",
		load: func() (sourcecdk.Source, error) {
			return brexsource.New()
		},
	},
	{
		name: "brightflag",
		load: func() (sourcecdk.Source, error) {
			return brightflagsource.New()
		},
	},
	{
		name: "brinqa",
		load: func() (sourcecdk.Source, error) {
			return brinqasource.New()
		},
	},
	{
		name: "britive",
		load: func() (sourcecdk.Source, error) {
			return britivesource.New()
		},
	},
	{
		name: "browserstack",
		load: func() (sourcecdk.Source, error) {
			return browserstacksource.New()
		},
	},
	{
		name: "buddy_ci",
		load: func() (sourcecdk.Source, error) {
			return buddycisource.New()
		},
	},
	{
		name: "bugcrowd",
		load: func() (sourcecdk.Source, error) {
			return bugcrowdsource.New()
		},
	},
	{
		name: "bugsnag",
		load: func() (sourcecdk.Source, error) {
			return bugsnagsource.New()
		},
	},
	{
		name: "buildkite",
		load: func() (sourcecdk.Source, error) {
			return buildkitesource.New()
		},
	},
	{
		name: "bulksms",
		load: func() (sourcecdk.Source, error) {
			return bulksmssource.New()
		},
	},
	{
		name: "bunq",
		load: func() (sourcecdk.Source, error) {
			return bunqsource.New()
		},
	},
	{
		name: "burp_suite_enterprise",
		load: func() (sourcecdk.Source, error) {
			return burpsuiteenterprisesource.New()
		},
	},
	{
		name: "calcom",
		load: func() (sourcecdk.Source, error) {
			return calcomsource.New()
		},
	},
	{
		name: "calendly",
		load: func() (sourcecdk.Source, error) {
			return calendlysource.New()
		},
	},
	{
		name: "callfire",
		load: func() (sourcecdk.Source, error) {
			return callfiresource.New()
		},
	},
	{
		name: "callrail",
		load: func() (sourcecdk.Source, error) {
			return callrailsource.New()
		},
	},
	{
		name: "campaign_monitor",
		load: func() (sourcecdk.Source, error) {
			return campaignmonitorsource.New()
		},
	},
	{
		name: "canva_enterprise",
		load: func() (sourcecdk.Source, error) {
			return canvaenterprisesource.New()
		},
	},
	{
		name: "carbon_black_cloud",
		load: func() (sourcecdk.Source, error) {
			return carbonblackcloudsource.New()
		},
	},
	{
		name: "caspio",
		load: func() (sourcecdk.Source, error) {
			return caspiosource.New()
		},
	},
	{
		name: "cast_ai",
		load: func() (sourcecdk.Source, error) {
			return castaisource.New()
		},
	},
	{
		name: "catalyst",
		load: func() (sourcecdk.Source, error) {
			return catalystsource.New()
		},
	},
	{
		name: "catchpoint",
		load: func() (sourcecdk.Source, error) {
			return catchpointsource.New()
		},
	},
	{
		name: "cato_networks",
		load: func() (sourcecdk.Source, error) {
			return catonetworkssource.New()
		},
	},
	{
		name: "cenit",
		load: func() (sourcecdk.Source, error) {
			return cenitsource.New()
		},
	},
	{
		name: "census",
		load: func() (sourcecdk.Source, error) {
			return censussource.New()
		},
	},
	{
		name: "censys_asm",
		load: func() (sourcecdk.Source, error) {
			return censysasmsource.New()
		},
	},
	{
		name: "cerbos_cloud",
		load: func() (sourcecdk.Source, error) {
			return cerboscloudsource.New()
		},
	},
	{
		name: "cerby",
		load: func() (sourcecdk.Source, error) {
			return cerbysource.New()
		},
	},
	{
		name: "cerebras",
		load: func() (sourcecdk.Source, error) {
			return cerebrassource.New()
		},
	},
	{
		name: "cerebro",
		load: func() (sourcecdk.Source, error) {
			return cerebrosource.New()
		},
	},
	{
		name: "ceridian_dayforce",
		load: func() (sourcecdk.Source, error) {
			return ceridiandayforcesource.New()
		},
	},
	{
		name: "chargebee",
		load: func() (sourcecdk.Source, error) {
			return chargebeesource.New()
		},
	},
	{
		name: "chargify",
		load: func() (sourcecdk.Source, error) {
			return chargifysource.New()
		},
	},
	{
		name: "charthop",
		load: func() (sourcecdk.Source, error) {
			return charthopsource.New()
		},
	},
	{
		name: "checkly",
		load: func() (sourcecdk.Source, error) {
			return checklysource.New()
		},
	},
	{
		name: "checkmarx_one",
		load: func() (sourcecdk.Source, error) {
			return checkmarxonesource.New()
		},
	},
	{
		name: "checkout_com",
		load: func() (sourcecdk.Source, error) {
			return checkoutcomsource.New()
		},
	},
	{
		name: "checkr",
		load: func() (sourcecdk.Source, error) {
			return checkrsource.New()
		},
	},
	{
		name: "chili_piper",
		load: func() (sourcecdk.Source, error) {
			return chilipipersource.New()
		},
	},
	{
		name: "chorus",
		load: func() (sourcecdk.Source, error) {
			return chorussource.New()
		},
	},
	{
		name: "chronosphere",
		load: func() (sourcecdk.Source, error) {
			return chronospheresource.New()
		},
	},
	{
		name: "churnzero",
		load: func() (sourcecdk.Source, error) {
			return churnzerosource.New()
		},
	},
	{
		name: "circleci",
		load: func() (sourcecdk.Source, error) {
			return circlecisource.New()
		},
	},
	{
		name: "cisco_umbrella",
		load: func() (sourcecdk.Source, error) {
			return ciscoumbrellasource.New()
		},
	},
	{
		name: "clari",
		load: func() (sourcecdk.Source, error) {
			return clarisource.New()
		},
	},
	{
		name: "claroty",
		load: func() (sourcecdk.Source, error) {
			return clarotysource.New()
		},
	},
	{
		name: "clearblade",
		load: func() (sourcecdk.Source, error) {
			return clearbladesource.New()
		},
	},
	{
		name: "clever_cloud",
		load: func() (sourcecdk.Source, error) {
			return clevercloudsource.New()
		},
	},
	{
		name: "clickmeter",
		load: func() (sourcecdk.Source, error) {
			return clickmetersource.New()
		},
	},
	{
		name: "clicksend",
		load: func() (sourcecdk.Source, error) {
			return clicksendsource.New()
		},
	},
	{
		name: "clickup",
		load: func() (sourcecdk.Source, error) {
			return clickupsource.New()
		},
	},
	{
		name: "close_crm",
		load: func() (sourcecdk.Source, error) {
			return closecrmsource.New()
		},
	},
	{
		name: "cloudbees_ci",
		load: func() (sourcecdk.Source, error) {
			return cloudbeescisource.New()
		},
	},
	{
		name: "cloudflare",
		load: func() (sourcecdk.Source, error) {
			return cloudflaresource.New()
		},
	},
	{
		name: "cloudflare_workers_ai",
		load: func() (sourcecdk.Source, error) {
			return cloudflareworkersaisource.New()
		},
	},
	{
		name: "cloudflare_zero_trust",
		load: func() (sourcecdk.Source, error) {
			return cloudflarezerotrustsource.New()
		},
	},
	{
		name: "cloudsmith",
		load: func() (sourcecdk.Source, error) {
			return cloudsmithsource.New()
		},
	},
	{
		name: "cloudtalk",
		load: func() (sourcecdk.Source, error) {
			return cloudtalksource.New()
		},
	},
	{
		name: "coalesce_data",
		load: func() (sourcecdk.Source, error) {
			return coalescedatasource.New()
		},
	},
	{
		name: "cobalt",
		load: func() (sourcecdk.Source, error) {
			return cobaltsource.New()
		},
	},
	{
		name: "cockroachdb_cloud",
		load: func() (sourcecdk.Source, error) {
			return cockroachdbcloudsource.New()
		},
	},
	{
		name: "coda",
		load: func() (sourcecdk.Source, error) {
			return codasource.New()
		},
	},
	{
		name: "codacy",
		load: func() (sourcecdk.Source, error) {
			return codacysource.New()
		},
	},
	{
		name: "codecov",
		load: func() (sourcecdk.Source, error) {
			return codecovsource.New()
		},
	},
	{
		name: "codefresh",
		load: func() (sourcecdk.Source, error) {
			return codefreshsource.New()
		},
	},
	{
		name: "codemagic",
		load: func() (sourcecdk.Source, error) {
			return codemagicsource.New()
		},
	},
	{
		name: "coder_cloud",
		load: func() (sourcecdk.Source, error) {
			return codercloudsource.New()
		},
	},
	{
		name: "cofense",
		load: func() (sourcecdk.Source, error) {
			return cofensesource.New()
		},
	},
	{
		name: "cohere",
		load: func() (sourcecdk.Source, error) {
			return coheresource.New()
		},
	},
	{
		name: "collibra",
		load: func() (sourcecdk.Source, error) {
			return collibrasource.New()
		},
	},
	{
		name: "combell",
		load: func() (sourcecdk.Source, error) {
			return combellsource.New()
		},
	},
	{
		name: "concur",
		load: func() (sourcecdk.Source, error) {
			return concursource.New()
		},
	},
	{
		name: "configcat",
		load: func() (sourcecdk.Source, error) {
			return configcatsource.New()
		},
	},
	{
		name: "confluence",
		load: func() (sourcecdk.Source, error) {
			return confluencesource.New()
		},
	},
	{
		name: "conga",
		load: func() (sourcecdk.Source, error) {
			return congasource.New()
		},
	},
	{
		name: "conjur",
		load: func() (sourcecdk.Source, error) {
			return conjursource.New()
		},
	},
	{
		name: "contentful",
		load: func() (sourcecdk.Source, error) {
			return contentfulsource.New()
		},
	},
	{
		name: "contractbook",
		load: func() (sourcecdk.Source, error) {
			return contractbooksource.New()
		},
	},
	{
		name: "contrast_security",
		load: func() (sourcecdk.Source, error) {
			return contrastsecuritysource.New()
		},
	},
	{
		name: "copper_crm",
		load: func() (sourcecdk.Source, error) {
			return coppercrmsource.New()
		},
	},
	{
		name: "coralogix",
		load: func() (sourcecdk.Source, error) {
			return coralogixsource.New()
		},
	},
	{
		name: "cornerstone_ondemand",
		load: func() (sourcecdk.Source, error) {
			return cornerstoneondemandsource.New()
		},
	},
	{
		name: "cortex_xdr",
		load: func() (sourcecdk.Source, error) {
			return cortexxdrsource.New()
		},
	},
	{
		name: "cortex_xsoar",
		load: func() (sourcecdk.Source, error) {
			return cortexxsoarsource.New()
		},
	},
	{
		name: "cosmo",
		load: func() (sourcecdk.Source, error) {
			return cosmosource.New()
		},
	},
	{
		name: "coupa",
		load: func() (sourcecdk.Source, error) {
			return coupasource.New()
		},
	},
	{
		name: "crashlytics",
		load: func() (sourcecdk.Source, error) {
			return crashlyticssource.New()
		},
	},
	{
		name: "creately",
		load: func() (sourcecdk.Source, error) {
			return createlysource.New()
		},
	},
	{
		name: "cribl_cloud",
		load: func() (sourcecdk.Source, error) {
			return criblcloudsource.New()
		},
	},
	{
		name: "crowdstrike_falcon",
		load: func() (sourcecdk.Source, error) {
			return crowdstrikefalconsource.New()
		},
	},
	{
		name: "crowdstrike_identity",
		load: func() (sourcecdk.Source, error) {
			return crowdstrikeidentitysource.New()
		},
	},
	{
		name: "culture_amp",
		load: func() (sourcecdk.Source, error) {
			return cultureampsource.New()
		},
	},
	{
		name: "customer_io",
		load: func() (sourcecdk.Source, error) {
			return customeriosource.New()
		},
	},
	{
		name: "cyberark_identity",
		load: func() (sourcecdk.Source, error) {
			return cyberarkidentitysource.New()
		},
	},
	{
		name: "cyberark_pam",
		load: func() (sourcecdk.Source, error) {
			return cyberarkpamsource.New()
		},
	},
	{
		name: "cycode",
		load: func() (sourcecdk.Source, error) {
			return cycodesource.New()
		},
	},
	{
		name: "cyera",
		load: func() (sourcecdk.Source, error) {
			return cyerasource.New()
		},
	},
	{
		name: "cyolo",
		load: func() (sourcecdk.Source, error) {
			return cyolosource.New()
		},
	},
	{
		name: "dashlane_business",
		load: func() (sourcecdk.Source, error) {
			return dashlanebusinesssource.New()
		},
	},
	{
		name: "databricks",
		load: func() (sourcecdk.Source, error) {
			return databrickssource.New()
		},
	},
	{
		name: "datadog",
		load: func() (sourcecdk.Source, error) {
			return datadogsource.New()
		},
	},
	{
		name: "datafold",
		load: func() (sourcecdk.Source, error) {
			return datafoldsource.New()
		},
	},
	{
		name: "dbt_cloud",
		load: func() (sourcecdk.Source, error) {
			return dbtcloudsource.New()
		},
	},
	{
		name: "dealhub",
		load: func() (sourcecdk.Source, error) {
			return dealhubsource.New()
		},
	},
	{
		name: "deel",
		load: func() (sourcecdk.Source, error) {
			return deelsource.New()
		},
	},
	{
		name: "deepseek",
		load: func() (sourcecdk.Source, error) {
			return deepseeksource.New()
		},
	},
	{
		name: "defectdojo_cloud",
		load: func() (sourcecdk.Source, error) {
			return defectdojocloudsource.New()
		},
	},
	{
		name: "degreed",
		load: func() (sourcecdk.Source, error) {
			return degreedsource.New()
		},
	},
	{
		name: "delinea",
		load: func() (sourcecdk.Source, error) {
			return delineasource.New()
		},
	},
	{
		name: "demandbase",
		load: func() (sourcecdk.Source, error) {
			return demandbasesource.New()
		},
	},
	{
		name: "depot",
		load: func() (sourcecdk.Source, error) {
			return depotsource.New()
		},
	},
	{
		name: "descope",
		load: func() (sourcecdk.Source, error) {
			return descopesource.New()
		},
	},
	{
		name: "detectify",
		load: func() (sourcecdk.Source, error) {
			return detectifysource.New()
		},
	},
	{
		name: "devcycle",
		load: func() (sourcecdk.Source, error) {
			return devcyclesource.New()
		},
	},
	{
		name: "device42",
		load: func() (sourcecdk.Source, error) {
			return device42source.New()
		},
	},
	{
		name: "devtron",
		load: func() (sourcecdk.Source, error) {
			return devtronsource.New()
		},
	},
	{
		name: "dialpad",
		load: func() (sourcecdk.Source, error) {
			return dialpadsource.New()
		},
	},
	{
		name: "dig_security",
		load: func() (sourcecdk.Source, error) {
			return digsecuritysource.New()
		},
	},
	{
		name: "digitalocean",
		load: func() (sourcecdk.Source, error) {
			return digitaloceansource.New()
		},
	},
	{
		name: "discord",
		load: func() (sourcecdk.Source, error) {
			return discordsource.New()
		},
	},
	{
		name: "discourse",
		load: func() (sourcecdk.Source, error) {
			return discoursesource.New()
		},
	},
	{
		name: "divvy",
		load: func() (sourcecdk.Source, error) {
			return divvysource.New()
		},
	},
	{
		name: "dixa",
		load: func() (sourcecdk.Source, error) {
			return dixasource.New()
		},
	},
	{
		name: "docebo",
		load: func() (sourcecdk.Source, error) {
			return docebosource.New()
		},
	},
	{
		name: "docker_hub",
		load: func() (sourcecdk.Source, error) {
			return dockerhubsource.New()
		},
	},
	{
		name: "document360",
		load: func() (sourcecdk.Source, error) {
			return document360source.New()
		},
	},
	{
		name: "docusign",
		load: func() (sourcecdk.Source, error) {
			return docusignsource.New()
		},
	},
	{
		name: "domo",
		load: func() (sourcecdk.Source, error) {
			return domosource.New()
		},
	},
	{
		name: "doppler",
		load: func() (sourcecdk.Source, error) {
			return dopplersource.New()
		},
	},
	{
		name: "dracoon",
		load: func() (sourcecdk.Source, error) {
			return dracoonsource.New()
		},
	},
	{
		name: "dragos_worldview",
		load: func() (sourcecdk.Source, error) {
			return dragosworldviewsource.New()
		},
	},
	{
		name: "drata",
		load: func() (sourcecdk.Source, error) {
			return dratasource.New()
		},
	},
	{
		name: "drchrono",
		load: func() (sourcecdk.Source, error) {
			return drchronosource.New()
		},
	},
	{
		name: "drift",
		load: func() (sourcecdk.Source, error) {
			return driftsource.New()
		},
	},
	{
		name: "drone_cloud",
		load: func() (sourcecdk.Source, error) {
			return dronecloudsource.New()
		},
	},
	{
		name: "dropbox_business",
		load: func() (sourcecdk.Source, error) {
			return dropboxbusinesssource.New()
		},
	},
	{
		name: "dropbox_sign",
		load: func() (sourcecdk.Source, error) {
			return dropboxsignsource.New()
		},
	},
	{
		name: "duo",
		load: func() (sourcecdk.Source, error) {
			return duosource.New()
		},
	},
	{
		name: "duo_security",
		load: func() (sourcecdk.Source, error) {
			return duosecuritysource.New()
		},
	},
	{
		name: "dynamics_365_sales",
		load: func() (sourcecdk.Source, error) {
			return dynamics365salessource.New()
		},
	},
	{
		name: "dynatrace",
		load: func() (sourcecdk.Source, error) {
			return dynatracesource.New()
		},
	},
	{
		name: "easyllama",
		load: func() (sourcecdk.Source, error) {
			return easyllamasource.New()
		},
	},
	{
		name: "eclypsium",
		load: func() (sourcecdk.Source, error) {
			return eclypsiumsource.New()
		},
	},
	{
		name: "egnyte",
		load: func() (sourcecdk.Source, error) {
			return egnytesource.New()
		},
	},
	{
		name: "elastic_cloud",
		load: func() (sourcecdk.Source, error) {
			return elasticcloudsource.New()
		},
	},
	{
		name: "elastic_security",
		load: func() (sourcecdk.Source, error) {
			return elasticsecuritysource.New()
		},
	},
	{
		name: "elevenlabs",
		load: func() (sourcecdk.Source, error) {
			return elevenlabssource.New()
		},
	},
	{
		name: "elmah",
		load: func() (sourcecdk.Source, error) {
			return elmahsource.New()
		},
	},
	{
		name: "emaildomainhealth",
		load: func() (sourcecdk.Source, error) {
			return emaildomainhealthsource.New()
		},
	},
	{
		name: "endor_labs",
		load: func() (sourcecdk.Source, error) {
			return endorlabssource.New()
		},
	},
	{
		name: "env0",
		load: func() (sourcecdk.Source, error) {
			return env0source.New()
		},
	},
	{
		name: "envkey",
		load: func() (sourcecdk.Source, error) {
			return envkeysource.New()
		},
	},
	{
		name: "envoy",
		load: func() (sourcecdk.Source, error) {
			return envoysource.New()
		},
	},
	{
		name: "envoy_visitors",
		load: func() (sourcecdk.Source, error) {
			return envoyvisitorssource.New()
		},
	},
	{
		name: "ethena",
		load: func() (sourcecdk.Source, error) {
			return ethenasource.New()
		},
	},
	{
		name: "everlaw",
		load: func() (sourcecdk.Source, error) {
			return everlawsource.New()
		},
	},
	{
		name: "evernote_teams",
		load: func() (sourcecdk.Source, error) {
			return evernoteteamssource.New()
		},
	},
	{
		name: "evidencecas",
		load: func() (sourcecdk.Source, error) {
			return evidencecassource.New()
		},
	},
	{
		name: "evisort",
		load: func() (sourcecdk.Source, error) {
			return evisortsource.New()
		},
	},
	{
		name: "exavault",
		load: func() (sourcecdk.Source, error) {
			return exavaultsource.New()
		},
	},
	{
		name: "expel",
		load: func() (sourcecdk.Source, error) {
			return expelsource.New()
		},
	},
	{
		name: "expensify",
		load: func() (sourcecdk.Source, error) {
			return expensifysource.New()
		},
	},
	{
		name: "fairmarkit",
		load: func() (sourcecdk.Source, error) {
			return fairmarkitsource.New()
		},
	},
	{
		name: "faros_ai",
		load: func() (sourcecdk.Source, error) {
			return farosaisource.New()
		},
	},
	{
		name: "fastly",
		load: func() (sourcecdk.Source, error) {
			return fastlysource.New()
		},
	},
	{
		name: "fathom_video",
		load: func() (sourcecdk.Source, error) {
			return fathomvideosource.New()
		},
	},
	{
		name: "featurebase",
		load: func() (sourcecdk.Source, error) {
			return featurebasesource.New()
		},
	},
	{
		name: "fifteenfive",
		load: func() (sourcecdk.Source, error) {
			return fifteenfivesource.New()
		},
	},
	{
		name: "figma",
		load: func() (sourcecdk.Source, error) {
			return figmasource.New()
		},
	},
	{
		name: "files_com",
		load: func() (sourcecdk.Source, error) {
			return filescomsource.New()
		},
	},
	{
		name: "fire",
		load: func() (sourcecdk.Source, error) {
			return firesource.New()
		},
	},
	{
		name: "fireflies_ai",
		load: func() (sourcecdk.Source, error) {
			return firefliesaisource.New()
		},
	},
	{
		name: "firefly",
		load: func() (sourcecdk.Source, error) {
			return fireflysource.New()
		},
	},
	{
		name: "firehydrant",
		load: func() (sourcecdk.Source, error) {
			return firehydrantsource.New()
		},
	},
	{
		name: "fireworks_ai",
		load: func() (sourcecdk.Source, error) {
			return fireworksaisource.New()
		},
	},
	{
		name: "firmalyzer",
		load: func() (sourcecdk.Source, error) {
			return firmalyzersource.New()
		},
	},
	{
		name: "five9",
		load: func() (sourcecdk.Source, error) {
			return five9source.New()
		},
	},
	{
		name: "fivetran",
		load: func() (sourcecdk.Source, error) {
			return fivetransource.New()
		},
	},
	{
		name: "flagsmith_cloud",
		load: func() (sourcecdk.Source, error) {
			return flagsmithcloudsource.New()
		},
	},
	{
		name: "fleetdm",
		load: func() (sourcecdk.Source, error) {
			return fleetdmsource.New()
		},
	},
	{
		name: "forethought",
		load: func() (sourcecdk.Source, error) {
			return forethoughtsource.New()
		},
	},
	{
		name: "formstack",
		load: func() (sourcecdk.Source, error) {
			return formstacksource.New()
		},
	},
	{
		name: "foxpass",
		load: func() (sourcecdk.Source, error) {
			return foxpasssource.New()
		},
	},
	{
		name: "freshbooks",
		load: func() (sourcecdk.Source, error) {
			return freshbookssource.New()
		},
	},
	{
		name: "freshdesk",
		load: func() (sourcecdk.Source, error) {
			return freshdesksource.New()
		},
	},
	{
		name: "freshsales",
		load: func() (sourcecdk.Source, error) {
			return freshsalessource.New()
		},
	},
	{
		name: "freshservice",
		load: func() (sourcecdk.Source, error) {
			return freshservicesource.New()
		},
	},
	{
		name: "front",
		load: func() (sourcecdk.Source, error) {
			return frontsource.New()
		},
	},
	{
		name: "frontegg",
		load: func() (sourcecdk.Source, error) {
			return fronteggsource.New()
		},
	},
	{
		name: "frontify",
		load: func() (sourcecdk.Source, error) {
			return frontifysource.New()
		},
	},
	{
		name: "fulfillment_com",
		load: func() (sourcecdk.Source, error) {
			return fulfillmentcomsource.New()
		},
	},
	{
		name: "fullstory",
		load: func() (sourcecdk.Source, error) {
			return fullstorysource.New()
		},
	},
	{
		name: "fusionauth",
		load: func() (sourcecdk.Source, error) {
			return fusionauthsource.New()
		},
	},
	{
		name: "gainsight",
		load: func() (sourcecdk.Source, error) {
			return gainsightsource.New()
		},
	},
	{
		name: "gcp",
		load: func() (sourcecdk.Source, error) {
			return gcpsource.New()
		},
	},
	{
		name: "gem",
		load: func() (sourcecdk.Source, error) {
			return gemsource.New()
		},
	},
	{
		name: "genesys_cloud",
		load: func() (sourcecdk.Source, error) {
			return genesyscloudsource.New()
		},
	},
	{
		name: "gitbook",
		load: func() (sourcecdk.Source, error) {
			return gitbooksource.New()
		},
	},
	{
		name: "gitea",
		load: func() (sourcecdk.Source, error) {
			return giteasource.New()
		},
	},
	{
		name: "gitguardian",
		load: func() (sourcecdk.Source, error) {
			return gitguardiansource.New()
		},
	},
	{
		name: "gitguardian_secrets",
		load: func() (sourcecdk.Source, error) {
			return gitguardiansecretssource.New()
		},
	},
	{
		name: "github",
		load: func() (sourcecdk.Source, error) {
			return githubsource.New()
		},
	},
	{
		name: "gitlab",
		load: func() (sourcecdk.Source, error) {
			return gitlabsource.New()
		},
	},
	{
		name: "gitpod",
		load: func() (sourcecdk.Source, error) {
			return gitpodsource.New()
		},
	},
	{
		name: "gladly",
		load: func() (sourcecdk.Source, error) {
			return gladlysource.New()
		},
	},
	{
		name: "gocd",
		load: func() (sourcecdk.Source, error) {
			return gocdsource.New()
		},
	},
	{
		name: "godaddy",
		load: func() (sourcecdk.Source, error) {
			return godaddysource.New()
		},
	},
	{
		name: "gong",
		load: func() (sourcecdk.Source, error) {
			return gongsource.New()
		},
	},
	{
		name: "google_analytics_360",
		load: func() (sourcecdk.Source, error) {
			return googleanalytics360source.New()
		},
	},
	{
		name: "google_drive",
		load: func() (sourcecdk.Source, error) {
			return googledrivesource.New()
		},
	},
	{
		name: "google_gemini",
		load: func() (sourcecdk.Source, error) {
			return googlegeminisource.New()
		},
	},
	{
		name: "google_play_console",
		load: func() (sourcecdk.Source, error) {
			return googleplayconsolesource.New()
		},
	},
	{
		name: "google_secops_chronicle",
		load: func() (sourcecdk.Source, error) {
			return googlesecopschroniclesource.New()
		},
	},
	{
		name: "google_vertex_ai",
		load: func() (sourcecdk.Source, error) {
			return googlevertexaisource.New()
		},
	},
	{
		name: "googleworkspace",
		load: func() (sourcecdk.Source, error) {
			return googleworkspacesource.New()
		},
	},
	{
		name: "gorgias",
		load: func() (sourcecdk.Source, error) {
			return gorgiassource.New()
		},
	},
	{
		name: "grafana_cloud",
		load: func() (sourcecdk.Source, error) {
			return grafanacloudsource.New()
		},
	},
	{
		name: "grain",
		load: func() (sourcecdk.Source, error) {
			return grainsource.New()
		},
	},
	{
		name: "grammarly_business",
		load: func() (sourcecdk.Source, error) {
			return grammarlybusinesssource.New()
		},
	},
	{
		name: "gravitee_cloud",
		load: func() (sourcecdk.Source, error) {
			return graviteecloudsource.New()
		},
	},
	{
		name: "grc",
		load: func() (sourcecdk.Source, error) {
			return grcsource.New()
		},
	},
	{
		name: "greenhouse",
		load: func() (sourcecdk.Source, error) {
			return greenhousesource.New()
		},
	},
	{
		name: "greythr",
		load: func() (sourcecdk.Source, error) {
			return greythrsource.New()
		},
	},
	{
		name: "grip_security",
		load: func() (sourcecdk.Source, error) {
			return gripsecuritysource.New()
		},
	},
	{
		name: "groq",
		load: func() (sourcecdk.Source, error) {
			return groqsource.New()
		},
	},
	{
		name: "groundcover",
		load: func() (sourcecdk.Source, error) {
			return groundcoversource.New()
		},
	},
	{
		name: "gsmtasks",
		load: func() (sourcecdk.Source, error) {
			return gsmtaskssource.New()
		},
	},
	{
		name: "guru",
		load: func() (sourcecdk.Source, error) {
			return gurusource.New()
		},
	},
	{
		name: "gusto",
		load: func() (sourcecdk.Source, error) {
			return gustosource.New()
		},
	},
	{
		name: "hackerone",
		load: func() (sourcecdk.Source, error) {
			return hackeronesource.New()
		},
	},
	{
		name: "hadrian_security",
		load: func() (sourcecdk.Source, error) {
			return hadriansecuritysource.New()
		},
	},
	{
		name: "harness",
		load: func() (sourcecdk.Source, error) {
			return harnesssource.New()
		},
	},
	{
		name: "harness_platform",
		load: func() (sourcecdk.Source, error) {
			return harnessplatformsource.New()
		},
	},
	{
		name: "hashicorp_vault",
		load: func() (sourcecdk.Source, error) {
			return hashicorpvaultsource.New()
		},
	},
	{
		name: "haveibeenpwned",
		load: func() (sourcecdk.Source, error) {
			return haveibeenpwnedsource.New()
		},
	},
	{
		name: "healthchecks",
		load: func() (sourcecdk.Source, error) {
			return healthcheckssource.New()
		},
	},
	{
		name: "heap",
		load: func() (sourcecdk.Source, error) {
			return heapsource.New()
		},
	},
	{
		name: "helpscout",
		load: func() (sourcecdk.Source, error) {
			return helpscoutsource.New()
		},
	},
	{
		name: "heroku",
		load: func() (sourcecdk.Source, error) {
			return herokusource.New()
		},
	},
	{
		name: "hetzner",
		load: func() (sourcecdk.Source, error) {
			return hetznersource.New()
		},
	},
	{
		name: "hevo_data",
		load: func() (sourcecdk.Source, error) {
			return hevodatasource.New()
		},
	},
	{
		name: "hexnode",
		load: func() (sourcecdk.Source, error) {
			return hexnodesource.New()
		},
	},
	{
		name: "hibob",
		load: func() (sourcecdk.Source, error) {
			return hibobsource.New()
		},
	},
	{
		name: "hid_workforce_identity",
		load: func() (sourcecdk.Source, error) {
			return hidworkforceidentitysource.New()
		},
	},
	{
		name: "highlight",
		load: func() (sourcecdk.Source, error) {
			return highlightsource.New()
		},
	},
	{
		name: "highspot",
		load: func() (sourcecdk.Source, error) {
			return highspotsource.New()
		},
	},
	{
		name: "hightail",
		load: func() (sourcecdk.Source, error) {
			return hightailsource.New()
		},
	},
	{
		name: "hightouch",
		load: func() (sourcecdk.Source, error) {
			return hightouchsource.New()
		},
	},
	{
		name: "hitrust_mycsf",
		load: func() (sourcecdk.Source, error) {
			return hitrustmycsfsource.New()
		},
	},
	{
		name: "hive",
		load: func() (sourcecdk.Source, error) {
			return hivesource.New()
		},
	},
	{
		name: "holm_security",
		load: func() (sourcecdk.Source, error) {
			return holmsecuritysource.New()
		},
	},
	{
		name: "honeybadger",
		load: func() (sourcecdk.Source, error) {
			return honeybadgersource.New()
		},
	},
	{
		name: "honeycomb",
		load: func() (sourcecdk.Source, error) {
			return honeycombsource.New()
		},
	},
	{
		name: "hotjar",
		load: func() (sourcecdk.Source, error) {
			return hotjarsource.New()
		},
	},
	{
		name: "hubspot",
		load: func() (sourcecdk.Source, error) {
			return hubspotsource.New()
		},
	},
	{
		name: "hudsonrock",
		load: func() (sourcecdk.Source, error) {
			return hudsonrocksource.New()
		},
	},
	{
		name: "huggingface",
		load: func() (sourcecdk.Source, error) {
			return huggingfacesource.New()
		},
	},
	{
		name: "huntr",
		load: func() (sourcecdk.Source, error) {
			return huntrsource.New()
		},
	},
	{
		name: "hyperdx",
		load: func() (sourcecdk.Source, error) {
			return hyperdxsource.New()
		},
	},
	{
		name: "hyperproof",
		load: func() (sourcecdk.Source, error) {
			return hyperproofsource.New()
		},
	},
	{
		name: "ibm_randori",
		load: func() (sourcecdk.Source, error) {
			return ibmrandorisource.New()
		},
	},
	{
		name: "ibm_watsonx_ai",
		load: func() (sourcecdk.Source, error) {
			return ibmwatsonxaisource.New()
		},
	},
	{
		name: "icertis",
		load: func() (sourcecdk.Source, error) {
			return icertissource.New()
		},
	},
	{
		name: "icims",
		load: func() (sourcecdk.Source, error) {
			return icimssource.New()
		},
	},
	{
		name: "ilert",
		load: func() (sourcecdk.Source, error) {
			return ilertsource.New()
		},
	},
	{
		name: "illumidesk",
		load: func() (sourcecdk.Source, error) {
			return illumidesksource.New()
		},
	},
	{
		name: "imanage_cloud",
		load: func() (sourcecdk.Source, error) {
			return imanagecloudsource.New()
		},
	},
	{
		name: "immuta",
		load: func() (sourcecdk.Source, error) {
			return immutasource.New()
		},
	},
	{
		name: "imprivata",
		load: func() (sourcecdk.Source, error) {
			return imprivatasource.New()
		},
	},
	{
		name: "incident_io",
		load: func() (sourcecdk.Source, error) {
			return incidentiosource.New()
		},
	},
	{
		name: "increase",
		load: func() (sourcecdk.Source, error) {
			return increasesource.New()
		},
	},
	{
		name: "infisical",
		load: func() (sourcecdk.Source, error) {
			return infisicalsource.New()
		},
	},
	{
		name: "influxdata",
		load: func() (sourcecdk.Source, error) {
			return influxdatasource.New()
		},
	},
	{
		name: "insomnia_cloud",
		load: func() (sourcecdk.Source, error) {
			return insomniacloudsource.New()
		},
	},
	{
		name: "intercom",
		load: func() (sourcecdk.Source, error) {
			return intercomsource.New()
		},
	},
	{
		name: "intruder",
		load: func() (sourcecdk.Source, error) {
			return intrudersource.New()
		},
	},
	{
		name: "invicti",
		load: func() (sourcecdk.Source, error) {
			return invictisource.New()
		},
	},
	{
		name: "iqualify",
		load: func() (sourcecdk.Source, error) {
			return iqualifysource.New()
		},
	},
	{
		name: "ironclad",
		load: func() (sourcecdk.Source, error) {
			return ironcladsource.New()
		},
	},
	{
		name: "island",
		load: func() (sourcecdk.Source, error) {
			return islandsource.New()
		},
	},
	{
		name: "iterable",
		load: func() (sourcecdk.Source, error) {
			return iterablesource.New()
		},
	},
	{
		name: "jamf_pro",
		load: func() (sourcecdk.Source, error) {
			return jamfprosource.New()
		},
	},
	{
		name: "jamf_protect",
		load: func() (sourcecdk.Source, error) {
			return jamfprotectsource.New()
		},
	},
	{
		name: "jenkins",
		load: func() (sourcecdk.Source, error) {
			return jenkinssource.New()
		},
	},
	{
		name: "jetbrains_space",
		load: func() (sourcecdk.Source, error) {
			return jetbrainsspacesource.New()
		},
	},
	{
		name: "jfrog_artifactory",
		load: func() (sourcecdk.Source, error) {
			return jfrogartifactorysource.New()
		},
	},
	{
		name: "jfrog_artifactory_xray",
		load: func() (sourcecdk.Source, error) {
			return jfrogartifactoryxraysource.New()
		},
	},
	{
		name: "jfrog_xray",
		load: func() (sourcecdk.Source, error) {
			return jfrogxraysource.New()
		},
	},
	{
		name: "jira",
		load: func() (sourcecdk.Source, error) {
			return jirasource.New()
		},
	},
	{
		name: "journy_io",
		load: func() (sourcecdk.Source, error) {
			return journyiosource.New()
		},
	},
	{
		name: "jumpcloud",
		load: func() (sourcecdk.Source, error) {
			return jumpcloudsource.New()
		},
	},
	{
		name: "jumpseller",
		load: func() (sourcecdk.Source, error) {
			return jumpsellersource.New()
		},
	},
	{
		name: "justworks",
		load: func() (sourcecdk.Source, error) {
			return justworkssource.New()
		},
	},
	{
		name: "k6_cloud",
		load: func() (sourcecdk.Source, error) {
			return k6cloudsource.New()
		},
	},
	{
		name: "kandji",
		load: func() (sourcecdk.Source, error) {
			return kandjisource.New()
		},
	},
	{
		name: "keeper",
		load: func() (sourcecdk.Source, error) {
			return keepersource.New()
		},
	},
	{
		name: "keeper_security",
		load: func() (sourcecdk.Source, error) {
			return keepersecuritysource.New()
		},
	},
	{
		name: "kenna_security",
		load: func() (sourcecdk.Source, error) {
			return kennasecuritysource.New()
		},
	},
	{
		name: "kentik",
		load: func() (sourcecdk.Source, error) {
			return kentiksource.New()
		},
	},
	{
		name: "keycloak",
		load: func() (sourcecdk.Source, error) {
			return keycloaksource.New()
		},
	},
	{
		name: "klaviyo",
		load: func() (sourcecdk.Source, error) {
			return klaviyosource.New()
		},
	},
	{
		name: "knowbe4",
		load: func() (sourcecdk.Source, error) {
			return knowbe4source.New()
		},
	},
	{
		name: "kolide",
		load: func() (sourcecdk.Source, error) {
			return kolidesource.New()
		},
	},
	{
		name: "kong_konnect",
		load: func() (sourcecdk.Source, error) {
			return kongkonnectsource.New()
		},
	},
	{
		name: "kubernetes",
		load: func() (sourcecdk.Source, error) {
			return kubernetessource.New()
		},
	},
	{
		name: "kustomer",
		load: func() (sourcecdk.Source, error) {
			return kustomersource.New()
		},
	},
	{
		name: "lacework",
		load: func() (sourcecdk.Source, error) {
			return laceworksource.New()
		},
	},
	{
		name: "lambdatest",
		load: func() (sourcecdk.Source, error) {
			return lambdatestsource.New()
		},
	},
	{
		name: "laminar_security",
		load: func() (sourcecdk.Source, error) {
			return laminarsecuritysource.New()
		},
	},
	{
		name: "langchain",
		load: func() (sourcecdk.Source, error) {
			return langchainsource.New()
		},
	},
	{
		name: "langfuse",
		load: func() (sourcecdk.Source, error) {
			return langfusesource.New()
		},
	},
	{
		name: "last9",
		load: func() (sourcecdk.Source, error) {
			return last9source.New()
		},
	},
	{
		name: "lastpass_business",
		load: func() (sourcecdk.Source, error) {
			return lastpassbusinesssource.New()
		},
	},
	{
		name: "lattice",
		load: func() (sourcecdk.Source, error) {
			return latticesource.New()
		},
	},
	{
		name: "launchdarkly",
		load: func() (sourcecdk.Source, error) {
			return launchdarklysource.New()
		},
	},
	{
		name: "leapsome",
		load: func() (sourcecdk.Source, error) {
			return leapsomesource.New()
		},
	},
	{
		name: "learnifier",
		load: func() (sourcecdk.Source, error) {
			return learnifiersource.New()
		},
	},
	{
		name: "legit_security",
		load: func() (sourcecdk.Source, error) {
			return legitsecuritysource.New()
		},
	},
	{
		name: "lessonly",
		load: func() (sourcecdk.Source, error) {
			return lessonlysource.New()
		},
	},
	{
		name: "lever",
		load: func() (sourcecdk.Source, error) {
			return leversource.New()
		},
	},
	{
		name: "lightstep",
		load: func() (sourcecdk.Source, error) {
			return lightstepsource.New()
		},
	},
	{
		name: "linear",
		load: func() (sourcecdk.Source, error) {
			return linearsource.New()
		},
	},
	{
		name: "linksquares",
		load: func() (sourcecdk.Source, error) {
			return linksquaressource.New()
		},
	},
	{
		name: "linode",
		load: func() (sourcecdk.Source, error) {
			return linodesource.New()
		},
	},
	{
		name: "livestorm",
		load: func() (sourcecdk.Source, error) {
			return livestormsource.New()
		},
	},
	{
		name: "logicgate",
		load: func() (sourcecdk.Source, error) {
			return logicgatesource.New()
		},
	},
	{
		name: "logicmonitor",
		load: func() (sourcecdk.Source, error) {
			return logicmonitorsource.New()
		},
	},
	{
		name: "logrocket",
		load: func() (sourcecdk.Source, error) {
			return logrocketsource.New()
		},
	},
	{
		name: "logz_io",
		load: func() (sourcecdk.Source, error) {
			return logziosource.New()
		},
	},
	{
		name: "loket",
		load: func() (sourcecdk.Source, error) {
			return loketsource.New()
		},
	},
	{
		name: "looker",
		load: func() (sourcecdk.Source, error) {
			return lookersource.New()
		},
	},
	{
		name: "loom",
		load: func() (sourcecdk.Source, error) {
			return loomsource.New()
		},
	},
	{
		name: "lucidchart",
		load: func() (sourcecdk.Source, error) {
			return lucidchartsource.New()
		},
	},
	{
		name: "lucidscale",
		load: func() (sourcecdk.Source, error) {
			return lucidscalesource.New()
		},
	},
	{
		name: "lumos_identity",
		load: func() (sourcecdk.Source, error) {
			return lumosidentitysource.New()
		},
	},
	{
		name: "mabl",
		load: func() (sourcecdk.Source, error) {
			return mablsource.New()
		},
	},
	{
		name: "magento",
		load: func() (sourcecdk.Source, error) {
			return magentosource.New()
		},
	},
	{
		name: "mailchimp",
		load: func() (sourcecdk.Source, error) {
			return mailchimpsource.New()
		},
	},
	{
		name: "mailscript",
		load: func() (sourcecdk.Source, error) {
			return mailscriptsource.New()
		},
	},
	{
		name: "manageengine_endpoint_central",
		load: func() (sourcecdk.Source, error) {
			return manageengineendpointcentralsource.New()
		},
	},
	{
		name: "mandiant_advantage",
		load: func() (sourcecdk.Source, error) {
			return mandiantadvantagesource.New()
		},
	},
	{
		name: "marketo",
		load: func() (sourcecdk.Source, error) {
			return marketosource.New()
		},
	},
	{
		name: "mastodon",
		load: func() (sourcecdk.Source, error) {
			return mastodonsource.New()
		},
	},
	{
		name: "material_security",
		load: func() (sourcecdk.Source, error) {
			return materialsecuritysource.New()
		},
	},
	{
		name: "matillion",
		load: func() (sourcecdk.Source, error) {
			return matillionsource.New()
		},
	},
	{
		name: "maxio",
		load: func() (sourcecdk.Source, error) {
			return maxiosource.New()
		},
	},
	{
		name: "meistertask",
		load: func() (sourcecdk.Source, error) {
			return meistertasksource.New()
		},
	},
	{
		name: "mend_io",
		load: func() (sourcecdk.Source, error) {
			return mendiosource.New()
		},
	},
	{
		name: "mentimeter",
		load: func() (sourcecdk.Source, error) {
			return mentimetersource.New()
		},
	},
	{
		name: "meraki",
		load: func() (sourcecdk.Source, error) {
			return merakisource.New()
		},
	},
	{
		name: "mercury",
		load: func() (sourcecdk.Source, error) {
			return mercurysource.New()
		},
	},
	{
		name: "mesh_payments",
		load: func() (sourcecdk.Source, error) {
			return meshpaymentssource.New()
		},
	},
	{
		name: "metaplane",
		load: func() (sourcecdk.Source, error) {
			return metaplanesource.New()
		},
	},
	{
		name: "mezmo",
		load: func() (sourcecdk.Source, error) {
			return mezmosource.New()
		},
	},
	{
		name: "microsoft_365",
		load: func() (sourcecdk.Source, error) {
			return microsoft365source.New()
		},
	},
	{
		name: "microsoft_defender_for_cloud",
		load: func() (sourcecdk.Source, error) {
			return microsoftdefenderforcloudsource.New()
		},
	},
	{
		name: "microsoft_defender_for_cloud_apps",
		load: func() (sourcecdk.Source, error) {
			return microsoftdefenderforcloudappssource.New()
		},
	},
	{
		name: "microsoft_defender_for_endpoint",
		load: func() (sourcecdk.Source, error) {
			return microsoftdefenderforendpointsource.New()
		},
	},
	{
		name: "microsoft_entra_id",
		load: func() (sourcecdk.Source, error) {
			return microsoftentraidsource.New()
		},
	},
	{
		name: "microsoft_foundry",
		load: func() (sourcecdk.Source, error) {
			return microsoftfoundrysource.New()
		},
	},
	{
		name: "microsoft_sentinel",
		load: func() (sourcecdk.Source, error) {
			return microsoftsentinelsource.New()
		},
	},
	{
		name: "microsoft_teams",
		load: func() (sourcecdk.Source, error) {
			return microsoftteamssource.New()
		},
	},
	{
		name: "mimecast",
		load: func() (sourcecdk.Source, error) {
			return mimecastsource.New()
		},
	},
	{
		name: "miradore",
		load: func() (sourcecdk.Source, error) {
			return miradoresource.New()
		},
	},
	{
		name: "miro",
		load: func() (sourcecdk.Source, error) {
			return mirosource.New()
		},
	},
	{
		name: "mist",
		load: func() (sourcecdk.Source, error) {
			return mistsource.New()
		},
	},
	{
		name: "mistral",
		load: func() (sourcecdk.Source, error) {
			return mistralsource.New()
		},
	},
	{
		name: "mobileiron",
		load: func() (sourcecdk.Source, error) {
			return mobileironsource.New()
		},
	},
	{
		name: "mode_analytics",
		load: func() (sourcecdk.Source, error) {
			return modeanalyticssource.New()
		},
	},
	{
		name: "monday_com",
		load: func() (sourcecdk.Source, error) {
			return mondaycomsource.New()
		},
	},
	{
		name: "mongodb_atlas",
		load: func() (sourcecdk.Source, error) {
			return mongodbatlassource.New()
		},
	},
	{
		name: "monte_carlo_data",
		load: func() (sourcecdk.Source, error) {
			return montecarlodatasource.New()
		},
	},
	{
		name: "moogsoft",
		load: func() (sourcecdk.Source, error) {
			return moogsoftsource.New()
		},
	},
	{
		name: "mosyle",
		load: func() (sourcecdk.Source, error) {
			return mosylesource.New()
		},
	},
	{
		name: "motaword",
		load: func() (sourcecdk.Source, error) {
			return motawordsource.New()
		},
	},
	{
		name: "mparticle",
		load: func() (sourcecdk.Source, error) {
			return mparticlesource.New()
		},
	},
	{
		name: "mulesoft_anypoint",
		load: func() (sourcecdk.Source, error) {
			return mulesoftanypointsource.New()
		},
	},
	{
		name: "multiplier",
		load: func() (sourcecdk.Source, error) {
			return multipliersource.New()
		},
	},
	{
		name: "mural",
		load: func() (sourcecdk.Source, error) {
			return muralsource.New()
		},
	},
	{
		name: "n_auth",
		load: func() (sourcecdk.Source, error) {
			return nauthsource.New()
		},
	},
	{
		name: "namely",
		load: func() (sourcecdk.Source, error) {
			return namelysource.New()
		},
	},
	{
		name: "navan",
		load: func() (sourcecdk.Source, error) {
			return navansource.New()
		},
	},
	{
		name: "netboxdemo",
		load: func() (sourcecdk.Source, error) {
			return netboxdemosource.New()
		},
	},
	{
		name: "netdocuments",
		load: func() (sourcecdk.Source, error) {
			return netdocumentssource.New()
		},
	},
	{
		name: "netlicensing",
		load: func() (sourcecdk.Source, error) {
			return netlicensingsource.New()
		},
	},
	{
		name: "netlify",
		load: func() (sourcecdk.Source, error) {
			return netlifysource.New()
		},
	},
	{
		name: "netskope",
		load: func() (sourcecdk.Source, error) {
			return netskopesource.New()
		},
	},
	{
		name: "netspi_platform",
		load: func() (sourcecdk.Source, error) {
			return netspiplatformsource.New()
		},
	},
	{
		name: "netsuite",
		load: func() (sourcecdk.Source, error) {
			return netsuitesource.New()
		},
	},
	{
		name: "neutrinoapi",
		load: func() (sourcecdk.Source, error) {
			return neutrinoapisource.New()
		},
	},
	{
		name: "new_relic",
		load: func() (sourcecdk.Source, error) {
			return newrelicsource.New()
		},
	},
	{
		name: "nice_cxone",
		load: func() (sourcecdk.Source, error) {
			return nicecxonesource.New()
		},
	},
	{
		name: "noetic_cyber",
		load: func() (sourcecdk.Source, error) {
			return noeticcybersource.New()
		},
	},
	{
		name: "noname_security",
		load: func() (sourcecdk.Source, error) {
			return nonamesecuritysource.New()
		},
	},
	{
		name: "noosh",
		load: func() (sourcecdk.Source, error) {
			return nooshsource.New()
		},
	},
	{
		name: "nordigen",
		load: func() (sourcecdk.Source, error) {
			return nordigensource.New()
		},
	},
	{
		name: "nordlayer",
		load: func() (sourcecdk.Source, error) {
			return nordlayersource.New()
		},
	},
	{
		name: "normalyze",
		load: func() (sourcecdk.Source, error) {
			return normalyzesource.New()
		},
	},
	{
		name: "notion",
		load: func() (sourcecdk.Source, error) {
			return notionsource.New()
		},
	},
	{
		name: "nucleus_security",
		load: func() (sourcecdk.Source, error) {
			return nucleussecuritysource.New()
		},
	},
	{
		name: "nuclino",
		load: func() (sourcecdk.Source, error) {
			return nuclinosource.New()
		},
	},
	{
		name: "nudge_security",
		load: func() (sourcecdk.Source, error) {
			return nudgesecuritysource.New()
		},
	},
	{
		name: "observe_platform",
		load: func() (sourcecdk.Source, error) {
			return observeplatformsource.New()
		},
	},
	{
		name: "obsidian_security",
		load: func() (sourcecdk.Source, error) {
			return obsidiansecuritysource.New()
		},
	},
	{
		name: "octopus_deploy",
		load: func() (sourcecdk.Source, error) {
			return octopusdeploysource.New()
		},
	},
	{
		name: "office_space",
		load: func() (sourcecdk.Source, error) {
			return officespacesource.New()
		},
	},
	{
		name: "okta",
		load: func() (sourcecdk.Source, error) {
			return oktasource.New()
		},
	},
	{
		name: "omada_identity",
		load: func() (sourcecdk.Source, error) {
			return omadaidentitysource.New()
		},
	},
	{
		name: "omni_analytics",
		load: func() (sourcecdk.Source, error) {
			return omnianalyticssource.New()
		},
	},
	{
		name: "onelogin",
		load: func() (sourcecdk.Source, error) {
			return oneloginsource.New()
		},
	},
	{
		name: "onepassword_business",
		load: func() (sourcecdk.Source, error) {
			return onepasswordbusinesssource.New()
		},
	},
	{
		name: "onetrust",
		load: func() (sourcecdk.Source, error) {
			return onetrustsource.New()
		},
	},
	{
		name: "opal_security",
		load: func() (sourcecdk.Source, error) {
			return opalsecuritysource.New()
		},
	},
	{
		name: "openai",
		load: func() (sourcecdk.Source, error) {
			return openaisource.New()
		},
	},
	{
		name: "opendatasoft",
		load: func() (sourcecdk.Source, error) {
			return opendatasoftsource.New()
		},
	},
	{
		name: "openfintech",
		load: func() (sourcecdk.Source, error) {
			return openfintechsource.New()
		},
	},
	{
		name: "openpolicy",
		load: func() (sourcecdk.Source, error) {
			return openpolicysource.New()
		},
	},
	{
		name: "openrouter",
		load: func() (sourcecdk.Source, error) {
			return openroutersource.New()
		},
	},
	{
		name: "opsgenie",
		load: func() (sourcecdk.Source, error) {
			return opsgeniesource.New()
		},
	},
	{
		name: "opslevel",
		load: func() (sourcecdk.Source, error) {
			return opslevelsource.New()
		},
	},
	{
		name: "optimizely_feature_experimentation",
		load: func() (sourcecdk.Source, error) {
			return optimizelyfeatureexperimentationsource.New()
		},
	},
	{
		name: "oracle_hcm",
		load: func() (sourcecdk.Source, error) {
			return oraclehcmsource.New()
		},
	},
	{
		name: "orca",
		load: func() (sourcecdk.Source, error) {
			return orcasource.New()
		},
	},
	{
		name: "orca_security",
		load: func() (sourcecdk.Source, error) {
			return orcasecuritysource.New()
		},
	},
	{
		name: "ordway",
		load: func() (sourcecdk.Source, error) {
			return ordwaysource.New()
		},
	},
	{
		name: "osisoft",
		load: func() (sourcecdk.Source, error) {
			return osisoftsource.New()
		},
	},
	{
		name: "otter_ai",
		load: func() (sourcecdk.Source, error) {
			return otteraisource.New()
		},
	},
	{
		name: "outreach",
		load: func() (sourcecdk.Source, error) {
			return outreachsource.New()
		},
	},
	{
		name: "oyster_hr",
		load: func() (sourcecdk.Source, error) {
			return oysterhrsource.New()
		},
	},
	{
		name: "paddle",
		load: func() (sourcecdk.Source, error) {
			return paddlesource.New()
		},
	},
	{
		name: "pagerduty",
		load: func() (sourcecdk.Source, error) {
			return pagerdutysource.New()
		},
	},
	{
		name: "pandadoc",
		load: func() (sourcecdk.Source, error) {
			return pandadocsource.New()
		},
	},
	{
		name: "panopticon",
		load: func() (sourcecdk.Source, error) {
			return panopticonsource.New()
		},
	},
	{
		name: "panther",
		load: func() (sourcecdk.Source, error) {
			return panthersource.New()
		},
	},
	{
		name: "pathlock",
		load: func() (sourcecdk.Source, error) {
			return pathlocksource.New()
		},
	},
	{
		name: "paychex_flex",
		load: func() (sourcecdk.Source, error) {
			return paychexflexsource.New()
		},
	},
	{
		name: "paycom",
		load: func() (sourcecdk.Source, error) {
			return paycomsource.New()
		},
	},
	{
		name: "paylocity",
		load: func() (sourcecdk.Source, error) {
			return paylocitysource.New()
		},
	},
	{
		name: "paylocity_time",
		load: func() (sourcecdk.Source, error) {
			return paylocitytimesource.New()
		},
	},
	{
		name: "pendo",
		load: func() (sourcecdk.Source, error) {
			return pendosource.New()
		},
	},
	{
		name: "perfecto",
		load: func() (sourcecdk.Source, error) {
			return perfectosource.New()
		},
	},
	{
		name: "perforce_helix_cloud",
		load: func() (sourcecdk.Source, error) {
			return perforcehelixcloudsource.New()
		},
	},
	{
		name: "performyard",
		load: func() (sourcecdk.Source, error) {
			return performyardsource.New()
		},
	},
	{
		name: "perimeter81",
		load: func() (sourcecdk.Source, error) {
			return perimeter81source.New()
		},
	},
	{
		name: "permit_io",
		load: func() (sourcecdk.Source, error) {
			return permitiosource.New()
		},
	},
	{
		name: "perplexity",
		load: func() (sourcecdk.Source, error) {
			return perplexitysource.New()
		},
	},
	{
		name: "personio",
		load: func() (sourcecdk.Source, error) {
			return personiosource.New()
		},
	},
	{
		name: "pinecone",
		load: func() (sourcecdk.Source, error) {
			return pineconesource.New()
		},
	},
	{
		name: "pingdom",
		load: func() (sourcecdk.Source, error) {
			return pingdomsource.New()
		},
	},
	{
		name: "pingone",
		load: func() (sourcecdk.Source, error) {
			return pingonesource.New()
		},
	},
	{
		name: "pipedrive",
		load: func() (sourcecdk.Source, error) {
			return pipedrivesource.New()
		},
	},
	{
		name: "pitch",
		load: func() (sourcecdk.Source, error) {
			return pitchsource.New()
		},
	},
	{
		name: "planview_adaptivework",
		load: func() (sourcecdk.Source, error) {
			return planviewadaptiveworksource.New()
		},
	},
	{
		name: "platform_sh",
		load: func() (sourcecdk.Source, error) {
			return platformshsource.New()
		},
	},
	{
		name: "plextrac",
		load: func() (sourcecdk.Source, error) {
			return plextracsource.New()
		},
	},
	{
		name: "portable",
		load: func() (sourcecdk.Source, error) {
			return portablesource.New()
		},
	},
	{
		name: "portainer_cloud",
		load: func() (sourcecdk.Source, error) {
			return portainercloudsource.New()
		},
	},
	{
		name: "portswigger_enterprise",
		load: func() (sourcecdk.Source, error) {
			return portswiggerenterprisesource.New()
		},
	},
	{
		name: "postman",
		load: func() (sourcecdk.Source, error) {
			return postmansource.New()
		},
	},
	{
		name: "postmark",
		load: func() (sourcecdk.Source, error) {
			return postmarksource.New()
		},
	},
	{
		name: "power_bi",
		load: func() (sourcecdk.Source, error) {
			return powerbisource.New()
		},
	},
	{
		name: "prisma_cloud",
		load: func() (sourcecdk.Source, error) {
			return prismacloudsource.New()
		},
	},
	{
		name: "privacera",
		load: func() (sourcecdk.Source, error) {
			return privacerasource.New()
		},
	},
	{
		name: "probely",
		load: func() (sourcecdk.Source, error) {
			return probelysource.New()
		},
	},
	{
		name: "procurify",
		load: func() (sourcecdk.Source, error) {
			return procurifysource.New()
		},
	},
	{
		name: "productboard",
		load: func() (sourcecdk.Source, error) {
			return productboardsource.New()
		},
	},
	{
		name: "productiv",
		load: func() (sourcecdk.Source, error) {
			return productivsource.New()
		},
	},
	{
		name: "proofpoint",
		load: func() (sourcecdk.Source, error) {
			return proofpointsource.New()
		},
	},
	{
		name: "proposify",
		load: func() (sourcecdk.Source, error) {
			return proposifysource.New()
		},
	},
	{
		name: "pulumi_cloud",
		load: func() (sourcecdk.Source, error) {
			return pulumicloudsource.New()
		},
	},
	{
		name: "push_security",
		load: func() (sourcecdk.Source, error) {
			return pushsecuritysource.New()
		},
	},
	{
		name: "qdrant_cloud",
		load: func() (sourcecdk.Source, error) {
			return qdrantcloudsource.New()
		},
	},
	{
		name: "qodo",
		load: func() (sourcecdk.Source, error) {
			return qodosource.New()
		},
	},
	{
		name: "qualtrics",
		load: func() (sourcecdk.Source, error) {
			return qualtricssource.New()
		},
	},
	{
		name: "qualys_vm",
		load: func() (sourcecdk.Source, error) {
			return qualysvmsource.New()
		},
	},
	{
		name: "qualys_vmdr",
		load: func() (sourcecdk.Source, error) {
			return qualysvmdrsource.New()
		},
	},
	{
		name: "quay",
		load: func() (sourcecdk.Source, error) {
			return quaysource.New()
		},
	},
	{
		name: "quickbase",
		load: func() (sourcecdk.Source, error) {
			return quickbasesource.New()
		},
	},
	{
		name: "quickbooks_online",
		load: func() (sourcecdk.Source, error) {
			return quickbooksonlinesource.New()
		},
	},
	{
		name: "quip",
		load: func() (sourcecdk.Source, error) {
			return quipsource.New()
		},
	},
	{
		name: "rally",
		load: func() (sourcecdk.Source, error) {
			return rallysource.New()
		},
	},
	{
		name: "ramp",
		load: func() (sourcecdk.Source, error) {
			return rampsource.New()
		},
	},
	{
		name: "rapid7_insightidr",
		load: func() (sourcecdk.Source, error) {
			return rapid7insightidrsource.New()
		},
	},
	{
		name: "rapid7_insightvm",
		load: func() (sourcecdk.Source, error) {
			return rapid7insightvmsource.New()
		},
	},
	{
		name: "raygun",
		load: func() (sourcecdk.Source, error) {
			return raygunsource.New()
		},
	},
	{
		name: "readme",
		load: func() (sourcecdk.Source, error) {
			return readmesource.New()
		},
	},
	{
		name: "rebilly",
		load: func() (sourcecdk.Source, error) {
			return rebillysource.New()
		},
	},
	{
		name: "recharge",
		load: func() (sourcecdk.Source, error) {
			return rechargesource.New()
		},
	},
	{
		name: "reco_security",
		load: func() (sourcecdk.Source, error) {
			return recosecuritysource.New()
		},
	},
	{
		name: "recorded_future",
		load: func() (sourcecdk.Source, error) {
			return recordedfuturesource.New()
		},
	},
	{
		name: "recurly",
		load: func() (sourcecdk.Source, error) {
			return recurlysource.New()
		},
	},
	{
		name: "red_canary",
		load: func() (sourcecdk.Source, error) {
			return redcanarysource.New()
		},
	},
	{
		name: "redhat",
		load: func() (sourcecdk.Source, error) {
			return redhatsource.New()
		},
	},
	{
		name: "redirection_io",
		load: func() (sourcecdk.Source, error) {
			return redirectioniosource.New()
		},
	},
	{
		name: "relativity_one",
		load: func() (sourcecdk.Source, error) {
			return relativityonesource.New()
		},
	},
	{
		name: "remote_com",
		load: func() (sourcecdk.Source, error) {
			return remotecomsource.New()
		},
	},
	{
		name: "render_cloud",
		load: func() (sourcecdk.Source, error) {
			return rendercloudsource.New()
		},
	},
	{
		name: "replicate",
		load: func() (sourcecdk.Source, error) {
			return replicatesource.New()
		},
	},
	{
		name: "replicated",
		load: func() (sourcecdk.Source, error) {
			return replicatedsource.New()
		},
	},
	{
		name: "resend",
		load: func() (sourcecdk.Source, error) {
			return resendsource.New()
		},
	},
	{
		name: "retool",
		load: func() (sourcecdk.Source, error) {
			return retoolsource.New()
		},
	},
	{
		name: "revenuecat",
		load: func() (sourcecdk.Source, error) {
			return revenuecatsource.New()
		},
	},
	{
		name: "ringcentral",
		load: func() (sourcecdk.Source, error) {
			return ringcentralsource.New()
		},
	},
	{
		name: "rippling",
		load: func() (sourcecdk.Source, error) {
			return ripplingsource.New()
		},
	},
	{
		name: "riskiq",
		load: func() (sourcecdk.Source, error) {
			return riskiqsource.New()
		},
	},
	{
		name: "riskonnect",
		load: func() (sourcecdk.Source, error) {
			return riskonnectsource.New()
		},
	},
	{
		name: "rivery",
		load: func() (sourcecdk.Source, error) {
			return riverysource.New()
		},
	},
	{
		name: "robin",
		load: func() (sourcecdk.Source, error) {
			return robinsource.New()
		},
	},
	{
		name: "rollbar",
		load: func() (sourcecdk.Source, error) {
			return rollbarsource.New()
		},
	},
	{
		name: "rootly",
		load: func() (sourcecdk.Source, error) {
			return rootlysource.New()
		},
	},
	{
		name: "rudderstack",
		load: func() (sourcecdk.Source, error) {
			return rudderstacksource.New()
		},
	},
	{
		name: "runscope",
		load: func() (sourcecdk.Source, error) {
			return runscopesource.New()
		},
	},
	{
		name: "runzero",
		load: func() (sourcecdk.Source, error) {
			return runzerosource.New()
		},
	},
	{
		name: "safe_base",
		load: func() (sourcecdk.Source, error) {
			return safebasesource.New()
		},
	},
	{
		name: "sage_intacct",
		load: func() (sourcecdk.Source, error) {
			return sageintacctsource.New()
		},
	},
	{
		name: "sailpoint_identitynow",
		load: func() (sourcecdk.Source, error) {
			return sailpointidentitynowsource.New()
		},
	},
	{
		name: "sakari",
		load: func() (sourcecdk.Source, error) {
			return sakarisource.New()
		},
	},
	{
		name: "salesforce",
		load: func() (sourcecdk.Source, error) {
			return salesforcesource.New()
		},
	},
	{
		name: "salesforce_cpq",
		load: func() (sourcecdk.Source, error) {
			return salesforcecpqsource.New()
		},
	},
	{
		name: "saleshood",
		load: func() (sourcecdk.Source, error) {
			return saleshoodsource.New()
		},
	},
	{
		name: "salesloft",
		load: func() (sourcecdk.Source, error) {
			return salesloftsource.New()
		},
	},
	{
		name: "salt_security",
		load: func() (sourcecdk.Source, error) {
			return saltsecuritysource.New()
		},
	},
	{
		name: "sauce_labs",
		load: func() (sourcecdk.Source, error) {
			return saucelabssource.New()
		},
	},
	{
		name: "saviynt",
		load: func() (sourcecdk.Source, error) {
			return saviyntsource.New()
		},
	},
	{
		name: "scalefusion",
		load: func() (sourcecdk.Source, error) {
			return scalefusionsource.New()
		},
	},
	{
		name: "scalr",
		load: func() (sourcecdk.Source, error) {
			return scalrsource.New()
		},
	},
	{
		name: "sdk",
		load: func() (sourcecdk.Source, error) {
			return sdksource.New()
		},
	},
	{
		name: "secureframe",
		load: func() (sourcecdk.Source, error) {
			return secureframesource.New()
		},
	},
	{
		name: "securiti",
		load: func() (sourcecdk.Source, error) {
			return securitisource.New()
		},
	},
	{
		name: "securityscorecard",
		load: func() (sourcecdk.Source, error) {
			return securityscorecardsource.New()
		},
	},
	{
		name: "securitytoolingmap",
		load: func() (sourcecdk.Source, error) {
			return securitytoolingmapsource.New()
		},
	},
	{
		name: "securonix",
		load: func() (sourcecdk.Source, error) {
			return securonixsource.New()
		},
	},
	{
		name: "segment",
		load: func() (sourcecdk.Source, error) {
			return segmentsource.New()
		},
	},
	{
		name: "seismic",
		load: func() (sourcecdk.Source, error) {
			return seismicsource.New()
		},
	},
	{
		name: "semaphore_ci",
		load: func() (sourcecdk.Source, error) {
			return semaphorecisource.New()
		},
	},
	{
		name: "semgrep",
		load: func() (sourcecdk.Source, error) {
			return semgrepsource.New()
		},
	},
	{
		name: "sendgrid",
		load: func() (sourcecdk.Source, error) {
			return sendgridsource.New()
		},
	},
	{
		name: "sendoso",
		load: func() (sourcecdk.Source, error) {
			return sendososource.New()
		},
	},
	{
		name: "sentinelone",
		load: func() (sourcecdk.Source, error) {
			return sentinelonesource.New()
		},
	},
	{
		name: "sentra",
		load: func() (sourcecdk.Source, error) {
			return sentrasource.New()
		},
	},
	{
		name: "sentry",
		load: func() (sourcecdk.Source, error) {
			return sentrysource.New()
		},
	},
	{
		name: "servicenow",
		load: func() (sourcecdk.Source, error) {
			return servicenowsource.New()
		},
	},
	{
		name: "servicenow_grc",
		load: func() (sourcecdk.Source, error) {
			return servicenowgrcsource.New()
		},
	},
	{
		name: "sevenrooms",
		load: func() (sourcecdk.Source, error) {
			return sevenroomssource.New()
		},
	},
	{
		name: "sharefile",
		load: func() (sourcecdk.Source, error) {
			return sharefilesource.New()
		},
	},
	{
		name: "shipengine",
		load: func() (sourcecdk.Source, error) {
			return shipenginesource.New()
		},
	},
	{
		name: "shorebird",
		load: func() (sourcecdk.Source, error) {
			return shorebirdsource.New()
		},
	},
	{
		name: "shortcut",
		load: func() (sourcecdk.Source, error) {
			return shortcutsource.New()
		},
	},
	{
		name: "showpad",
		load: func() (sourcecdk.Source, error) {
			return showpadsource.New()
		},
	},
	{
		name: "sigma_computing",
		load: func() (sourcecdk.Source, error) {
			return sigmacomputingsource.New()
		},
	},
	{
		name: "signl4",
		load: func() (sourcecdk.Source, error) {
			return signl4source.New()
		},
	},
	{
		name: "silverfort",
		load: func() (sourcecdk.Source, error) {
			return silverfortsource.New()
		},
	},
	{
		name: "simplemdm",
		load: func() (sourcecdk.Source, error) {
			return simplemdmsource.New()
		},
	},
	{
		name: "sinao",
		load: func() (sourcecdk.Source, error) {
			return sinaosource.New()
		},
	},
	{
		name: "sirionlabs",
		load: func() (sourcecdk.Source, error) {
			return sirionlabssource.New()
		},
	},
	{
		name: "sisense",
		load: func() (sourcecdk.Source, error) {
			return sisensesource.New()
		},
	},
	{
		name: "sixsense",
		load: func() (sourcecdk.Source, error) {
			return sixsensesource.New()
		},
	},
	{
		name: "skedda",
		load: func() (sourcecdk.Source, error) {
			return skeddasource.New()
		},
	},
	{
		name: "skillsoft_percipio",
		load: func() (sourcecdk.Source, error) {
			return skillsoftpercipiosource.New()
		},
	},
	{
		name: "slab",
		load: func() (sourcecdk.Source, error) {
			return slabsource.New()
		},
	},
	{
		name: "slack",
		load: func() (sourcecdk.Source, error) {
			return slacksource.New()
		},
	},
	{
		name: "slideroom",
		load: func() (sourcecdk.Source, error) {
			return slideroomsource.New()
		},
	},
	{
		name: "slite",
		load: func() (sourcecdk.Source, error) {
			return slitesource.New()
		},
	},
	{
		name: "smartrecruiters",
		load: func() (sourcecdk.Source, error) {
			return smartrecruiterssource.New()
		},
	},
	{
		name: "smartsheet",
		load: func() (sourcecdk.Source, error) {
			return smartsheetsource.New()
		},
	},
	{
		name: "smartsuite",
		load: func() (sourcecdk.Source, error) {
			return smartsuitesource.New()
		},
	},
	{
		name: "snowflake",
		load: func() (sourcecdk.Source, error) {
			return snowflakesource.New()
		},
	},
	{
		name: "snyk",
		load: func() (sourcecdk.Source, error) {
			return snyksource.New()
		},
	},
	{
		name: "soda_cloud",
		load: func() (sourcecdk.Source, error) {
			return sodacloudsource.New()
		},
	},
	{
		name: "sonarcloud",
		load: func() (sourcecdk.Source, error) {
			return sonarcloudsource.New()
		},
	},
	{
		name: "sonatype_lifecycle",
		load: func() (sourcecdk.Source, error) {
			return sonatypelifecyclesource.New()
		},
	},
	{
		name: "sonrai_security",
		load: func() (sourcecdk.Source, error) {
			return sonraisecuritysource.New()
		},
	},
	{
		name: "sophos_central",
		load: func() (sourcecdk.Source, error) {
			return sophoscentralsource.New()
		},
	},
	{
		name: "soti_mobicontrol",
		load: func() (sourcecdk.Source, error) {
			return sotimobicontrolsource.New()
		},
	},
	{
		name: "sourcegraph",
		load: func() (sourcecdk.Source, error) {
			return sourcegraphsource.New()
		},
	},
	{
		name: "sourcewhale",
		load: func() (sourcecdk.Source, error) {
			return sourcewhalesource.New()
		},
	},
	{
		name: "spacelift",
		load: func() (sourcecdk.Source, error) {
			return spaceliftsource.New()
		},
	},
	{
		name: "spendesk",
		load: func() (sourcecdk.Source, error) {
			return spendesksource.New()
		},
	},
	{
		name: "split_io",
		load: func() (sourcecdk.Source, error) {
			return splitiosource.New()
		},
	},
	{
		name: "splunk_cloud",
		load: func() (sourcecdk.Source, error) {
			return splunkcloudsource.New()
		},
	},
	{
		name: "splunk_observability",
		load: func() (sourcecdk.Source, error) {
			return splunkobservabilitysource.New()
		},
	},
	{
		name: "springhealth",
		load: func() (sourcecdk.Source, error) {
			return springhealthsource.New()
		},
	},
	{
		name: "sprinklr",
		load: func() (sourcecdk.Source, error) {
			return sprinklrsource.New()
		},
	},
	{
		name: "sprinto",
		load: func() (sourcecdk.Source, error) {
			return sprintosource.New()
		},
	},
	{
		name: "sprout_social",
		load: func() (sourcecdk.Source, error) {
			return sproutsocialsource.New()
		},
	},
	{
		name: "squadcast",
		load: func() (sourcecdk.Source, error) {
			return squadcastsource.New()
		},
	},
	{
		name: "square",
		load: func() (sourcecdk.Source, error) {
			return squaresource.New()
		},
	},
	{
		name: "stability_ai",
		load: func() (sourcecdk.Source, error) {
			return stabilityaisource.New()
		},
	},
	{
		name: "stackblitz",
		load: func() (sourcecdk.Source, error) {
			return stackblitzsource.New()
		},
	},
	{
		name: "stackhawk",
		load: func() (sourcecdk.Source, error) {
			return stackhawksource.New()
		},
	},
	{
		name: "statsig",
		load: func() (sourcecdk.Source, error) {
			return statsigsource.New()
		},
	},
	{
		name: "statuscake",
		load: func() (sourcecdk.Source, error) {
			return statuscakesource.New()
		},
	},
	{
		name: "statuspage",
		load: func() (sourcecdk.Source, error) {
			return statuspagesource.New()
		},
	},
	{
		name: "stigg",
		load: func() (sourcecdk.Source, error) {
			return stiggsource.New()
		},
	},
	{
		name: "stitch",
		load: func() (sourcecdk.Source, error) {
			return stitchsource.New()
		},
	},
	{
		name: "stoplight",
		load: func() (sourcecdk.Source, error) {
			return stoplightsource.New()
		},
	},
	{
		name: "stream_io_api",
		load: func() (sourcecdk.Source, error) {
			return streamioapisource.New()
		},
	},
	{
		name: "stripe",
		load: func() (sourcecdk.Source, error) {
			return stripesource.New()
		},
	},
	{
		name: "strongdm",
		load: func() (sourcecdk.Source, error) {
			return strongdmsource.New()
		},
	},
	{
		name: "stytch",
		load: func() (sourcecdk.Source, error) {
			return stytchsource.New()
		},
	},
	{
		name: "successfactors",
		load: func() (sourcecdk.Source, error) {
			return successfactorssource.New()
		},
	},
	{
		name: "sumo_logic",
		load: func() (sourcecdk.Source, error) {
			return sumologicsource.New()
		},
	},
	{
		name: "surveymonkey",
		load: func() (sourcecdk.Source, error) {
			return surveymonkeysource.New()
		},
	},
	{
		name: "svix",
		load: func() (sourcecdk.Source, error) {
			return svixsource.New()
		},
	},
	{
		name: "swaggerhub",
		load: func() (sourcecdk.Source, error) {
			return swaggerhubsource.New()
		},
	},
	{
		name: "swif_ai",
		load: func() (sourcecdk.Source, error) {
			return swifaisource.New()
		},
	},
	{
		name: "synack",
		load: func() (sourcecdk.Source, error) {
			return synacksource.New()
		},
	},
	{
		name: "sync_com",
		load: func() (sourcecdk.Source, error) {
			return synccomsource.New()
		},
	},
	{
		name: "sysdig_secure",
		load: func() (sourcecdk.Source, error) {
			return sysdigsecuresource.New()
		},
	},
	{
		name: "tableau_cloud",
		load: func() (sourcecdk.Source, error) {
			return tableaucloudsource.New()
		},
	},
	{
		name: "tailscale",
		load: func() (sourcecdk.Source, error) {
			return tailscalesource.New()
		},
	},
	{
		name: "talkdesk",
		load: func() (sourcecdk.Source, error) {
			return talkdesksource.New()
		},
	},
	{
		name: "tallyfy",
		load: func() (sourcecdk.Source, error) {
			return tallyfysource.New()
		},
	},
	{
		name: "tanium_cloud",
		load: func() (sourcecdk.Source, error) {
			return taniumcloudsource.New()
		},
	},
	{
		name: "taxamo",
		load: func() (sourcecdk.Source, error) {
			return taxamosource.New()
		},
	},
	{
		name: "teamcity_cloud",
		load: func() (sourcecdk.Source, error) {
			return teamcitycloudsource.New()
		},
	},
	{
		name: "teampay",
		load: func() (sourcecdk.Source, error) {
			return teampaysource.New()
		},
	},
	{
		name: "teamwork",
		load: func() (sourcecdk.Source, error) {
			return teamworksource.New()
		},
	},
	{
		name: "teamwork_projects",
		load: func() (sourcecdk.Source, error) {
			return teamworkprojectssource.New()
		},
	},
	{
		name: "telemetryhub",
		load: func() (sourcecdk.Source, error) {
			return telemetryhubsource.New()
		},
	},
	{
		name: "teleport",
		load: func() (sourcecdk.Source, error) {
			return teleportsource.New()
		},
	},
	{
		name: "telnyx",
		load: func() (sourcecdk.Source, error) {
			return telnyxsource.New()
		},
	},
	{
		name: "tenable_io",
		load: func() (sourcecdk.Source, error) {
			return tenableiosource.New()
		},
	},
	{
		name: "terraform_cloud",
		load: func() (sourcecdk.Source, error) {
			return terraformcloudsource.New()
		},
	},
	{
		name: "testim",
		load: func() (sourcecdk.Source, error) {
			return testimsource.New()
		},
	},
	{
		name: "tettra",
		load: func() (sourcecdk.Source, error) {
			return tettrasource.New()
		},
	},
	{
		name: "thoropass",
		load: func() (sourcecdk.Source, error) {
			return thoropasssource.New()
		},
	},
	{
		name: "thoughtspot",
		load: func() (sourcecdk.Source, error) {
			return thoughtspotsource.New()
		},
	},
	{
		name: "thousandeyes",
		load: func() (sourcecdk.Source, error) {
			return thousandeyessource.New()
		},
	},
	{
		name: "threatjammer",
		load: func() (sourcecdk.Source, error) {
			return threatjammersource.New()
		},
	},
	{
		name: "three_sixty_learning",
		load: func() (sourcecdk.Source, error) {
			return threesixtylearningsource.New()
		},
	},
	{
		name: "tines",
		load: func() (sourcecdk.Source, error) {
			return tinessource.New()
		},
	},
	{
		name: "together_ai",
		load: func() (sourcecdk.Source, error) {
			return togetheraisource.New()
		},
	},
	{
		name: "torii",
		load: func() (sourcecdk.Source, error) {
			return toriisource.New()
		},
	},
	{
		name: "torq",
		load: func() (sourcecdk.Source, error) {
			return torqsource.New()
		},
	},
	{
		name: "traceable_ai",
		load: func() (sourcecdk.Source, error) {
			return traceableaisource.New()
		},
	},
	{
		name: "travis_ci",
		load: func() (sourcecdk.Source, error) {
			return traviscisource.New()
		},
	},
	{
		name: "tray_io",
		load: func() (sourcecdk.Source, error) {
			return trayiosource.New()
		},
	},
	{
		name: "trello",
		load: func() (sourcecdk.Source, error) {
			return trellosource.New()
		},
	},
	{
		name: "tresorit",
		load: func() (sourcecdk.Source, error) {
			return tresoritsource.New()
		},
	},
	{
		name: "trivy",
		load: func() (sourcecdk.Source, error) {
			return trivysource.New()
		},
	},
	{
		name: "trufflehog_enterprise",
		load: func() (sourcecdk.Source, error) {
			return trufflehogenterprisesource.New()
		},
	},
	{
		name: "truora",
		load: func() (sourcecdk.Source, error) {
			return truorasource.New()
		},
	},
	{
		name: "trustarc",
		load: func() (sourcecdk.Source, error) {
			return trustarcsource.New()
		},
	},
	{
		name: "trustedendpoint",
		load: func() (sourcecdk.Source, error) {
			return trustedendpointsource.New()
		},
	},
	{
		name: "trustpilot",
		load: func() (sourcecdk.Source, error) {
			return trustpilotsource.New()
		},
	},
	{
		name: "tugboat_logic",
		load: func() (sourcecdk.Source, error) {
			return tugboatlogicsource.New()
		},
	},
	{
		name: "twilio",
		load: func() (sourcecdk.Source, error) {
			return twiliosource.New()
		},
	},
	{
		name: "twitter",
		load: func() (sourcecdk.Source, error) {
			return twittersource.New()
		},
	},
	{
		name: "tyk",
		load: func() (sourcecdk.Source, error) {
			return tyksource.New()
		},
	},
	{
		name: "typeform",
		load: func() (sourcecdk.Source, error) {
			return typeformsource.New()
		},
	},
	{
		name: "typefully",
		load: func() (sourcecdk.Source, error) {
			return typefullysource.New()
		},
	},
	{
		name: "udemy_business",
		load: func() (sourcecdk.Source, error) {
			return udemybusinesssource.New()
		},
	},
	{
		name: "ujet",
		load: func() (sourcecdk.Source, error) {
			return ujetsource.New()
		},
	},
	{
		name: "ukg_pro",
		load: func() (sourcecdk.Source, error) {
			return ukgprosource.New()
		},
	},
	{
		name: "unleash_cloud",
		load: func() (sourcecdk.Source, error) {
			return unleashcloudsource.New()
		},
	},
	{
		name: "upguard",
		load: func() (sourcecdk.Source, error) {
			return upguardsource.New()
		},
	},
	{
		name: "uptime_com",
		load: func() (sourcecdk.Source, error) {
			return uptimecomsource.New()
		},
	},
	{
		name: "uptimerobot",
		load: func() (sourcecdk.Source, error) {
			return uptimerobotsource.New()
		},
	},
	{
		name: "uptrace",
		load: func() (sourcecdk.Source, error) {
			return uptracesource.New()
		},
	},
	{
		name: "userpilot",
		load: func() (sourcecdk.Source, error) {
			return userpilotsource.New()
		},
	},
	{
		name: "uservoice",
		load: func() (sourcecdk.Source, error) {
			return uservoicesource.New()
		},
	},
	{
		name: "valence_security",
		load: func() (sourcecdk.Source, error) {
			return valencesecuritysource.New()
		},
	},
	{
		name: "vanta",
		load: func() (sourcecdk.Source, error) {
			return vantasource.New()
		},
	},
	{
		name: "varicent",
		load: func() (sourcecdk.Source, error) {
			return varicentsource.New()
		},
	},
	{
		name: "velopayments",
		load: func() (sourcecdk.Source, error) {
			return velopaymentssource.New()
		},
	},
	{
		name: "veracode",
		load: func() (sourcecdk.Source, error) {
			return veracodesource.New()
		},
	},
	{
		name: "vercel",
		load: func() (sourcecdk.Source, error) {
			return vercelsource.New()
		},
	},
	{
		name: "victoriametrics_cloud",
		load: func() (sourcecdk.Source, error) {
			return victoriametricscloudsource.New()
		},
	},
	{
		name: "victorops",
		load: func() (sourcecdk.Source, error) {
			return victoropssource.New()
		},
	},
	{
		name: "vidyard",
		load: func() (sourcecdk.Source, error) {
			return vidyardsource.New()
		},
	},
	{
		name: "virustotal",
		load: func() (sourcecdk.Source, error) {
			return virustotalsource.New()
		},
	},
	{
		name: "visiblethread",
		load: func() (sourcecdk.Source, error) {
			return visiblethreadsource.New()
		},
	},
	{
		name: "vitally",
		load: func() (sourcecdk.Source, error) {
			return vitallysource.New()
		},
	},
	{
		name: "vulncheck",
		load: func() (sourcecdk.Source, error) {
			return vulnchecksource.New()
		},
	},
	{
		name: "vulnview",
		load: func() (sourcecdk.Source, error) {
			return vulnviewsource.New()
		},
	},
	{
		name: "webex",
		load: func() (sourcecdk.Source, error) {
			return webexsource.New()
		},
	},
	{
		name: "whatsapp",
		load: func() (sourcecdk.Source, error) {
			return whatsappsource.New()
		},
	},
	{
		name: "whereby",
		load: func() (sourcecdk.Source, error) {
			return wherebysource.New()
		},
	},
	{
		name: "whistic",
		load: func() (sourcecdk.Source, error) {
			return whisticsource.New()
		},
	},
	{
		name: "wing_security",
		load: func() (sourcecdk.Source, error) {
			return wingsecuritysource.New()
		},
	},
	{
		name: "winsms",
		load: func() (sourcecdk.Source, error) {
			return winsmssource.New()
		},
	},
	{
		name: "wistia",
		load: func() (sourcecdk.Source, error) {
			return wistiasource.New()
		},
	},
	{
		name: "wiz",
		load: func() (sourcecdk.Source, error) {
			return wizsource.New()
		},
	},
	{
		name: "workable",
		load: func() (sourcecdk.Source, error) {
			return workablesource.New()
		},
	},
	{
		name: "workato",
		load: func() (sourcecdk.Source, error) {
			return workatosource.New()
		},
	},
	{
		name: "workday",
		load: func() (sourcecdk.Source, error) {
			return workdaysource.New()
		},
	},
	{
		name: "workfront",
		load: func() (sourcecdk.Source, error) {
			return workfrontsource.New()
		},
	},
	{
		name: "workos",
		load: func() (sourcecdk.Source, error) {
			return workossource.New()
		},
	},
	{
		name: "workplace_from_meta",
		load: func() (sourcecdk.Source, error) {
			return workplacefrommetasource.New()
		},
	},
	{
		name: "wrike",
		load: func() (sourcecdk.Source, error) {
			return wrikesource.New()
		},
	},
	{
		name: "writer",
		load: func() (sourcecdk.Source, error) {
			return writersource.New()
		},
	},
	{
		name: "xai",
		load: func() (sourcecdk.Source, error) {
			return xaisource.New()
		},
	},
	{
		name: "xero",
		load: func() (sourcecdk.Source, error) {
			return xerosource.New()
		},
	},
	{
		name: "xmatters",
		load: func() (sourcecdk.Source, error) {
			return xmatterssource.New()
		},
	},
	{
		name: "xtrf_eu",
		load: func() (sourcecdk.Source, error) {
			return xtrfeusource.New()
		},
	},
	{
		name: "yardi_voyager",
		load: func() (sourcecdk.Source, error) {
			return yardivoyagersource.New()
		},
	},
	{
		name: "zapier_enterprise",
		load: func() (sourcecdk.Source, error) {
			return zapierenterprisesource.New()
		},
	},
	{
		name: "zeet",
		load: func() (sourcecdk.Source, error) {
			return zeetsource.New()
		},
	},
	{
		name: "zendesk",
		load: func() (sourcecdk.Source, error) {
			return zendesksource.New()
		},
	},
	{
		name: "zendesk_sell",
		load: func() (sourcecdk.Source, error) {
			return zendesksellsource.New()
		},
	},
	{
		name: "zenefits",
		load: func() (sourcecdk.Source, error) {
			return zenefitssource.New()
		},
	},
	{
		name: "zerofox",
		load: func() (sourcecdk.Source, error) {
			return zerofoxsource.New()
		},
	},
	{
		name: "zilla_security",
		load: func() (sourcecdk.Source, error) {
			return zillasecuritysource.New()
		},
	},
	{
		name: "ziphq",
		load: func() (sourcecdk.Source, error) {
			return ziphqsource.New()
		},
	},
	{
		name: "zoho_books",
		load: func() (sourcecdk.Source, error) {
			return zohobookssource.New()
		},
	},
	{
		name: "zoho_crm",
		load: func() (sourcecdk.Source, error) {
			return zohocrmsource.New()
		},
	},
	{
		name: "zoho_mail",
		load: func() (sourcecdk.Source, error) {
			return zohomailsource.New()
		},
	},
	{
		name: "zoho_projects",
		load: func() (sourcecdk.Source, error) {
			return zohoprojectssource.New()
		},
	},
	{
		name: "zoho_sprints",
		load: func() (sourcecdk.Source, error) {
			return zohosprintssource.New()
		},
	},
	{
		name: "zoho_workdrive",
		load: func() (sourcecdk.Source, error) {
			return zohoworkdrivesource.New()
		},
	},
	{
		name: "zoom",
		load: func() (sourcecdk.Source, error) {
			return zoomsource.New()
		},
	},
	{
		name: "zoom_phone",
		load: func() (sourcecdk.Source, error) {
			return zoomphonesource.New()
		},
	},
	{
		name: "zoominfo",
		load: func() (sourcecdk.Source, error) {
			return zoominfosource.New()
		},
	},
	{
		name: "zscaler_internet_access",
		load: func() (sourcecdk.Source, error) {
			return zscalerinternetaccesssource.New()
		},
	},
	{
		name: "zscaler_private_access",
		load: func() (sourcecdk.Source, error) {
			return zscalerprivateaccesssource.New()
		},
	},
	{
		name: "zuora",
		load: func() (sourcecdk.Source, error) {
			return zuorasource.New()
		},
	},
	{
		name: "zylo",
		load: func() (sourcecdk.Source, error) {
			return zylosource.New()
		},
	},
}

// DynamicDefinitionSource adapts a stored dynamic connector definition into the
// source layer without exposing concrete source packages to callers.
func DynamicDefinitionSource(definition connectordefinitions.Definition) (sourcecdk.Source, error) {
	normalized, err := connectordefinitions.Normalize(definition)
	if err != nil {
		return nil, err
	}
	if normalized.Validation.Status == connectordefinitions.ValidationBlocked {
		return nil, fmt.Errorf("%w: connector definition %q is blocked: %s", connectordefinitions.ErrInvalidDefinition, normalized.SourceID, normalized.Validation.Summary)
	}
	if normalized.Ingest.Mode == connectordefinitions.IngestModeDeposit {
		return newDepositDefinitionSource(normalized), nil
	}
	return catalogruntimesource.NewDefinition(normalized)
}

func ReadDynamicDefinitionFixture(ctx context.Context, definition connectordefinitions.Definition, familyID string, body []byte) (DefinitionFixtureReadResult, error) {
	return catalogruntimesource.ReadDefinitionFixture(ctx, definition, familyID, body)
}

// Builtin constructs the in-process source registry for the rewrite skeleton.
func Builtin() (*sourcecdk.Registry, error) {
	sources := make([]sourcecdk.Source, 0, len(builtinSourceLoaders))
	registered := map[string]struct{}{}
	for _, loader := range builtinSourceLoaders {
		source, err := loader.load()
		if err != nil {
			return nil, fmt.Errorf("load %s source: %w", loader.name, err)
		}
		if spec := source.Spec(); spec != nil {
			registered[spec.Id] = struct{}{}
		}
		sources = append(sources, source)
	}
	catalog, err := connectorcatalog.BuiltinRuntime()
	if err != nil {
		return nil, fmt.Errorf("load connector definition catalog: %w", err)
	}
	for _, entry := range catalog.Entries {
		sourceID := entry.Definition.SourceID
		if _, ok := registered[sourceID]; ok || entry.Report.Verdict != connectordefinitions.SupportVerdictSupported {
			continue
		}
		source, err := catalogruntimesource.New(entry)
		if err != nil {
			return nil, fmt.Errorf("load catalog source %s: %w", sourceID, err)
		}
		registered[sourceID] = struct{}{}
		sources = append(sources, source)
	}
	registry, err := sourcecdk.NewRegistry(sources...)
	if err != nil {
		return nil, err
	}
	return registry.WithBuiltinDefinitionCatalog(), nil
}
