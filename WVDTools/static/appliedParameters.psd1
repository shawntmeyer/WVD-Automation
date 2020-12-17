@{
	# General Information #
	# =================== #
	# Environment
	subscriptionId                              = '<ReplaceWith-SubscriptionId>'
	aadTenantId                                 = '<ReplaceWith-TenantId>'
    
	# Pipeline
	serviceConnectionName                       = '<ReplaceWith-ServiceConnection>'
	serviceConnectionSPObjectID                 = '<ReplaceWith-ServiceConnectionServicePrincipalObjectId>'
	vmImage                                     = 'ubuntu-latest'
	poolName                                    = '<ReplaceWith-PoolName>'
	orchestrationPath                           = 'WVD/Environments/pipeline-orchestrated'
	orchestrationFunctionsPath                  = 'WVD/OrchestrationSources/SharedDeploymentFunctions'
	wvdUploadsPath                              = 'WVD/OrchestrationSources/Uploads'
	
	# Components
	componentStorageContainerName               = '<ReplaceWith-ComponentsStorageAccountContainer>'
	componentStorageAccountName                 = '<ReplaceWith-ComponentsStorageAccount>'

	# ResourceGroups
	HostPool01RGName                            = '<ReplaceWith-WVD-HostPool-RG>'
	ImagingRGName                               = '<ReplaceWith-bsd-imaging-rg>'
	MgmtRGName                                  = '<ReplaceWith-WVD-Mgmt-RG>'
	ProfilesRGName                              = '<ReplaceWith-WVD-Profiles-RG>'

	PrimaryResourceLocation                     = '<ReplaceWith-PrimaryLocation>'
	SecondaryResourceLocation                   = '<ReplaceWith-SecondaryLocation>'
	
	# Groups
	group01                                     = '<ReplaceWith-UserGroup1>'

	#######################

	# Management related #
	# ================== #
	
	# Key Vault
	wvdKvltName                                 = '<ReplaceWith-KeyVaultName>'

	# Assets Storage Account
	assetsSaName                                = '<ReplaceWith-AssetsStorageAccountName>'

	# Automation Account
	automationAccountName                       = '<ReplaceWith-AutomationAccount>'
	ScalingRunbookName                          = '<ReplaceWith-ScalingRunbookName>'
	ScalingWebhookName                          = '<ReplaceWith-ScalingRunbookWebhookName>'
	RunAsConnectionSPName                       = '<ReplaceWith-AutomationAccountRunAsServicePrincipalName>'
	RunAsSelfSignedCertSecretName               = '<ReplaceWith-AutomationAccountRunAsSelfSignedCertSecretName>'
	AutoAccountRunAsCertExpiryInMonths          = '<ReplaceWith-AutomationAccountRunAsCertExpiryInMonths>'
	
	# Recovery Services Vault
	rsvName                                     = '<ReplaceWith-RecoveryVaultName>'
	
	#####################
    
	# Profiles related #
	# ================ #
	profilesSa01Name                            = '<ReplaceWith-profilesStorageAccountName01>'
	profilesSa01StorageAccountKind              = 'StorageV2'
	profilesSa01SorageAccountSku                = 'Standard_LRS'
	profilesSa01FileShare01Name                 = '<ReplaceWith-FileShareName1>'
	profilesSa01FileShare02Name                 = '<ReplaceWith-FileShareName2>'

	###################

	# Host Pool related #
	# ================= #
    
	# Host Pool 01
	hostPool01Name                              = '<ReplaceWith-HostPoolName>'
	hostPool01HostpoolType                      = 'Pooled'
	hostPool01LoadBalancerType                  = 'BreadthFirst'
	
	# Desktop Application Group 01
	desAppGroup01Name                           = '<ReplaceWith-Desktop-ApplicationGroup>'
	desAppGroup01Type                           = 'Desktop'

	# Remote Application Group 01
	remAppGroup01Name                           = '<ReplaceWith-Remote-ApplicationGroup>'
	remAppGroup01Type                           = 'RemoteApp'
	
	# Workspace 01
	workspace01Name                             = '<ReplaceWith-WorkSpaceName>' 

	# Session Host
	shVmSize                                    = '<ReplaceWith-ImageTemplateVmSize>'
	shSubnetRef                                 = '<ReplaceWith-VMSubnetResourceId>'
	shAdminUsername                             = '<ReplaceWith-VMLocalAdminUserName>'
	shDomainName                                = '<ReplaceWith-DomainName>'
	shDomainJoinUserPrincipalName               = '<ReplaceWith-DomainJoinUserPrincipalName>'
	shDomainJoinUserName                        = '<ReplaceWith-DomainJoinUserName>'
	shDomainJoinOU                              = '<ReplaceWith-domainJoinOU>'
	
	## Session Host 01
	sh01VmNamePrefix                            = '<ReplaceWith-vmNamePrefix>'
	sh01VmNumberOfInstances                     = <ReplaceWith-vmNumberOfInstances>
	sh01VmInitialNumber                         = 0
	sh01ImageCustomRef                          = '<ReplaceWith-CustomImageReferenceId>'
	sh01ImagePublisher                          = '<ReplaceWith-MarketplaceImagePublisher>' # Used only if not providing a custom image ref. 
	sh01ImageOffer                              = '<ReplaceWith-MarketplaceImageOffer>'
	sh01ImageSku                                = '<ReplaceWith-MarketplaceImageSku>' 
	sh01ImageVersion                            = '<ReplaceWith-MarketplaceImageVersion>'
	sh01ImageLifecycleDeleteVMDeadline          = '<ReplaceWith-ImagingDeleteVMDeadline>' # In 'yyyyMMddHHmm'. The deadline after which outdated VMs are delete
	sh01ImageLifecycleLogoffDeadline            = '<ReplaceWith-ImagingLogoffDeadline>' # In 'yyyyMMddHHmm'. The deadline after which users are log-off by force 
	sh01ImageLifecycleUtcOffset                 = <ReplaceWith-ImagingTimeDifference> # Time difference to UTC. Enabled handling of different time zones.
	sh01ImageLifecycleLogOffMessageTitle        = '<ReplaceWith-ImagingLogOffMessageTitle>' # PopUp title shown to users if they are warned of an upcoming imminent log-off
	sh01ImageLifecycleLogOffMessageBody         = '<ReplaceWith-ImagingLogOffMessageBody>' # PopUp text shown to users if they are warned of an upcoming imminent log-off
	LogAnalyticsWorkspaceName                     = '<ReplaceWith-LogAnalyticsWorkspaceName>' # Name of an OMS workspace to send host-pool image update process logs to
	
	# Scaling
	MaintenanceTagName                          = 'MaintenanceMode'
	## Scaling Scheduler 01
	logicAppName01Name                          = '<ReplaceWith-ScalingSchedulerName>'
	logicApp01RecurrenceInterval                = '<ReplaceWith-RecurrenceInterval>' # In Minutes (min 15)
	logicAppName01LimitSecondsToForceLogOffUser = '<ReplaceWith-LimitSecondsToForceLogOffUser>'
	logicAppName01BeginPeakTime                 = '<ReplaceWith-EndPeakTime>'
	logicAppName01EndPeakTime                   = '<ReplaceWith-BeginPeakTime>'
	logicAppName01UtcOffset                     = '<ReplaceWith-UtcOffset>'
	logicAppName01LogOffMessageBody             = '<ReplaceWith-LogOffMessageBody>'
	logicAppName01LogOffMessageTitle            = '<ReplaceWith-LogOffMessageTitle>'
	logicAppName01MinimumNumberOfRDSH           = '<ReplaceWith-MinimumNumberOfRDSH>'
	logicAppName01SessionThresholdPerCPU        = '<ReplaceWith-SessionThresholdPerCPU>'
	
	###############

	# Imaging related #
	# =============== #
	
	# General
	image01Name                                 = '<ReplaceWith-ImageDefinitionName>'
	image01SourcePublisher                      = '<ReplaceWith-ImageDefinitionPublisher>'
	image01SourceOffer                          = '<ReplaceWith-ImageOffer>'
	image01SourceSku                            = '<ReplaceWith-ImageSku>' 
	image01SourceVersion                        = 'latest'
	synchronouslyWaitForImageBuild              = $false
	
	# MSI
	imageMsiName                                = '<ReplaceWith-userMsiName>'
	
	# Image Gallery
	imgGalleryName                              = '<ReplaceWith-ImageGalleryName>'
	galleryDescription                          = '<ReplaceWith-GalleryDescription>'
	
	# Image Definition
	imgDef01OsType                              = '<ReplaceWith-ImageDefinitionOsType>'
	imgDef01OsState                             = '<ReplaceWith-ImageDefinitionOsState>'
	imgDef01MinRecommendedvCPUs                 = '<ReplaceWith-ImageMinRecommendedvCPUs>'
	imgDef01MaxRecommendedvCPUs                 = '<ReplaceWith-ImageMaxRecommendedvCPUs>'
	imgDef01MinRecommendedMemory                = '<ReplaceWith-vmNumberOfInstances>'
	imgDef01MaxRecommendedMemory                = '<ReplaceWith-ImageMaxRecommendedMemory>'
	imgDef01HyperVGeneration                    = '<ReplaceWith-ImageHyperVGeneration>'
	
	# Image Template
	imageTemplate01Name                         = '<ReplaceWith-imageTemplateName>'
	imageTemplate01VMSize                       = '<ReplaceWith-ImageTemplateVmSize>'
	imageTemplate01AzureImageBuilderSubnetId    = '<ReplaceWith-ImageTemplateSubnetId>'
	imageTemplate01SourceType                   = 'PlatformImage'
	
	######################

	# Authentication related
	# ==================== #
	identityApproach                            = '<ReplaceWith-IdentityApproach>' # (AD or AADDS)
    
	# Only required for AD
	DevOpsVariableGroup                         = '<ReplaceWith-DevOpsWVDSecretsGroup>'
    
	# Only required for AADDS
	domainJoinPrincipalName                     = '<ReplaceWith-DomainJoinUserPrincipalName>'
	########################
}