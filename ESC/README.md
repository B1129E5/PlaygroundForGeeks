# ESC
Exchange Security Collect
Script to collect Security information for Exchange OnPremises
Project was renamed the 09/11/2022 from ESI - Exchange Security Information to ESC - Exchange Security Collect


The goal of this document is to help in the analysis of information collected by the script.
For some tabs, a quick way to check the modifications could be to check the WhenCreated and WhenChanged column when they are available.



## How to collect

## How to generate the Excel file


## How to Analyse the Excel File

This script collects the following information :
- MRA : 
o	Collect all the assignment between management roles, group and their scope
o	Focus on role with high privileges : 
- Impersonation
- Mailbox search
- Mailbox Import Export
- Mail Recipient : You should also pay attention to this role because it allows to give full access on every mailboxes
- Ensure that scopes are used especially for Application Impersonation
o	If those roles need to be delegated, put a scope and monitor the group and the users with this delegation
o	You should also review the custom delegations in order to 
- Check if they are still needed
- If they are scoped
- If they can be reduced in terms of privileges
o	If you need to know what the default delegations are, the cmdlet and parameters associated with each role… I will add in the zip file,  the file Dump_RBAC_2019CU12-Sept22.xls. This file contains the default RBAC configuration for a new Exchange 2019 CU 12 organization.
o	Delegating Management role assignments have been removed
- MRCustom : 
o	Collect all the custom management roles with their scope
o	When custom roles are created this tab helps to check the parent role
- MRCustomDetails : 
o	Collect management roles' details
o	When custom roles are created this tab helps to check all the cmdlet and parameters that were kept in the role
- MRScope : 
o	Collect custom management scopes
o	Focus on scope which too wide, ex :  include all mailbox for a domain…
- AdminAuditLog : 
o	Collect information about the configuration of AdminAudit log
o	Check if the default settings have been altered
o	Focus on :
- AdminAuditLogEnabled : Should be True
- AdminAuditLogCmdlets : should *
- AdminAuditLogExcludedCmdlets : Should be empty
- AdminAuditLogAgeLimit : should be at least 90 days
- ReceiveConnector : 
o	Collect information on Receive Connector 
o	Focus on AuthMechanism with ExternalAuthoritative. This means that this Receive connectors I Open Relay
o	Focus on Anonymous Authentication
o	If Anonymous check the RemoteIPRanges
- Should not include ::
- ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 0.0.0.0-255.255.255.255 
- subnet
o	Review the Tarpit
- SendConnector : 
o	Collect information about Send Connector
o	Check TLS information
- RemoteDomain :
o	Collect all the Remote Domain and retrieve the value AutoForwardEnabled
o	Focus first on the DomainName * and check if the setting AutoForwardEnabled set to True. With this configuration any users can created Inbox rules to automatically forwarded any received message to a mailbox outside of the organization
o	Review all the Remote Domain with  AutoForwardEnabled set to True
- TransportRules : 
o	Collect Transport Rule with one of these actions : BlindCopyTo, CopyTo, RedirectMessage
o	Review these Transport Rules and check if they are still accurate
- Transport rules are used by attackers to automatically send message outside the organization
- JournalRules: 
o	Collect Journal Rules
o	Review these Journal Rules
- MbxDBJournaling : 
o	Collect the property JournalRecipient for all databases
o	Review the databases that have a JournalRecipient set
- MailboxDatabaseReceiveAs : 
o	Collect ReceiveAs permissions on the database object
o	This permission set Full Access mailboxes for the user accounts on all mailboxes in the target database
- MailboxDatabaseSendAs : 
o	Collect SendAs permissions on the database object
o	This permissions allow the user to have the permissions Send-As on all mailboxes in the target database
- PartConfPerm 
o	This tab shows the permssions on containers and servers object in the configuration partition where Exchange information are stored
o	The help with the analysis, and display non standard permissions, add the following Filter 
- isInherited :  False
- User : unchecked
- All servers
- NT AUTHORITY\Authenticated Users
- DSONE\Organization Management
- DSONE\Public Folder Management
- DSONE\Delegated Setup
- DSONE\Exchange Servers
- DSONE\Exchange Trusted Subsystem
- NT AUTHORITY\Authenticated Users
- DSONE\Domain Admins
- DSONE\Schema Admins
- DSONE\Enterprise Admins
- NT AUTHORITY\SYSTEM
- NT AUTHORITY\NETWORK SERVICE
- DSONE\RTCComponentUniversalServices
- DSONE\RTCUniversalServerAdmins
- DSONE\Managed Availability Servers
- Everyone
- NT AUTHORITY\ANONYMOUS LOGON
- DAGEncryption
o	Check the value NetworkEncryption and AutoDagBitlockerEnabled
o	Both value should be set to true
- POP : 
o	Collect POP
o	Focus on LogonType : Plaintext Authentication
o	Check servers where Pop is started
o	If PlainText authentication has been set, retrieve the list of mailboxes with POP enabled using the following command 
- get-casmailbox -resultsize unlimited | ? {$_.PopEnabled -eq $true}
- Remember that Pop should be disabled on all mailboxes except those which really need it. When a mailbox is created POP is enabled by default
- IMAP : 
o	Collect IMAP
o	Focus on LogonType : Plaintext Authentication
o	Check servers where IMAP is started
o	If PlainText authentication has been set, retrieve the list of mailboxes with POP enabled using the following command 
- get-casmailbox -resultsize unlimited | ? {$_.ImapEnabled -eq $true}
- Remember that IMAP should be disabled on all mailboxes except those which really need it. When a mailbox is created IMAP is enabled by default
- Kerberos :
o	Ensure that Kerberos is configured on all servers
- ExchGroup: 
o	Retrieve all the group in the OU "Microsoft Exchange Security Groups"
o	When nested group :
- Retrieve all the members by checking all the nested groups in all domains in the forest
- If groups for other forest, the content can't be retrieved
- MemberPath display in the imbrication path
- Level displays the level of imbrication
- 0 for the group that is currently reviewed
- 1 direct member of the group
- 2 member of a group that a direct member
- 3 member of a group that is already nested
- 4…
o	Focus first on the following groups
- Discovery Management : should be empty
- Organization Management : Should not content service accounts and only few administrators
- Exchange Servers: should only contain the Exchange Computer accounts and the group Exchange Install Domain Servers
- Exchange Trusted Subsystem : Should only contain the Exchange Computer accounts
- Exchange Windows Permissions : Should only contain Exchange Trusted Subsystem
o	Filter on PasswordLastSet to check accounts will a last password set greater that 1 year
o	Filter on LastLogonDateto check accounts will a LastLogonDate greater that 1 year month
o	The tab also showed if the account is enabled, has a mailbox and its DN
- ExchGroupCount
o	For each group check the total unique user that member of this group
- ADRootGrp
o	Retrieve content of the group Enterprise Admins, Domain Admins and Administrators group, account Operators for the root domain and display their content
o	When nested group :
- Retrieve all the members by checking all the nested group in all domains in the forest
- If groups for other forest, the content can't be retrieved
- MemberPath display all the group in the imbrication path
- Level displays the level of imbrication
- 0 for the group that is currently reviewed
- 1 direct member of the group
- 2 member of a group that a direct member
- 3 member of a group that is already nested
- 4…
o	Filter on PasswordLastSet to check accounts will a last password set greater that 1 year
o	Filter on LastLogonDateto check accounts will a LastLogonDate greater that 1 year month
o	The tab also showed if the account is enabled, has a mailbox and its DN
- ADRootGrpCount
o	For each group check the total unique user that member of this group
- ExchVersion
o	Show the Exchange Version
o	Check if the latest CU/SU is deployed
- SrvLocalAdmin: 
o	Retrieve the content of the Local Administrators group for all Exchange Servers
o	When nested group :
- Retrieve all the members by checking all the nested group in all domains in the forest
- If groups for other forest, the content can't be retrieved
- MemberPath display all the group in the imbrication path
- Level displays the level of imbrication
- 0 for the group that is currently reviewed
- 1 direct member of the group
- 2 member of a group that a direct member
- 3 member of a group that is already nested
- 4…
o	Filter on PasswordLastSet to check accounts will a last password set greater that 1 year
o	Filter on LastLogonDateto check accounts will a LastLogonDate greater that 1 year month
o	Remember :
- a local admin can perform a PasstheHash attack on the Computer object of an Exchange Server and so have all the Rights granted through the Exchange Trusted Subsystem and Exchange Windows Permissions
- They have full access on mailbox database and Transport database (Safety Net data …)
- They can start scheduled tasks with System
- …
o	Default content 
- Local Administrators account
- Domain Admins
- Exchange Trusted Subsystem
- Organization Management
o	The content NEEDS to be CONSISTENT on all servers
o	Only the default content should be in the local Administrators goup
o	Recommendation : Use PivotTable
- SrvLocalAdminCount
o	For each group check the total unique user that member of this group
- SMBv1
o	Check if the SMBv1 feature in installed
o	Check if SMBv1 is disabled in the registed
o	Excepted values : 
 
- Services
o	For each server, retrieve the list of installed services
o	Check if some suspicious services are displayed
o	Check it the list of installed services is consistent
o	Recommendation : Use PivotTable
- Software :
o	For each server, retrieve the list of installed software
o	No freeware/shareware or application not related to Exchange should be displayed
o	Check it the list of installed software is consistent
o	Recommendation : Use PivotTable
- ScheduledTask
o	Retrieve all the Scheduled tasks for all Exchange servers
o	Check if scripts start with the System account
o	Check the user account uses to start the tasks
o	Check the location of the script and ensure that only Exchange Administrators have access to the script
- TLS
o	Check the status of registry key related to TLS
- SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client
- SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server
- SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client
- SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server
- SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client
- SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server
- SOFTWARE\Microsoft\.NETFramework\v2.0.50727
- SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727
- SOFTWARE\Microsoft\.NETFramework\v4.0.30319
- SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319
- For more information for the expected value, check this blog
- Exchange Server TLS guidance, part 1: Getting Ready for TLS 1.2
o	https://techcommunity.microsoft.com/t5/exchange-team-blog/exchange-server-tls-guidance-part-1-getting-ready-for-tls-1-2/ba-p/607649
- Exchange Server TLS guidance Part 2: Enabling TLS 1.2 and Identifying Clients Not Using It
o	https://techcommunity.microsoft.com/t5/exchange-team-blog/exchange-server-tls-guidance-part-2-enabling-tls-1-2-and/ba-p/607761
- Exchange Server TLS guidance Part 3: Turning Off TLS 1.0/1.1
o	https://techcommunity.microsoft.com/t5/exchange-team-blog/exchange-server-tls-guidance-part-3-turning-off-tls-1-0-1-1/ba-p/607898
- TransportAgent : 
o	Check if there is not an "odd" Transport Agent
- WFeatures
o	Ensure if MSMQ is installed 
o	Exchange Server prerequisites, Exchange 2019 system requirements, Exchange 2019 requirements | Microsoft Learn
  
- OrganizationConfig : 
o	Collect information about the information
o	Check for example if MailTipsExternalRecipientsTipsEnabled has been enabled, if not I add low issue in the report and explain how it can be interested to have this parameter set. It force users to think about the content of their email
- TransportConfig : 
o	Retrieve some information regarding general transport configuration
o	Check if ShadowRedundancy is enabled
o	Check TLS information
- SendConnector : 
o	Collect information about Send Connector
o	Check TLS information
- MRA_Delegating : 
o	Collect all the management roles with their scope
o	Focus on non standard delegating
- TransportPipeline : 
o	Collect information about the Transport Pipeline for each server
o	Check if Transport Pipeline has been enabled and if yes for which mailbox
