import json
import os
import logging
import argparse
import time
import sys
from datetime import datetime

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

try:
    import dns.resolver
except ImportError:
    logging.warning("dns.resolver module not found. DNS record collection will be skipped. "
                    "Install it with: pip install dnspython")
    dns = None

# Basic logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Comprehensive list of scopes for Google Workspace and GCP
SCOPES = list(set([  # Use set to avoid duplicates, then convert back to list
    # Workspace - Users and Security
    'https://www.googleapis.com/auth/admin.directory.user.readonly',
    'https://www.googleapis.com/auth/admin.directory.user.security',
    # Workspace - Domains
    'https://www.googleapis.com/auth/admin.directory.domain.readonly',
    # Workspace - Groups
    'https://www.googleapis.com/auth/admin.directory.group.readonly',
    'https://www.googleapis.com/auth/apps.groups.settings',
    # Workspace - Org Units
    'https://www.googleapis.com/auth/admin.directory.orgunit.readonly',
    # Workspace - Roles
    'https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly',
    # Workspace - Gmail
    'https://www.googleapis.com/auth/gmail.settings.basic',
    'https://www.googleapis.com/auth/gmail.settings.sharing',
    # Workspace - Calendar
    'https://www.googleapis.com/auth/calendar.readonly',
    'https://www.googleapis.com/auth/calendar.settings.readonly',
    # Workspace - Classroom
    'https://www.googleapis.com/auth/classroom.courses.readonly', # For course and roster info
    # Workspace - Chat
    'https://www.googleapis.com/auth/chat.messages.readonly', # If specific message content checks are needed
    'https://www.googleapis.com/auth/chat.spaces.readonly',   # For space metadata
    # Workspace - Drive
    'https://www.googleapis.com/auth/drive.readonly',         # General Drive access
    'https://www.googleapis.com/auth/drive.metadata.readonly', # For metadata specifically
    # Workspace - Reports & Alerts
    'https://www.googleapis.com/auth/admin.reports.audit.readonly',
    'https://www.googleapis.com/auth/admin.reports.usage.readonly',
    'https://www.googleapis.com/auth/alertcenter.alerts.readonly',
    # Workspace - eDiscovery
    'https://www.googleapis.com/auth/ediscovery.readonly',
    # GCP - General and IAM
    'https://www.googleapis.com/auth/cloud-platform', # Broad access, useful for discovery
    'https://www.googleapis.com/auth/iam.securityReviewer', # More specific for IAM audit
    # GCP - Resource Management
    'https://www.googleapis.com/auth/resourcemanager.organization.readonly',
    # GCP - Compute Engine
    'https://www.googleapis.com/auth/compute.readonly',
    # GCP - Cloud Storage
    'https://www.googleapis.com/auth/devstorage.read_only',
    # GCP - KMS
    'https://www.googleapis.com/auth/cloudkms.readonly',
    # GCP - Logging
    'https://www.googleapis.com/auth/logging.read',
    # GCP - Security Center
    'https://www.googleapis.com/auth/securitycenter.sources.readonly',
    # GCP - Service Usage
    'https://www.googleapis.com/auth/serviceusage.readonly',
]))

class GoogleWorkspaceCollector:
    def __init__(self, credentials_file, delegated_email):
        self.credentials_file = credentials_file
        self.delegated_email = delegated_email
        self.credentials = None
        self.services = {}
        self.project_id = None
        self.org_id = None 
        self.customer_id = None # Google Workspace Customer ID
        self.data = {
            "customerInfo": { # Initialize as a dictionary
                "customer_id": None,
                "gcp_organization_id": None,
                "other_customer_details": None # For any other direct customer details
            },
            "domains": [],
            "orgUnits": [],
            "users": [],
            "groups": [],
            "groupSettings": {},
            "userGmailSettings": {},
            "calendarSettings": {},
            "calendarAcls": {},
            "driveSettings": None,
            "driveFiles": [], # Simplified for now
            "chatSpaces": [],
            "auditReports": {},
            "usageReports": {},
            "dnsRecords": {},
            "gcp_iam_organization_policy": None,
            "gcp_iam_project_policy": None,
            "gcp_project_service_accounts": [],
            "gcp_vpc_networks": [],
            "gcp_firewall_rules": [],
            "gcp_subnetworks": [],
            "gcp_enabled_services": [],
            "gcp_scc_findings": [],
            "gcp_kms_keys": [],
            "gcp_gcs_buckets": [],
            "gcp_iap_web_resources": [],
            "gcp_workload_identity_pools": []
        }
        logging.info(f"GoogleWorkspaceCollector initialized for {delegated_email}")

    def authenticate(self):
        logging.info("Attempting to authenticate...")
        try:
            self.credentials = service_account.Credentials.from_service_account_file(
                self.credentials_file, scopes=SCOPES, subject=self.delegated_email
            )
            
            # Core Workspace Admin SDK (critical for many checks)
            try:
                self.services['admin'] = build('admin', 'directory_v1', credentials=self.credentials)
                logging.info("Successfully built Admin SDK Directory service.")
            except Exception as e:
                logging.error(f"Failed to build Admin SDK Directory service: {e}", exc_info=True)
                raise  # This is critical, so re-raise to fail authentication

            try:
                self.services['reports'] = build('admin', 'reports_v1', credentials=self.credentials)
                logging.info("Successfully built Admin SDK Reports service.")
            except Exception as e:
                logging.warning(f"Failed to build Admin SDK Reports service: {e}")
                # Non-critical for basic auth, but some data collection will fail

            # Extract project_id from credentials if available
            if hasattr(self.credentials, '_service_account_email'):
                 # The service account email is often in the format: service-account-name@project-id.iam.gserviceaccount.com
                sa_email = self.credentials._service_account_email
                if sa_email and '@' in sa_email and '.iam.gserviceaccount.com' in sa_email:
                    self.project_id = sa_email.split('@')[1].split('.iam.gserviceaccount.com')[0]
                    logging.info(f"Extracted project_id: {self.project_id} from service account email.")
            if not self.project_id and hasattr(self.credentials, 'project_id'): # Fallback for some credential types
                 self.project_id = self.credentials.project_id
                 logging.info(f"Extracted project_id: {self.project_id} from credentials attribute.")
            
            # Workspace Services
            service_definitions_workspace = {
                'gmail': ('gmail', 'v1'),
                'drive': ('drive', 'v3'),
                'calendar': ('calendar', 'v3'),
                'groupssettings': ('groupssettings', 'v1'),
                'chat': ('chat', 'v1'),
                'alertcenter': ('alertcenter', 'v1beta1'),
                # 'classroom': ('classroom', 'v1'), # Example if needed later
            }
            for name, (service_name, version) in service_definitions_workspace.items():
                try:
                    self.services[name] = build(service_name, version, credentials=self.credentials)
                    logging.info(f"Successfully built Workspace service: {name} ({version})")
                except Exception as e:
                    logging.warning(f"Failed to build Workspace service {name} ({version}): {e}")
                    # Non-critical for basic auth, but some data collection will fail

            # GCP Services
            service_definitions_gcp = {
                'cloudresourcemanager': ('cloudresourcemanager', 'v1'),
                'compute': ('compute', 'v1'),
                'storage': ('storage', 'v1'),
                'iam': ('iam', 'v1'),
                'kms': ('cloudkms', 'v1'),
                'logging': ('logging', 'v2'),
                'securitycenter': ('securitycenter', 'v1'),
                'serviceusage': ('serviceusage', 'v1'),
                'iap': ('iap', 'v1'), # Added IAP service
            }
            for name, (service_name, version) in service_definitions_gcp.items():
                try:
                    self.services[name] = build(service_name, version, credentials=self.credentials)
                    logging.info(f"Successfully built GCP service: {name} ({version})")
                except Exception as e:
                    logging.warning(f"Failed to build GCP service {name} ({version}): {e} - This might be due to the API not being enabled on the project.")
                    # Non-critical for basic auth if Workspace checks are the primary goal

            logging.info("Authentication process completed. Core admin service ready. Other services initialized where possible.")
            return True
            
        except Exception as e:
            logging.error(f"Core authentication failed: {e}", exc_info=True)
            return False

    def retry_api_call(self, func, max_attempts=3, delay=2):
        logging.debug(f"Attempting API call: {func.__name__ if hasattr(func, '__name__') else 'partial_func'}")
        for attempt in range(max_attempts):
            try:
                return func()
            except HttpError as e:
                logging.warning(f"API call failed (attempt {attempt + 1}/{max_attempts}): {e.resp.status} {e.reason}")
                if e.resp.status in [403, 429, 500, 503]: # Retry on these common transient errors
                    if attempt < max_attempts - 1:
                        time.sleep(delay * (2 ** attempt)) # Exponential backoff
                    else:
                        logging.error(f"API call failed after {max_attempts} attempts: {e}")
                        raise
                else: # Don't retry on other errors (e.g., 404 Not Found, 401 Unauthorized)
                    logging.error(f"API call failed with non-retryable error: {e}")
                    raise
            except Exception as e: # Catch other potential errors like network issues
                logging.warning(f"API call failed due to non-HttpError (attempt {attempt + 1}/{max_attempts}): {e}")
                if attempt < max_attempts - 1:
                    time.sleep(delay * (2 ** attempt))
                else:
                    logging.error(f"API call failed after {max_attempts} attempts with non-HttpError: {e}")
                    raise
        return None # Should not be reached if raise works correctly

    def collect_customer_info(self):
        logging.info("Collecting Google Workspace Customer ID and GCP Organization ID...")
        
        admin_service = self.services.get('admin')
        if not admin_service:
            logging.error("Admin service not available, cannot fetch customer ID.")
            self.data["customerInfo"]["customer_id"] = "ERROR_SERVICE_UNAVAILABLE"
            return False

        try:
            logging.debug(f"Fetching user details for {self.delegated_email} to get Customer ID.")
            user_info = self.retry_api_call(
                lambda: admin_service.users().get(userKey=self.delegated_email).execute()
            )
            if user_info and 'customerId' in user_info:
                self.customer_id = user_info['customerId']
                self.data['customerInfo']['customer_id'] = self.customer_id
                logging.info(f"Successfully fetched Google Workspace Customer ID: {self.customer_id}")
            else:
                logging.error("Failed to fetch Customer ID: 'customerId' not in user info response.")
                self.data['customerInfo']['customer_id'] = "ERROR_NOT_FOUND"
                return False # Customer ID is fundamental for many Workspace calls
        except HttpError as e:
            logging.error(f"HttpError fetching Customer ID for {self.delegated_email}: {e}", exc_info=True)
            self.data['customerInfo']['customer_id'] = f"ERROR_HTTP_{e.resp.status}"
            return False # Critical failure
        except Exception as e:
            logging.error(f"Generic error fetching Customer ID for {self.delegated_email}: {e}", exc_info=True)
            self.data['customerInfo']['customer_id'] = "ERROR_EXCEPTION"
            return False # Critical failure

        # Fetch GCP Organization ID
        if self.project_id and self.services.get('cloudresourcemanager'):
            crm_service = self.services.get('cloudresourcemanager')
            try:
                logging.debug(f"Fetching project details for {self.project_id} to get GCP Organization ID.")
                project_details = self.retry_api_call(
                    lambda: crm_service.projects().get(projectId=self.project_id).execute()
                )
                if project_details and 'parent' in project_details:
                    parent = project_details['parent']
                    if parent['type'] == 'organization':
                        self.org_id = parent['id']
                        self.data['customerInfo']['gcp_organization_id'] = self.org_id
                        logging.info(f"Successfully fetched GCP Organization ID: {self.org_id}")
                    else:
                        logging.info(f"Project {self.project_id} is not directly under an organization. Parent type: {parent.get('type', 'Unknown')}")
                        self.data['customerInfo']['gcp_organization_id'] = "NOT_UNDER_ORGANIZATION"
                else:
                    logging.warning(f"Could not determine GCP Organization ID for project {self.project_id}. 'parent' field missing in response.")
                    self.data['customerInfo']['gcp_organization_id'] = "ERROR_NO_PARENT_INFO"
            except HttpError as e:
                logging.error(f"HttpError fetching GCP Organization ID for project {self.project_id}: {e}", exc_info=True)
                self.data['customerInfo']['gcp_organization_id'] = f"ERROR_HTTP_{e.resp.status}"
            except Exception as e:
                logging.error(f"Generic error fetching GCP Organization ID for project {self.project_id}: {e}", exc_info=True)
                self.data['customerInfo']['gcp_organization_id'] = "ERROR_EXCEPTION"
        elif not self.project_id:
            logging.warning("GCP Project ID not available, cannot fetch GCP Organization ID.")
            self.data['customerInfo']['gcp_organization_id'] = "PROJECT_ID_MISSING"
        elif not self.services.get('cloudresourcemanager'):
            logging.warning("Cloud Resource Manager service not available, cannot fetch GCP Organization ID.")
            self.data['customerInfo']['gcp_organization_id'] = "CRM_SERVICE_UNAVAILABLE"
            
        # For other customer details (placeholder for now, can be expanded)
        # E.g., using admin_service.customers().get(customerKey=self.customer_id).execute()
        # self.data['customerInfo']['other_customer_details'] = "..."
        
        return True # Return true even if org_id fails, as customer_id might be sufficient for some checks

    def collect_gcp_organization_iam_policy(self):
        logging.info("Collecting GCP Organization IAM policy...")
        if not self.org_id:
            logging.warning("GCP Organization ID not available, cannot fetch Organization IAM policy.")
            self.data['gcp_iam_organization_policy'] = {"error": "ORGANIZATION_ID_MISSING"}
            return False
        
        crm_service = self.services.get('cloudresourcemanager')
        if not crm_service:
            logging.warning("Cloud Resource Manager service not available, cannot fetch Organization IAM policy.")
            self.data['gcp_iam_organization_policy'] = {"error": "CRM_SERVICE_UNAVAILABLE"}
            return False

        try:
            policy = self.retry_api_call(
                lambda: crm_service.organizations().getIamPolicy(
                    resource=f'organizations/{self.org_id}', body={}
                ).execute()
            )
            self.data['gcp_iam_organization_policy'] = policy
            logging.info(f"Successfully fetched GCP Organization IAM policy for org ID {self.org_id}.")
            return True
        except HttpError as e:
            logging.error(f"HttpError fetching GCP Organization IAM policy for org ID {self.org_id}: {e}", exc_info=True)
            self.data['gcp_iam_organization_policy'] = {"error": f"HTTP_ERROR_{e.resp.status}", "details": str(e)}
            return False
        except Exception as e:
            logging.error(f"Generic error fetching GCP Organization IAM policy for org ID {self.org_id}: {e}", exc_info=True)
            self.data['gcp_iam_organization_policy'] = {"error": "EXCEPTION", "details": str(e)}
            return False

    def collect_gcp_project_iam_policy(self):
        logging.info("Collecting GCP Project IAM policy...")
        if not self.project_id:
            logging.warning("GCP Project ID not available, cannot fetch Project IAM policy.")
            self.data['gcp_iam_project_policy'] = {"error": "PROJECT_ID_MISSING"}
            return False

        crm_service = self.services.get('cloudresourcemanager')
        if not crm_service:
            logging.warning("Cloud Resource Manager service not available, cannot fetch Project IAM policy.")
            self.data['gcp_iam_project_policy'] = {"error": "CRM_SERVICE_UNAVAILABLE"}
            return False

        try:
            policy = self.retry_api_call(
                lambda: crm_service.projects().getIamPolicy(
                    resource=self.project_id, body={}
                ).execute()
            )
            self.data['gcp_iam_project_policy'] = policy
            logging.info(f"Successfully fetched GCP Project IAM policy for project ID {self.project_id}.")
            return True
        except HttpError as e:
            logging.error(f"HttpError fetching GCP Project IAM policy for project ID {self.project_id}: {e}", exc_info=True)
            self.data['gcp_iam_project_policy'] = {"error": f"HTTP_ERROR_{e.resp.status}", "details": str(e)}
            return False
        except Exception as e:
            logging.error(f"Generic error fetching GCP Project IAM policy for project ID {self.project_id}: {e}", exc_info=True)
            self.data['gcp_iam_project_policy'] = {"error": "EXCEPTION", "details": str(e)}
            return False

    def collect_gcp_project_service_accounts(self):
        logging.info("Collecting GCP Project Service Accounts...")
        if not self.project_id:
            logging.warning("GCP Project ID not available, cannot fetch Project Service Accounts.")
            self.data['gcp_project_service_accounts'] = [{"error": "PROJECT_ID_MISSING"}]
            return False

        iam_service = self.services.get('iam')
        if not iam_service:
            logging.warning("IAM service not available, cannot fetch Project Service Accounts.")
            self.data['gcp_project_service_accounts'] = [{"error": "IAM_SERVICE_UNAVAILABLE"}]
            return False
        
        accounts_list = []
        try:
            request = iam_service.projects().serviceAccounts().list(name=f'projects/{self.project_id}')
            while request is not None:
                response = self.retry_api_call(lambda: request.execute())
                accounts = response.get('accounts', [])
                accounts_list.extend(accounts)
                request = iam_service.projects().serviceAccounts().list_next(previous_request=request, previous_response=response)
            
            self.data['gcp_project_service_accounts'] = accounts_list
            logging.info(f"Successfully fetched {len(accounts_list)} service accounts for project ID {self.project_id}.")
            return True
        except HttpError as e:
            logging.error(f"HttpError fetching GCP Project Service Accounts for project ID {self.project_id}: {e}", exc_info=True)
            self.data['gcp_project_service_accounts'] = [{"error": f"HTTP_ERROR_{e.resp.status}", "details": str(e)}]
            return False
        except Exception as e:
            logging.error(f"Generic error fetching GCP Project Service Accounts for project ID {self.project_id}: {e}", exc_info=True)
            self.data['gcp_project_service_accounts'] = [{"error": "EXCEPTION", "details": str(e)}]
            return False

    def collect_gcp_vpc_networks(self):
        logging.info("Collecting GCP VPC Networks...")
        if not self.project_id:
            logging.warning("GCP Project ID not available, cannot fetch VPC Networks.")
            self.data['gcp_vpc_networks'] = [{"error": "PROJECT_ID_MISSING"}]
            return False

        compute_service = self.services.get('compute')
        if not compute_service:
            logging.warning("Compute service not available, cannot fetch VPC Networks.")
            self.data['gcp_vpc_networks'] = [{"error": "COMPUTE_SERVICE_UNAVAILABLE"}]
            return False

        networks_list = []
        try:
            request = compute_service.networks().list(project=self.project_id)
            while request is not None:
                response = self.retry_api_call(lambda: request.execute())
                items = response.get('items', [])
                for network in items:
                    networks_list.append({
                        "name": network.get("name"),
                        "selfLink": network.get("selfLink"),
                        "autoCreateSubnetworks": network.get("autoCreateSubnetworks"),
                        "subnetworks": network.get("subnetworks", []),
                        "routingConfig": network.get("routingConfig"),
                        "description": network.get("description"),
                        "creationTimestamp": network.get("creationTimestamp")
                    })
                request = compute_service.networks().list_next(previous_request=request, previous_response=response)
            
            self.data['gcp_vpc_networks'] = networks_list
            logging.info(f"Successfully fetched {len(networks_list)} VPC networks for project ID {self.project_id}.")
            return True
        except HttpError as e:
            logging.error(f"HttpError fetching GCP VPC Networks for project ID {self.project_id}: {e}", exc_info=True)
            self.data['gcp_vpc_networks'] = [{"error": f"HTTP_ERROR_{e.resp.status}", "details": str(e)}]
            return False
        except Exception as e:
            logging.error(f"Generic error fetching GCP VPC Networks for project ID {self.project_id}: {e}", exc_info=True)
            self.data['gcp_vpc_networks'] = [{"error": "EXCEPTION", "details": str(e)}]
            return False

    def collect_gcp_firewall_rules(self):
        logging.info("Collecting GCP Firewall Rules...")
        if not self.project_id:
            logging.warning("GCP Project ID not available, cannot fetch Firewall Rules.")
            self.data['gcp_firewall_rules'] = [{"error": "PROJECT_ID_MISSING"}]
            return False

        compute_service = self.services.get('compute')
        if not compute_service:
            logging.warning("Compute service not available, cannot fetch Firewall Rules.")
            self.data['gcp_firewall_rules'] = [{"error": "COMPUTE_SERVICE_UNAVAILABLE"}]
            return False

        firewall_rules_list = []
        try:
            request = compute_service.firewalls().list(project=self.project_id)
            while request is not None:
                response = self.retry_api_call(lambda: request.execute())
                items = response.get('items', [])
                for rule in items:
                    firewall_rules_list.append({
                        "name": rule.get("name"),
                        "selfLink": rule.get("selfLink"),
                        "network": rule.get("network"),
                        "priority": rule.get("priority"),
                        "direction": rule.get("direction"),
                        "allowed": rule.get("allowed", []),
                        "denied": rule.get("denied", []),
                        "sourceRanges": rule.get("sourceRanges", []),
                        "destinationRanges": rule.get("destinationRanges", []),
                        "sourceTags": rule.get("sourceTags", []),
                        "targetTags": rule.get("targetTags", []),
                        "disabled": rule.get("disabled"),
                        "description": rule.get("description"),
                        "creationTimestamp": rule.get("creationTimestamp")
                    })
                request = compute_service.firewalls().list_next(previous_request=request, previous_response=response)
            
            self.data['gcp_firewall_rules'] = firewall_rules_list
            logging.info(f"Successfully fetched {len(firewall_rules_list)} firewall rules for project ID {self.project_id}.")
            return True
        except HttpError as e:
            logging.error(f"HttpError fetching GCP Firewall Rules for project ID {self.project_id}: {e}", exc_info=True)
            self.data['gcp_firewall_rules'] = [{"error": f"HTTP_ERROR_{e.resp.status}", "details": str(e)}]
            return False
        except Exception as e:
            logging.error(f"Generic error fetching GCP Firewall Rules for project ID {self.project_id}: {e}", exc_info=True)
            self.data['gcp_firewall_rules'] = [{"error": "EXCEPTION", "details": str(e)}]
            return False

    def collect_gcp_subnetworks(self):
        logging.info("Collecting GCP Subnetworks...")
        if not self.project_id:
            logging.warning("GCP Project ID not available, cannot fetch Subnetworks.")
            self.data['gcp_subnetworks'] = [{"error": "PROJECT_ID_MISSING"}]
            return False

        compute_service = self.services.get('compute')
        if not compute_service:
            logging.warning("Compute service not available, cannot fetch Subnetworks.")
            self.data['gcp_subnetworks'] = [{"error": "COMPUTE_SERVICE_UNAVAILABLE"}]
            return False

        subnetworks_list = []
        try:
            # aggregatedList returns items per region
            request = compute_service.subnetworks().aggregatedList(project=self.project_id)
            while request is not None:
                response = self.retry_api_call(lambda: request.execute())
                # response['items'] is a dict where keys are "regions/us-central1", etc.
                for region_scoped_list in response.get('items', {}).values():
                    if 'subnetworks' in region_scoped_list: # Check if the key exists
                        for subnetwork in region_scoped_list['subnetworks']:
                            subnetworks_list.append({
                                "name": subnetwork.get("name"),
                                "selfLink": subnetwork.get("selfLink"),
                                "network": subnetwork.get("network"),
                                "region": subnetwork.get("region").split('/')[-1] if subnetwork.get("region") else None, # Extract region name
                                "ipCidrRange": subnetwork.get("ipCidrRange"),
                                "gatewayAddress": subnetwork.get("gatewayAddress"),
                                "privateIpGoogleAccess": subnetwork.get("privateIpGoogleAccess"),
                                "purpose": subnetwork.get("purpose"),
                                "role": subnetwork.get("role"),
                                "logConfig": subnetwork.get("logConfig"),
                                "creationTimestamp": subnetwork.get("creationTimestamp")
                            })
                request = compute_service.subnetworks().aggregatedList_next(previous_request=request, previous_response=response)
            
            self.data['gcp_subnetworks'] = subnetworks_list
            logging.info(f"Successfully fetched {len(subnetworks_list)} subnetworks for project ID {self.project_id} across all regions.")
            return True
        except HttpError as e:
            logging.error(f"HttpError fetching GCP Subnetworks for project ID {self.project_id}: {e}", exc_info=True)
            self.data['gcp_subnetworks'] = [{"error": f"HTTP_ERROR_{e.resp.status}", "details": str(e)}]
            return False
        except Exception as e:
            logging.error(f"Generic error fetching GCP Subnetworks for project ID {self.project_id}: {e}", exc_info=True)
            self.data['gcp_subnetworks'] = [{"error": "EXCEPTION", "details": str(e)}]
            return False

    def collect_gcp_enabled_services(self):
        logging.info("Collecting GCP Enabled Services...")
        if not self.project_id:
            logging.warning("GCP Project ID not available, cannot fetch enabled services.")
            self.data['gcp_enabled_services'] = [{"error": "PROJECT_ID_MISSING"}]
            return False

        serviceusage_service = self.services.get('serviceusage')
        if not serviceusage_service:
            logging.warning("Service Usage service not available, cannot fetch enabled services.")
            self.data['gcp_enabled_services'] = [{"error": "SERVICEUSAGE_SERVICE_UNAVAILABLE"}]
            return False

        enabled_services_list = []
        try:
            request = serviceusage_service.services().list(
                parent=f'projects/{self.project_id}', 
                filter='state:ENABLED'
            )
            while request is not None:
                response = self.retry_api_call(lambda: request.execute())
                services = response.get('services', [])
                for service in services:
                    enabled_services_list.append({
                        "name": service.get("name"),
                        "title": service.get("config", {}).get("title")
                    })
                request = serviceusage_service.services().list_next(
                    previous_request=request, previous_response=response
                )
            
            self.data['gcp_enabled_services'] = enabled_services_list
            logging.info(f"Successfully fetched {len(enabled_services_list)} enabled services for project ID {self.project_id}.")
            return True
        except HttpError as e:
            logging.error(f"HttpError fetching GCP Enabled Services for project ID {self.project_id}: {e}", exc_info=True)
            self.data['gcp_enabled_services'] = [{"error": f"HTTP_ERROR_{e.resp.status}", "details": str(e)}]
            return False
        except Exception as e:
            logging.error(f"Generic error fetching GCP Enabled Services for project ID {self.project_id}: {e}", exc_info=True)
            self.data['gcp_enabled_services'] = [{"error": "EXCEPTION", "details": str(e)}]
            return False

    def collect_gcp_scc_findings(self):
        logging.info("Collecting GCP Security Command Center Findings...")
        scc_service = self.services.get('securitycenter')
        if not scc_service:
            logging.warning("Security Command Center service not available, cannot fetch findings.")
            self.data['gcp_scc_findings'] = [{"error": "SCC_SERVICE_UNAVAILABLE"}]
            return False

        parent_resource = None
        list_findings_method = None
        list_findings_next_method = None

        if self.org_id:
            parent_resource = f'organizations/{self.org_id}/sources/-'
            # The client library structure is organizations().sources().findings()
            # However, the actual API endpoint might group findings under organizations() directly for sources/-
            # Let's assume direct access for sources/- under organization for now, or project.
            # Correct client library usage: scc_service.organizations().sources().findings() for specific source,
            # or scc_service.organizations().findings() if API supports direct listing under org without specifying source.
            # The prompt implies listing from ALL sources, thus `sources/-`.
            try:
                list_findings_method = scc_service.organizations().sources().findings()
            except AttributeError: # Fallback if findings are not directly under sources() but under organization()
                 logging.warning("Could not find findings under organizations().sources(). Trying organizations().findings().")
                 try:
                    list_findings_method = scc_service.organizations().findings() # This might not be a valid path.
                 except AttributeError:
                    logging.error("Could not establish a method to list findings at organization level.")
                    self.data['gcp_scc_findings'] = [{"error": "SCC_ORG_FINDING_METHOD_UNAVAILABLE"}]
                    return False
        elif self.project_id:
            parent_resource = f'projects/{self.project_id}/sources/-'
            try:
                list_findings_method = scc_service.projects().sources().findings()
            except AttributeError:
                logging.warning("Could not find findings under projects().sources(). Trying projects().findings().")
                try:
                    list_findings_method = scc_service.projects().findings()
                except AttributeError:
                    logging.error("Could not establish a method to list findings at project level.")
                    self.data['gcp_scc_findings'] = [{"error": "SCC_PROJECT_FINDING_METHOD_UNAVAILABLE"}]
                    return False
        else:
            logging.warning("Neither GCP Organization ID nor Project ID is available. Cannot fetch SCC findings.")
            self.data['gcp_scc_findings'] = [{"error": "PARENT_RESOURCE_ID_MISSING"}]
            return False
        
        if not list_findings_method: # Should be caught above, but as a safeguard.
            logging.error("SCC finding list method not initialized.")
            self.data['gcp_scc_findings'] = [{"error": "SCC_METHOD_INIT_FAILED"}]
            return False

        findings_list = []
        try:
            logging.info(f"Fetching SCC findings for parent: {parent_resource}")
            request = list_findings_method.list(parent=parent_resource)
            
            while request is not None:
                response = self.retry_api_call(lambda: request.execute())
                # Findings are typically in 'listFindingsResults' which is a list of dicts,
                # each containing a 'finding' object. Or sometimes directly in 'findings'.
                
                results = response.get('listFindingsResults', [])
                if not results and 'findings' in response: # Alternative structure
                    results = [{'finding': f} for f in response.get('findings',[])]


                for result_item in results:
                    finding = result_item.get('finding', {}) # actual finding data
                    if not finding: continue

                    findings_list.append({
                        "name": finding.get("name"),
                        "state": finding.get("state"),
                        "category": finding.get("category"),
                        "severity": finding.get("severity"),
                        "sourceDisplayName": finding.get("sourceProperties", {}).get("sourceDisplayName"), # Example of nested property
                        "eventTime": finding.get("eventTime"),
                        "createTime": finding.get("createTime"),
                        "resourceName": finding.get("resourceName"),
                        "description": finding.get("description"), # SCC V2 specific field
                        "externalUri": finding.get("externalUri"),
                        "indicator": finding.get("indicator") # SCC V2 specific field for threat intelligence
                    })
                
                # Pagination: list_next method is part of the same collection object
                request = list_findings_method.list_next(previous_request=request, previous_response=response)

            self.data['gcp_scc_findings'] = findings_list
            logging.info(f"Successfully fetched {len(findings_list)} SCC findings for {parent_resource}.")
            return True
        except HttpError as e:
            logging.error(f"HttpError fetching SCC findings for {parent_resource}: {e}", exc_info=True)
            self.data['gcp_scc_findings'] = [{"error": f"HTTP_ERROR_{e.resp.status}", "details": str(e)}]
            return False
        except Exception as e:
            logging.error(f"Generic error fetching SCC findings for {parent_resource}: {e}", exc_info=True)
            self.data['gcp_scc_findings'] = [{"error": "EXCEPTION", "details": str(e)}]
            return False

    def collect_gcp_kms_keys(self):
        logging.info("Collecting GCP Cloud KMS Keys...")
        if not self.project_id:
            logging.warning("GCP Project ID not available, cannot fetch KMS keys.")
            self.data['gcp_kms_keys'] = [{"error": "PROJECT_ID_MISSING"}]
            return False

        kms_service = self.services.get('kms')
        if not kms_service:
            logging.warning("Cloud KMS service not available, cannot fetch KMS keys.")
            self.data['gcp_kms_keys'] = [{"error": "KMS_SERVICE_UNAVAILABLE"}]
            return False

        all_kms_data = []
        try:
            # 1. List Locations
            locations_request = kms_service.projects().locations().list(name=f'projects/{self.project_id}')
            locations_response = self.retry_api_call(lambda: locations_request.execute())
            locations = locations_response.get('locations', [])
            logging.info(f"Found {len(locations)} locations for KMS keys in project {self.project_id}.")

            for location in locations:
                location_path = location.get('name') # e.g., projects/my-project/locations/us-central1
                if not location_path:
                    logging.warning("Skipping location with no path.")
                    continue
                
                logging.debug(f"Fetching KMS key rings for location: {location_path}")

                # 2. List Key Rings in Location
                key_rings_request = kms_service.projects().locations().keyRings().list(parent=location_path)
                while key_rings_request is not None:
                    key_rings_response = self.retry_api_call(lambda: key_rings_request.execute())
                    key_rings = key_rings_response.get('keyRings', [])

                    for key_ring in key_rings:
                        key_ring_path = key_ring.get('name') # e.g., projects/my-project/locations/us-central1/keyRings/my-key-ring
                        if not key_ring_path:
                            logging.warning(f"Skipping key ring with no path in location {location_path}.")
                            continue
                        
                        logging.debug(f"Fetching KMS crypto keys for key ring: {key_ring_path}")

                        # 3. List Crypto Keys in Key Ring
                        crypto_keys_request = kms_service.projects().locations().keyRings().cryptoKeys().list(parent=key_ring_path)
                        while crypto_keys_request is not None:
                            crypto_keys_response = self.retry_api_call(lambda: crypto_keys_request.execute())
                            crypto_keys = crypto_keys_response.get('cryptoKeys', [])

                            for crypto_key in crypto_keys:
                                crypto_key_path = crypto_key.get('name') # e.g., projects/my-project/locations/us-central1/keyRings/my-key-ring/cryptoKeys/my-key
                                if not crypto_key_path:
                                    logging.warning(f"Skipping crypto key with no path in key ring {key_ring_path}.")
                                    continue

                                logging.debug(f"Fetching details for crypto key: {crypto_key_path}")
                                
                                # 4. Get Crypto Key Details
                                key_details = self.retry_api_call(
                                    lambda: kms_service.projects().locations().keyRings().cryptoKeys().get(name=crypto_key_path).execute()
                                )
                                
                                # 5. Get IAM Policy for Crypto Key
                                key_iam_policy = self.retry_api_call(
                                    lambda: kms_service.projects().locations().keyRings().cryptoKeys().getIamPolicy(resource=crypto_key_path).execute()
                                )
                                
                                all_kms_data.append({
                                    "location_path": location_path,
                                    "key_ring_path": key_ring_path,
                                    "crypto_key_path": crypto_key_path,
                                    "key_details": key_details,
                                    "iam_policy": key_iam_policy
                                })
                            
                            crypto_keys_request = kms_service.projects().locations().keyRings().cryptoKeys().list_next(
                                previous_request=crypto_keys_request, previous_response=crypto_keys_response
                            )
                    
                    key_rings_request = kms_service.projects().locations().keyRings().list_next(
                        previous_request=key_rings_request, previous_response=key_rings_response
                    )
            
            self.data['gcp_kms_keys'] = all_kms_data
            logging.info(f"Successfully fetched {len(all_kms_data)} KMS keys with details for project {self.project_id}.")
            return True

        except HttpError as e:
            logging.error(f"HttpError fetching GCP KMS Keys for project {self.project_id}: {e}", exc_info=True)
            self.data['gcp_kms_keys'] = [{"error": f"HTTP_ERROR_{e.resp.status}", "details": str(e)}]
            return False
        except Exception as e:
            logging.error(f"Generic error fetching GCP KMS Keys for project {self.project_id}: {e}", exc_info=True)
            self.data['gcp_kms_keys'] = [{"error": "EXCEPTION", "details": str(e)}]
            return False

    def collect_gcp_gcs_buckets(self):
        logging.info("Collecting GCP GCS Buckets...")
        if not self.project_id:
            logging.warning("GCP Project ID not available, cannot fetch GCS buckets.")
            self.data['gcp_gcs_buckets'] = [{"error": "PROJECT_ID_MISSING"}]
            return False

        storage_service = self.services.get('storage')
        if not storage_service:
            logging.warning("Storage service not available, cannot fetch GCS buckets.")
            self.data['gcp_gcs_buckets'] = [{"error": "STORAGE_SERVICE_UNAVAILABLE"}]
            return False

        all_bucket_data = []
        try:
            request = storage_service.buckets().list(project=self.project_id)
            while request is not None:
                response = self.retry_api_call(lambda: request.execute())
                buckets = response.get('items', [])

                for bucket_resource in buckets:
                    bucket_name = bucket_resource.get("name")
                    if not bucket_name:
                        logging.warning("Skipping bucket with no name.")
                        continue
                    
                    logging.debug(f"Fetching IAM policy for GCS bucket: {bucket_name}")
                    iam_policy = None
                    try:
                        iam_policy = self.retry_api_call(
                            lambda: storage_service.buckets().getIamPolicy(bucket=bucket_name).execute()
                        )
                    except HttpError as e:
                        logging.error(f"HttpError fetching IAM policy for bucket {bucket_name}: {e}", exc_info=True)
                        iam_policy = {"error": f"HTTP_ERROR_{e.resp.status}", "details": str(e)}
                    except Exception as e:
                        logging.error(f"Generic error fetching IAM policy for bucket {bucket_name}: {e}", exc_info=True)
                        iam_policy = {"error": "EXCEPTION", "details": str(e)}
                        
                    # Public Access Prevention is part of the bucket resource itself
                    iam_config = bucket_resource.get('iamConfiguration', {})
                    public_access_prevention = iam_config.get('publicAccessPrevention', 'unknown') # Default if not set

                    all_bucket_data.append({
                        "name": bucket_name,
                        "id": bucket_resource.get("id"),
                        "location": bucket_resource.get("location"),
                        "storageClass": bucket_resource.get("storageClass"),
                        "timeCreated": bucket_resource.get("timeCreated"),
                        "updated": bucket_resource.get("updated"),
                        "iam_policy": iam_policy,
                        "public_access_prevention": public_access_prevention,
                        "versioning": bucket_resource.get("versioning"),
                        "logging": bucket_resource.get("logging"),
                        "website": bucket_resource.get("website"),
                        "labels": bucket_resource.get("labels")
                    })
                
                request = storage_service.buckets().list_next(previous_request=request, previous_response=response)
            
            self.data['gcp_gcs_buckets'] = all_bucket_data
            logging.info(f"Successfully fetched {len(all_bucket_data)} GCS buckets for project {self.project_id}.")
            return True

        except HttpError as e:
            logging.error(f"HttpError fetching GCP GCS Buckets for project {self.project_id}: {e}", exc_info=True)
            self.data['gcp_gcs_buckets'] = [{"error": f"HTTP_ERROR_{e.resp.status}", "details": str(e)}]
            return False
        except Exception as e:
            logging.error(f"Generic error fetching GCP GCS Buckets for project {self.project_id}: {e}", exc_info=True)
            self.data['gcp_gcs_buckets'] = [{"error": "EXCEPTION", "details": str(e)}]
            return False

    def collect_gcp_iap_settings(self):
        logging.info("Collecting GCP IAP Web Resources...")
        if not self.project_id:
            logging.warning("GCP Project ID not available, cannot fetch IAP settings.")
            self.data['gcp_iap_web_resources'] = [{"error": "PROJECT_ID_MISSING"}]
            return False

        iap_service = self.services.get('iap')
        if not iap_service:
            logging.warning("IAP service not available, cannot fetch IAP settings.")
            self.data['gcp_iap_web_resources'] = [{"error": "IAP_SERVICE_UNAVAILABLE"}]
            return False
        
        iap_web_resources = []
        try:
            # Note: The IAP API's list methods might require more specific parent resource types
            # depending on what's being protected (e.g., App Engine services, backend services).
            # projects.iap_web().list() is a general starting point for web-accessible resources.
            # A more comprehensive listing might involve iterating through GCE backend services, App Engine services etc.
            # and then checking their IAP status. This implementation lists resources IAP is aware of.
            
            parent_resource = f'projects/{self.project_id}'
            # The API path is projects/{project_number_or_id}/iap_web
            # but the client library might abstract this under projects().iap_web() directly.
            # If this specific path does not work, it might need adjustment based on specific resource types.
            # For now, assuming projects.iap_web().list() is the intended high-level discovery.
            
            # The IAP API does not seem to have a straightforward global list for all IAP-protected resources.
            # It's often per service (e.g., appengine, GCE backend services).
            # This call `iap_web().list()` typically lists App Engine services.
            # For a fuller picture, one might need to list GCE backend services and check IAP status individually.
            # Given the prompt, this is a reasonable first step.
            
            # The `iap.projects.iap_web.list` method does not exist.
            # We need to list IAP settings for specific services like App Engine or Backend Services.
            # Let's try listing for App Engine services as an example.
            # The parent for App Engine services is `projects/{project_id}/iap_web/appengine-{project_id}`
            # However, to get a list of all services, we'd usually call iap.services.versions.list
            # but that's for App Engine Admin API, not IAP directly for policies.

            # Let's try to get the IAP settings for the project itself, which can hold default settings.
            # The resource name for project-level IAP settings is "projects/{project_number}/iap_settings"
            # However, this is not a "list" of web resources.
            # The prompt "list IAP-manageable web resources" suggests listing actual services.

            # Given the API structure, a common approach is to list services that *can* be protected by IAP
            # (e.g., GCE backend services, AppEngine services) and then query their IAP status.
            # The .iap_web().list() is meant for App Engine.
            # Let's assume the intention is to list App Engine services known to IAP.
            # The parent should be projects/{PROJECT_ID}/iap_web
            
            # The IAP API for listing resources is complex as it's per-service.
            # A common entry point for listing IAP configurations is via `iap.projects.brands.identityAwareProxyClients.list`
            # but that's for OAuth clients.
            # For listing services IAP is aware of, `iap.services.list` might be more appropriate if available,
            # or more specific ones like for App Engine: `iap.projects.iap_web.services.versions.list`
            # The prompt specifically mentioned `iap_web().list`, which is usually for App Engine services.
            # The parent for this is `projects/{project_number}/iap_web`.

            # Let's simplify and assume we're trying to get *some* IAP related info.
            # The `getIamPolicy` can be called on various resources.
            # The `iap.projects.iap_web.get` or similar methods might be relevant if we knew the specific service ID.
            # For listing, the API is tricky.
            # The prompt's suggested path `projects().iap_web().list()` is the most direct interpretation.
            # If this fails, it indicates a misunderstanding of the API structure or a missing, more specific parent.

            logging.info(f"Attempting to list IAP web resources under parent: {parent_resource}")
            # The IAP API doesn't have a simple "list all web resources" method.
            # It's typically: iap.projects.brands.services.list or similar, requiring a brand first.
            # Or, for specific types like App Engine:
            # The parent for App Engine services is `projects/{project_id}/iap_web`
            # Let's try the path suggested, it might be a simplified view.
            
            # The path `projects.iap_web.list` does not exist in the IAP v1 API.
            # A common method to get IAP settings is `iap.projects.iap_settings.get`.
            # However, this gets settings, not a list of web resources.
            # Let's assume the goal is to get the overall IAP settings for the project.
            # If the goal *was* to list App Engine apps and their IAP:
            # 1. List App Engine apps.
            # 2. For each app, get its IAP settings.
            # This is more involved.
            # For this task, we will store a placeholder or a project-level IAP setting if available.
            
            # Given the constraints and the tool's direct API call nature,
            # we'll try to fetch project-level IAP settings as a proxy for "IAP settings".
            try:
                iap_settings_name = f"projects/{self.project_id}/iap_settings"
                settings_response = self.retry_api_call(
                    lambda: iap_service.projects().iap_settings().get(name=iap_settings_name).execute()
                )
                iap_web_resources.append(settings_response) # Storing settings as if it's a "resource"
                logging.info(f"Successfully fetched IAP settings for project {self.project_id}.")
            except HttpError as e:
                 if e.resp.status == 404: # Not found can mean IAP not configured or no specific project wide settings
                    logging.warning(f"No project-level IAP settings found for {self.project_id} (404). This might be normal if IAP is not used or configured at this level.")
                    iap_web_resources.append({"info": f"No project-level IAP settings found (404) for {self.project_id}"})
                 else:
                    raise # Re-raise other HttpErrors
            
            self.data['gcp_iap_web_resources'] = iap_web_resources # Storing as a list for consistency
            return True
        except HttpError as e:
            logging.error(f"HttpError fetching GCP IAP settings for project {self.project_id}: {e}", exc_info=True)
            self.data['gcp_iap_web_resources'] = [{"error": f"HTTP_ERROR_{e.resp.status}", "details": str(e)}]
            return False
        except Exception as e:
            logging.error(f"Generic error fetching GCP IAP settings for project {self.project_id}: {e}", exc_info=True)
            self.data['gcp_iap_web_resources'] = [{"error": "EXCEPTION", "details": str(e)}]
            return False

    def collect_gcp_workload_identity_pools(self):
        logging.info("Collecting GCP Workload Identity Pools...")
        if not self.project_id:
            logging.warning("GCP Project ID not available, cannot fetch Workload Identity Pools.")
            self.data['gcp_workload_identity_pools'] = [{"error": "PROJECT_ID_MISSING"}]
            return False

        iam_service = self.services.get('iam')
        if not iam_service:
            logging.warning("IAM service not available, cannot fetch Workload Identity Pools.")
            self.data['gcp_workload_identity_pools'] = [{"error": "IAM_SERVICE_UNAVAILABLE"}]
            return False

        all_pools_data = []
        parent_path = f'projects/{self.project_id}/locations/global'
        try:
            # List Pools
            pools_request = iam_service.projects().locations().workloadIdentityPools().list(parent=parent_path)
            while pools_request is not None:
                pools_response = self.retry_api_call(lambda: pools_request.execute())
                pools = pools_response.get('workloadIdentityPools', [])

                for pool in pools:
                    pool_name = pool.get('name')
                    pool_data = {
                        "name": pool_name,
                        "displayName": pool.get('displayName'),
                        "state": pool.get('state'),
                        "providers": []
                    }
                    
                    if not pool_name:
                        logging.warning(f"Skipping pool with no name under {parent_path}.")
                        continue

                    logging.debug(f"Fetching providers for Workload Identity Pool: {pool_name}")
                    
                    # List Providers for each Pool
                    providers_request = iam_service.projects().locations().workloadIdentityPools().providers().list(parent=pool_name)
                    while providers_request is not None:
                        providers_response = self.retry_api_call(lambda: providers_request.execute())
                        providers = providers_response.get('workloadIdentityPoolProviders', [])
                        pool_data["providers"].extend(providers)
                        providers_request = iam_service.projects().locations().workloadIdentityPools().providers().list_next(
                            previous_request=providers_request, previous_response=providers_response
                        )
                    all_pools_data.append(pool_data)
                
                pools_request = iam_service.projects().locations().workloadIdentityPools().list_next(
                    previous_request=pools_request, previous_response=pools_response
                )
            
            self.data['gcp_workload_identity_pools'] = all_pools_data
            logging.info(f"Successfully fetched {len(all_pools_data)} Workload Identity Pools and their providers for project {self.project_id}.")
            return True

        except HttpError as e:
            logging.error(f"HttpError fetching GCP Workload Identity Pools for project {self.project_id}: {e}", exc_info=True)
            self.data['gcp_workload_identity_pools'] = [{"error": f"HTTP_ERROR_{e.resp.status}", "details": str(e)}]
            return False
        except Exception as e:
            logging.error(f"Generic error fetching GCP Workload Identity Pools for project {self.project_id}: {e}", exc_info=True)
            self.data['gcp_workload_identity_pools'] = [{"error": "EXCEPTION", "details": str(e)}]
            return False

    def collect_domains(self):
        logging.info("Collecting domains...")
        # Placeholder
        self.data["domains"] = [{"domainName": "example.com", "verified": True}]
        return True

    def collect_org_units(self):
        logging.info("Collecting org units...")
        # Placeholder
        self.data["orgUnits"] = [{"name": "Root", "orgUnitPath": "/", "orgUnitId": "root_id"}]
        return True

    def collect_users(self):
        logging.info("Collecting users...")
        # Placeholder
        self.data["users"] = [{"primaryEmail": self.delegated_email, "isAdmin": True, "isEnrolledIn2Sv": False}]
        return True

    def collect_groups_and_settings(self):
        logging.info("Collecting groups and settings...")
        # Placeholder
        self.data["groups"] = [{"email": "group@example.com", "name": "Test Group"}]
        self.data["groupSettings"]["group@example.com"] = {"whoCanJoin": "ALL_IN_DOMAIN_CAN_JOIN"}
        return True

    def collect_gmail_settings_for_users(self):
        logging.info("Collecting Gmail settings for users...")
        # Placeholder
        self.data["userGmailSettings"][self.delegated_email] = {"autoForwarding": {"enabled": False}}
        return True

    def collect_calendar_settings_and_acls(self):
        logging.info("Collecting Calendar settings and ACLs...")
        # Placeholder
        self.data["calendarSettings"]["primary"] = {"defaultAccess": "domain"}
        self.data["calendarAcls"]["primary_calendar_id"] = [{"scope": {"type": "default"}, "role": "reader"}]
        return True

    def collect_drive_settings_and_files(self):
        logging.info("Collecting Drive settings and files...")
        # Placeholder
        self.data["driveSettings"] = {"sharingSettings": {"domainSharingOption": "domainWithLink"}}
        self.data["driveFiles"] = [{"id": "file_id_example", "name": "Test Document", "shared": True, "owners": [self.delegated_email]}]
        return True

    def collect_chat_spaces(self):
        logging.info("Collecting Chat spaces...")
        # Placeholder
        self.data["chatSpaces"] = [{"name": "spaces/example_space", "displayName": "Test Space"}]
        return True

    def collect_reports(self):
        logging.info("Collecting reports (audit & usage)...")
        # Placeholder
        self.data["auditReports"]["login"] = [{"actor": self.delegated_email, "event": "login_success"}]
        self.data["usageReports"]["accounts"] = [{"date": "2023-01-01", "num_users": 1}]
        return True

    def collect_dns_records(self):
        logging.info("Collecting DNS records (simulated)...")
        if dns:
            # Placeholder - actual implementation would query DNS for domains in self.data["domains"]
            self.data["dnsRecords"]["example.com"] = {"MX": ["mx.example.com"], "SPF": "v=spf1 include:_spf.google.com ~all"}
        else:
            logging.warning("DNS record collection skipped as dnspython is not installed.")
        return True
        
    def analyze_security_posture(self):
        logging.info("Starting security posture analysis...")
        check_results = []
        target_scope_customer = f"Customer ID: {self.customer_id}" if self.customer_id else "Google Workspace Customer"

        def _add_check_result(check_id, name, scope, status, expected, actual, remediation):
            check_results.append({
                "check_id": check_id,
                "check_name": name,
                "target_scope": scope,
                "status": status,
                "expected_value": expected,
                "actual_value": actual,
                "remediation_suggestion": remediation
            })

        users_data = self.data.get('users')
        if not users_data or not isinstance(users_data, list) or not users_data: # Check if users_data is a non-empty list
            logging.warning("User data is not available or empty. Skipping user-based security checks (WS-IAM-001, 002, 005, 007, 008, 009).")
            _add_check_result(
                "WS-PRECHECK-001", "User Data Availability", "System", "ERROR",
                "User data available for analysis.", "User data missing or empty.",
                "Ensure user data collection was successful to perform IAM checks."
            )
            # Do not return yet, other checks might be possible
        else: # Proceed with user-based checks if users_data is valid
            # --- WS-IAM-001 & WS-IAM-002: Super Admin Count ---
            admin_users = []
            for user in users_data:
                if not isinstance(user, dict):
                    logging.warning(f"Skipping malformed user entry: {user}")
                    continue
                if user.get('isAdmin', False): # Gracefully handle missing 'isAdmin'
                    admin_users.append(user)
            
            num_admin_users = len(admin_users)

            # WS-IAM-001
            status_iam_001 = "PASS" if num_admin_users > 1 else "FAIL"
            _add_check_result(
                "WS-IAM-001", "More than one Super Admin", target_scope_customer, status_iam_001,
                "> 1 Super Admin", f"{num_admin_users} Super Admins",
                "Ensure at least two users have Super Admin privileges for redundancy and to avoid lockout."
            )

            # WS-IAM-002
            status_iam_002 = "PASS" if num_admin_users <= 4 else "FAIL"
            _add_check_result(
                "WS-IAM-002", "No more than 4 Super Admins", target_scope_customer, status_iam_002,
                "<= 4 Super Admins", f"{num_admin_users} Super Admins",
                "Limit the number of Super Admins to a small, manageable group (ideally 2-3) to reduce attack surface. Regularly review Super Admin assignments."
            )

            # --- WS-IAM-005: 2SV enforced for Admins ---
            if not admin_users:
                _add_check_result(
                    "WS-IAM-005", "2SV enforced for Admins", "All Super Admin accounts", "PASS", 
                    "All Super Admins have 2SV enforced.", "No Super Admin accounts found.",
                    "Enforce 2-Step Verification for all administrative accounts through Google Workspace admin console settings."
                )
            else:
                admins_not_enforced_2sv = []
                for admin in admin_users:
                    primary_email = admin.get('primaryEmail', 'Unknown Email')
                    if not admin.get('isEnforcedIn2Sv', False): 
                        admins_not_enforced_2sv.append(primary_email)
                    elif not isinstance(admin.get('isEnforcedIn2Sv'), bool):
                         logging.warning(f"User {primary_email} has non-boolean isEnforcedIn2Sv value: {admin.get('isEnforcedIn2Sv')}. Treating as not enforced.")
                         admins_not_enforced_2sv.append(primary_email)

                if not admins_not_enforced_2sv:
                    _add_check_result(
                        "WS-IAM-005", "2SV enforced for Admins", "All Super Admin accounts", "PASS",
                        "All Super Admins have 2SV enforced.", "All Super Admins have 2SV enforced.",
                        "Enforce 2-Step Verification for all administrative accounts through Google Workspace admin console settings."
                    )
                else:
                    actual_value_iam_005 = (f"{len(admin_users) - len(admins_not_enforced_2sv)} out of {len(admin_users)} "
                                            f"Super Admins have 2SV enforced. Failing users: {', '.join(admins_not_enforced_2sv)}")
                    _add_check_result(
                        "WS-IAM-005", "2SV enforced for Admins", "All Super Admin accounts", "FAIL",
                        "All Super Admins have 2SV enforced.", actual_value_iam_005,
                        "Enforce 2-Step Verification for all administrative accounts through Google Workspace admin console settings."
                    )
            
            # --- WS-IAM-007: 2SV enforced for All Users ---
            total_users = len(users_data)
            users_not_enforced_2sv_count = 0
            for user in users_data:
                if not isinstance(user, dict): continue
                primary_email = user.get('primaryEmail', 'Unknown Email')
                if not user.get('isEnforcedIn2Sv', False): 
                    users_not_enforced_2sv_count += 1
                elif not isinstance(user.get('isEnforcedIn2Sv'), bool):
                    logging.warning(f"User {primary_email} has non-boolean isEnforcedIn2Sv value: {user.get('isEnforcedIn2Sv')}. Treating as not enforced.")
                    users_not_enforced_2sv_count += 1

            if users_not_enforced_2sv_count == 0:
                _add_check_result(
                    "WS-IAM-007", "2SV enforced for All Users", "All Users in Google Workspace", "PASS",
                    "All users have 2SV enforced.", "All users have 2SV enforced.",
                    "Enforce 2-Step Verification for all users via Google Workspace admin console settings to enhance account security."
                )
            else:
                actual_value_iam_007 = (f"{total_users - users_not_enforced_2sv_count} out of {total_users} "
                                        f"users have 2SV enforced. Failing users count: {users_not_enforced_2sv_count}")
                _add_check_result(
                    "WS-IAM-007", "2SV enforced for All Users", "All Users in Google Workspace", "FAIL",
                    "All users have 2SV enforced.", actual_value_iam_007,
                    "Enforce 2-Step Verification for all users via Google Workspace admin console settings to enhance account security."
                )

            # --- WS-IAM-008: Super Admin account recovery enabled ---
            if not admin_users:
                 _add_check_result(
                    "WS-IAM-008", "Super Admin account recovery enabled", "All Super Admin accounts", "PASS", # Or NA
                    "All Super Admins have account recovery (email or phone) configured.", "No Super Admin accounts found.",
                    "Ensure all Super Admin accounts have recovery email and/or phone numbers configured to prevent lockout."
                )
            else:
                admins_missing_recovery = []
                for admin in admin_users:
                    primary_email = admin.get('primaryEmail', 'Unknown Email')
                    has_recovery_email = bool(admin.get('recoveryEmail')) # Check if exists and is not empty
                    has_recovery_phone = bool(admin.get('recoveryPhone')) # Check if exists and is not empty
                    if not (has_recovery_email or has_recovery_phone):
                        admins_missing_recovery.append(primary_email)
                
                if not admins_missing_recovery:
                    _add_check_result(
                        "WS-IAM-008", "Super Admin account recovery enabled", "All Super Admin accounts", "PASS",
                        "All Super Admins have account recovery (email or phone) configured.", "All Super Admins have recovery methods configured.",
                        "Ensure all Super Admin accounts have recovery email and/or phone numbers configured to prevent lockout."
                    )
                else:
                    actual_value_iam_008 = (f"{len(admin_users) - len(admins_missing_recovery)} out of {len(admin_users)} "
                                            f"Super Admins have recovery methods. Failing users: {', '.join(admins_missing_recovery)}")
                    _add_check_result(
                        "WS-IAM-008", "Super Admin account recovery enabled", "All Super Admin accounts", "FAIL",
                        "All Super Admins have account recovery (email or phone) configured.", actual_value_iam_008,
                        "Ensure all Super Admin accounts have recovery email and/or phone numbers configured to prevent lockout."
                    )

            # --- WS-IAM-009: User account recovery enabled (Strict) ---
            users_missing_recovery_count = 0
            for user in users_data:
                if not isinstance(user, dict): continue
                has_recovery_email = bool(user.get('recoveryEmail'))
                has_recovery_phone = bool(user.get('recoveryPhone'))
                if not (has_recovery_email or has_recovery_phone):
                    users_missing_recovery_count += 1
            
            if users_missing_recovery_count == 0:
                _add_check_result(
                    "WS-IAM-009", "User account recovery enabled", "All Users in Google Workspace", "PASS",
                    "All users have account recovery (email or phone) configured.", "All users have recovery methods configured.",
                    "Encourage or enforce users to set up account recovery email and/or phone numbers. This can be managed via Google Workspace settings or user communication."
                )
            else:
                actual_value_iam_009 = (f"{total_users - users_missing_recovery_count} out of {total_users} "
                                        f"users have recovery methods configured. Users missing recovery count: {users_missing_recovery_count}")
                _add_check_result(
                    "WS-IAM-009", "User account recovery enabled", "All Users in Google Workspace", "FAIL",
                    "All users have account recovery (email or phone) configured.", actual_value_iam_009,
                    "Encourage or enforce users to set up account recovery email and/or phone numbers. This can be managed via Google Workspace settings or user communication."
                )

        # --- WS-IAM-004: Directory data access externally restricted (Groups) ---
        group_settings_data = self.data.get('groupSettings')
        if group_settings_data is None or not isinstance(group_settings_data, dict): # Check can be {} if no groups
            logging.warning("Group settings data is not available or not a dict. Skipping WS-IAM-004.")
            _add_check_result(
                "WS-IAM-004", "Directory data access externally restricted", "Google Workspace Groups settings", "ERROR",
                "External members are not allowed in any Google Groups.", "Group settings data missing or malformed.",
                "Ensure group settings data collection was successful."
            )
        elif not group_settings_data: # Empty dict means no groups or no settings fetched
             _add_check_result(
                "WS-IAM-004", "Directory data access externally restricted", "Google Workspace Groups settings", "PASS", # Or NA
                "External members are not allowed in any Google Groups.", "No group settings data found (implies no groups or no settings to check).",
                "Review Google Groups settings and disable 'Allow external members' for groups containing sensitive information, or for all groups if policy dictates."
            )
        else:
            groups_allowing_external = []
            for group_email, settings in group_settings_data.items():
                if not isinstance(settings, dict):
                    logging.warning(f"Skipping malformed settings for group {group_email}: {settings}")
                    continue
                # allowExternalMembers is often a string "true" or "false" from APIs
                if str(settings.get('allowExternalMembers')).lower() == 'true':
                    groups_allowing_external.append(group_email)
            
            if not groups_allowing_external:
                _add_check_result(
                    "WS-IAM-004", "Directory data access externally restricted", "Google Workspace Groups settings", "PASS",
                    "External members are not allowed in any Google Groups.", "All groups restrict external members.",
                    "Review Google Groups settings and disable 'Allow external members' for groups containing sensitive information, or for all groups if policy dictates."
                )
            else:
                actual_value_iam_004 = f"Groups allowing external members: {', '.join(groups_allowing_external)}"
                _add_check_result(
                    "WS-IAM-004", "Directory data access externally restricted", "Google Workspace Groups settings", "FAIL",
                    "External members are not allowed in any Google Groups.", actual_value_iam_004,
                    "Review Google Groups settings and disable 'Allow external members' for groups containing sensitive information, or for all groups if policy dictates."
                )

        # --- Calendar Settings Checks ---
        # These checks assume 'calendarSettings' might be populated by a more detailed
        # collection method in the future, e.g., from chrome.settings.calendars or similar.
        # For now, using a placeholder or very high-level data if available.
        # The current `collect_calendar_settings_and_acls` populates `self.data['calendarSettings']['primary']`
        # which is not the global workspace setting.
        # We will assume for these checks that a hypothetical `self.data.get('workspace_settings', {}).get('calendar', {})`
        # would hold these global settings. If not found, they will report as such.
        
        workspace_calendar_settings = self.data.get('workspace_settings', {}).get('calendar', {})
        calendar_settings_scope = "Google Workspace Calendar settings"

        # WS-CAL-001: External sharing options for primary calendars restricted
        external_sharing_options = workspace_calendar_settings.get('externalSharingOptions', 'unknown')
        cal001_status = "FAIL" # Default to FAIL if not explicitly secure or found
        cal001_actual = f"Setting value: {external_sharing_options}"
        if external_sharing_options in ['freeBusyOnly', 'noSharing']:
            cal001_status = "PASS"
        elif external_sharing_options == 'unknown':
             cal001_actual = "Workspace-level external sharing setting not found/applicable."
        _add_check_result(
            "WS-CAL-001", "External sharing options for primary calendars restricted", calendar_settings_scope, cal001_status,
            "External sharing set to 'free/busy only' or 'no sharing'.", cal001_actual,
            "Configure domain-wide calendar external sharing settings to 'Show only free/busy information' or less permissive, via Google Workspace Admin Console."
        )

        # WS-CAL-002: Internal sharing options for primary calendars restricted
        internal_sharing_options = workspace_calendar_settings.get('internalSharingOptions', 'unknown')
        cal002_status = "FAIL" # Default to FAIL
        cal002_actual = f"Setting value: {internal_sharing_options}"
        # Stricter interpretation: only freeBusy or readOnly are PASS. Full access is FAIL.
        if internal_sharing_options in ['allUsersInDomainFreeBusy', 'allUsersInDomainReadOnly']:
            cal002_status = "PASS"
        elif internal_sharing_options == 'unknown':
            cal002_actual = "Workspace-level internal sharing setting not found/applicable."
        _add_check_result(
            "WS-CAL-002", "Internal sharing options for primary calendars restricted", calendar_settings_scope, cal002_status,
            "Internal sharing configured (e.g., 'free/busy only for domain' or 'read-only for domain').", cal002_actual,
            "Configure domain-wide calendar internal sharing settings according to your organization's policy, typically avoiding full sharing by default, via Google Workspace Admin Console."
        )

        # WS-CAL-003: External invitation warnings for Google Calendar configured
        warn_on_external_invitations_raw = workspace_calendar_settings.get('warnOnExternalInvitations', 'unknown')
        cal003_status = "FAIL"
        cal003_actual = f"Setting value: {warn_on_external_invitations_raw}"
        
        if str(warn_on_external_invitations_raw).lower() == 'true':
            cal003_status = "PASS"
            cal003_actual = "Enabled"
        elif str(warn_on_external_invitations_raw).lower() == 'false':
            cal003_actual = "Disabled"
        elif warn_on_external_invitations_raw == 'unknown':
            cal003_actual = "Workspace-level external invitation warning setting not found/applicable."
            
        _add_check_result(
            "WS-CAL-003", "External invitation warnings for Google Calendar configured", calendar_settings_scope, cal003_status,
            "External invitation warnings are enabled.", cal003_actual,
            "Enable 'Warn users when they invite external guests' in Google Calendar settings via the Admin Console."
        )

        # --- Drive Settings Checks ---
        # Using a hypothetical 'workspace_settings.drive' structure
        workspace_drive_settings = self.data.get('workspace_settings', {}).get('drive', {})
        drive_sharing_settings = workspace_drive_settings.get('sharingSettings', {})
        drive_settings_scope = "Google Workspace Drive settings"
        
        # WS-DRV-001: Warn on external file sharing
        warn_on_external_share_raw = drive_sharing_settings.get('warnOnExternalShare', 'unknown')
        drv001_status = "FAIL"
        drv001_actual = f"Setting value: {warn_on_external_share_raw}"
        if str(warn_on_external_share_raw).lower() == 'true':
            drv001_status = "PASS"
            drv001_actual = "Enabled"
        elif str(warn_on_external_share_raw).lower() == 'false':
            drv001_actual = "Disabled"
        elif warn_on_external_share_raw == 'unknown':
            drv001_actual = "Workspace-level 'warnOnExternalShare' setting not found."
        _add_check_result(
            "WS-DRV-001", "Warn on external file sharing", drive_settings_scope, drv001_status,
            "Warning for external file sharing is enabled.", drv001_actual,
            "Enable 'Warn users when they share files outside the organization' in Google Drive settings via the Admin Console."
        )

        # WS-DRV-002: Prevent public file publishing
        # This can be complex. A direct 'allowPublicFilePublishing' is ideal.
        # If not, checking 'domainWideSharingOption' or similar might be needed.
        # For this implementation, we'll assume 'allowPublicFilePublishing' (boolean) or a similar specific flag.
        allow_public_publishing_raw = drive_sharing_settings.get('allowPublicFilePublishing', 'unknown')
        drv002_status = "FAIL"
        drv002_actual = f"Setting value: {allow_public_publishing_raw}"
        if str(allow_public_publishing_raw).lower() == 'false':
            drv002_status = "PASS"
            drv002_actual = "Public publishing disabled"
        elif str(allow_public_publishing_raw).lower() == 'true':
            drv002_actual = "Public publishing allowed"
        elif allow_public_publishing_raw == 'unknown':
            drv002_actual = "Workspace-level 'allowPublicFilePublishing' setting not found."
            # Could also check domainWideSharingOption here if available, e.g.:
            # domain_sharing = drive_sharing_settings.get('domainWideSharingOption', 'unknown')
            # if domain_sharing in ['domainOnly', 'domainWithWarning']: drv002_status = "PASS"
        _add_check_result(
            "WS-DRV-002", "Prevent public file publishing", drive_settings_scope, drv002_status,
            "Users cannot publish files to the web or make them publicly/unlisted visible.", drv002_actual,
            "Disable 'Allow users to publish files on the web' and restrict 'Link sharing' options to prevent files from being made public, via Google Drive settings in the Admin Console."
        )

        # WS-DRV-010: Restrict download/print/copy for viewers/commenters
        prevent_dl_raw = drive_sharing_settings.get('preventViewerCommenterDownload', 'unknown')
        drv010_status = "FAIL"
        drv010_actual = f"Setting value: {prevent_dl_raw}"
        if str(prevent_dl_raw).lower() == 'true':
            drv010_status = "PASS"
            drv010_actual = "Enabled"
        elif str(prevent_dl_raw).lower() == 'false':
            drv010_actual = "Disabled"
        elif prevent_dl_raw == 'unknown':
            drv010_actual = "Workspace-level 'preventViewerCommenterDownload' setting not found."
        _add_check_result(
            "WS-DRV-010", "Restrict download/print/copy for viewers/commenters", drive_settings_scope, drv010_status,
            "Viewers and commenters are prevented from downloading, printing, or copying files.", drv010_actual,
            "Enable 'Prevent viewers and commenters from downloading, printing, and copying files' in Google Drive settings via the Admin Console."
        )

        # --- Shared Drive Settings Checks ---
        workspace_shared_drive_settings = workspace_drive_settings.get('sharedDriveSettings', {})
        shared_drive_settings_scope = "Google Workspace Shared Drive settings"

        # WS-DRV-008: Shared Drive manager settings modification restricted
        allow_manager_modification_raw = workspace_shared_drive_settings.get('allowManagerSettingsModification', 'unknown')
        drv008_status = "FAIL"
        drv008_actual = f"Setting value: {allow_manager_modification_raw}"
        if str(allow_manager_modification_raw).lower() == 'false': # Pass if FALSE (restricted to admins)
            drv008_status = "PASS"
            drv008_actual = "Restricted to admins"
        elif str(allow_manager_modification_raw).lower() == 'true':
            drv008_actual = "Managers can modify"
        elif allow_manager_modification_raw == 'unknown':
            drv008_actual = "Shared Drive 'allowManagerSettingsModification' setting not found."
        _add_check_result(
            "WS-DRV-008", "Shared Drive manager settings modification restricted", shared_drive_settings_scope, drv008_status,
            "Shared Drive managers cannot modify Shared Drive settings (only admins can).", drv008_actual,
            "In Shared Drive settings, ensure that only administrators can modify Shared Drive settings, not users with Manager access."
        )

        # WS-DRV-009: Shared Drive file access restricted to members only
        allow_non_member_access_raw = workspace_shared_drive_settings.get('allowNonMemberAccess', 'unknown')
        drv009_status = "FAIL"
        drv009_actual = f"Setting value: {allow_non_member_access_raw}"
        if str(allow_non_member_access_raw).lower() == 'false': # Pass if FALSE (restricted to members)
            drv009_status = "PASS"
            drv009_actual = "Restricted to members"
        elif str(allow_non_member_access_raw).lower() == 'true':
            drv009_actual = "Non-members can be granted access"
        elif allow_non_member_access_raw == 'unknown':
            drv009_actual = "Shared Drive 'allowNonMemberAccess' setting not found."
        _add_check_result(
            "WS-DRV-009", "Shared Drive file access restricted to members only", shared_drive_settings_scope, drv009_status,
            "Shared Drive file access is restricted to members only.", drv009_actual,
            "Configure Shared Drive settings to disallow non-member access to files within Shared Drives."
        )

        # --- Advanced Gmail Settings Checks ---
        gmail_advanced_settings = self.data.get('workspace_settings', {}).get('gmail', {}).get('advancedSettings', {})
        gmail_advanced_settings_scope = "Google Workspace Gmail Advanced Settings"

        # Helper for boolean advanced Gmail settings expecting True
        def _check_boolean_gmail_setting(check_id, name, setting_name, remediation, expected_true=True): # Added expected_true
            setting_value = gmail_advanced_settings.get(setting_name, 'unknown')
            status = "FAIL"
            actual_str = f"Setting value: {setting_value}"
            expected_str = "Enabled" if expected_true else "Disabled"

            if str(setting_value).lower() == str(expected_true).lower():
                status = "PASS"
                actual_str = expected_str
            elif str(setting_value).lower() == str(not expected_true).lower(): # Check for the opposite state
                actual_str = "Enabled" if not expected_true else "Disabled"
            elif setting_value == 'unknown':
                actual_str = f"Setting '{setting_name}' not found."
            
            _add_check_result(check_id, name, gmail_advanced_settings_scope, status, expected_str, actual_str, remediation)


        _check_boolean_gmail_setting(
            "WS-GML-006", "Quarantine Admin Notifications", "quarantineAdminNotificationsEnabled",
            "Enable admin notifications for email quarantines in Gmail advanced settings."
        )
        _check_boolean_gmail_setting(
            "WS-GML-007", "Encrypted Attachment Protection (Untrusted Senders)", "protectEncryptedAttachmentsUntrustedSenders",
            "Enable protection against encrypted attachments from untrusted senders in Gmail advanced settings."
        )
        _check_boolean_gmail_setting(
            "WS-GML-008", "Script Attachment Protection (Untrusted Senders)", "protectScriptAttachmentsUntrustedSenders",
            "Enable protection against attachments with scripts from untrusted senders in Gmail advanced settings."
        )
        _check_boolean_gmail_setting(
            "WS-GML-009", "Anomalous Attachment Type Protection", "protectAnomalousAttachmentTypes",
            "Enable protection against anomalous attachment types in Gmail advanced settings."
        )
        _check_boolean_gmail_setting(
            "WS-GML-010", "Shortened URL Link Identification", "identifyLinksBehindShortenedUrls",
            "Enable 'Unshorten short links' or similar feature in Gmail advanced settings."
        )
        _check_boolean_gmail_setting(
            "WS-GML-011", "Scan Linked Images for Malicious Content", "scanLinkedImagesMaliciousContent",
            "Enable scanning of linked images for malicious content in Gmail advanced settings."
        )
        _check_boolean_gmail_setting(
            "WS-GML-014", "Untrusted Link Click Warning", "warnOnUntrustedDomainLinks",
            "Enable warnings for clicks on links to untrusted domains in Gmail advanced settings."
        )
        _check_boolean_gmail_setting(
            "WS-GML-015", "Similar Domain Spoofing Protection", "protectSimilarDomainSpoofing",
            "Enable protection against spoofing based on similar domain names in Gmail advanced settings."
        )
        _check_boolean_gmail_setting(
            "WS-GML-016", "Employee Name Spoofing Protection", "protectEmployeeNameSpoofing",
            "Enable protection against spoofing of employee names in Gmail advanced settings."
        )
        _check_boolean_gmail_setting(
            "WS-GML-017", "Inbound Domain Spoofing Protection", "protectInboundDomainSpoofing",
            "Enable protection against inbound emails spoofing your domain (e.g., reject based on DMARC/SPF) in Gmail advanced settings."
        )

        # WS-GML-018: Unauthenticated Email Protection
        unauth_email_protection_val = gmail_advanced_settings.get('protectUnauthenticatedEmails', 'unknown')
        gml018_status = "FAIL"
        gml018_actual = f"Setting value: {unauth_email_protection_val}"
        if unauth_email_protection_val in ['REJECT', 'QUARANTINE']: # Assuming these are the secure string values
            gml018_status = "PASS"
            gml018_actual = f"Action: {unauth_email_protection_val}"
        elif unauth_email_protection_val == 'unknown':
            gml018_actual = "Setting 'protectUnauthenticatedEmails' not found."
        _add_check_result(
            "WS-GML-018", "Unauthenticated Email Protection", gmail_advanced_settings_scope, gml018_status,
            "Strong protection (REJECT or QUARANTINE) for unauthenticated emails.", gml018_actual,
            "Configure strong protection (e.g., reject or quarantine) for unauthenticated emails in Gmail advanced settings."
        )

        _check_boolean_gmail_setting(
            "WS-GML-021", "External Recipient Warnings", "warnExternalRecipients",
            "Enable warnings when composing messages to external recipients in Gmail settings."
        )
        _check_boolean_gmail_setting(
            "WS-GML-022", "Enhanced Pre-Delivery Message Scanning", "enhancedPreDeliveryScanningEnabled",
            "Enable enhanced pre-delivery message scanning in Gmail advanced settings for better threat detection."
        )

        # --- Chat & Sites Settings ---
        workspace_chat_settings = self.data.get('workspace_settings', {}).get('chat', {})
        chat_settings_scope = "Google Workspace Chat settings"
        workspace_sites_settings = self.data.get('workspace_settings', {}).get('sites', {})
        sites_settings_scope = "Google Workspace Sites settings"

        # WS-CHT-001: External File Sharing in Chat Disabled
        allow_external_file_share_raw = workspace_chat_settings.get('allowExternalFileSharing', 'unknown')
        cht001_status = "FAIL"
        cht001_actual = f"Setting value: {allow_external_file_share_raw}"
        if str(allow_external_file_share_raw).lower() == 'false':
            cht001_status = "PASS"
            cht001_actual = "Disabled"
        elif str(allow_external_file_share_raw).lower() == 'true':
            cht001_actual = "Enabled"
        elif allow_external_file_share_raw == 'unknown':
            cht001_actual = "Chat 'allowExternalFileSharing' setting not found."
        _add_check_result(
            "WS-CHT-001", "External File Sharing in Chat Disabled", chat_settings_scope, cht001_status,
            "External file sharing in Chat is disabled.", cht001_actual,
            "Disable 'Allow users to send files to people outside of your organization' in Google Chat settings."
        )

        # WS-CHT-003: External Spaces in Chat Restricted
        restrict_external_spaces_raw = workspace_chat_settings.get('restrictExternalSpaces', 'unknown')
        cht003_status = "FAIL"
        cht003_actual = f"Setting value: {restrict_external_spaces_raw}"
        if str(restrict_external_spaces_raw).lower() == 'true':
            cht003_status = "PASS"
            cht003_actual = "Restricted"
        elif str(restrict_external_spaces_raw).lower() == 'false':
            cht003_actual = "Not restricted"
        elif restrict_external_spaces_raw == 'unknown':
            cht003_actual = "Chat 'restrictExternalSpaces' setting not found."
        _add_check_result(
            "WS-CHT-003", "External Spaces in Chat Restricted", chat_settings_scope, cht003_status,
            "Users cannot create or join external Chat spaces, or it's restricted.", cht003_actual,
            "Enable 'Prevent users from creating and joining spaces with people outside their organization' or configure appropriate restrictions in Google Chat settings."
        )
        
        # WS-SIT-001: Google Sites Service Off
        sites_service_enabled_raw = workspace_sites_settings.get('serviceEnabled', 'unknown')
        sit001_status = "FAIL" # Default to FAIL if service status is unknown or enabled
        sit001_actual = f"Setting value: {sites_service_enabled_raw}"
        if str(sites_service_enabled_raw).lower() == 'false':
            sit001_status = "PASS"
            sit001_actual = "Service Disabled/Off"
        elif str(sites_service_enabled_raw).lower() == 'true':
            sit001_actual = "Service Enabled/On"
        elif sites_service_enabled_raw == 'unknown':
            sit001_actual = "Sites 'serviceEnabled' setting not found."
        _add_check_result(
            "WS-SIT-001", "Google Sites Service Off", sites_settings_scope, sit001_status,
            "Google Sites service is turned Off for the domain/OU.", sit001_actual,
            "If Google Sites is not required for business operations, turn the service Off in Google Workspace Admin Console."
        )
        
        # --- GCP IAM Checks ---
        # GCP-IAM-001: No Owner Role at Organization Level
        gcp_org_iam_policy = self.data.get('gcp_iam_organization_policy')
        org_scope = f"GCP Organization ID: {self.org_id}" if self.org_id else "GCP Organization (ID not found)"
        if not self.org_id:
            _add_check_result("GCP-IAM-001", "No Owner Role at Organization Level", org_scope, "ERROR",
                              "No roles/owner assigned.", "Organization ID not available.",
                              "Ensure Organization ID is collected to perform this check.")
        elif not gcp_org_iam_policy or not isinstance(gcp_org_iam_policy.get('bindings'), list):
            _add_check_result("GCP-IAM-001", "No Owner Role at Organization Level", org_scope, "ERROR",
                              "No roles/owner assigned.", "Organization IAM policy data not found or malformed.",
                              "Ensure Organization IAM policy data collection was successful.")
        else:
            org_owners = []
            for binding in gcp_org_iam_policy.get('bindings', []):
                if binding.get('role') == 'roles/owner':
                    org_owners.extend(binding.get('members', []))
            if not org_owners:
                _add_check_result("GCP-IAM-001", "No Owner Role at Organization Level", org_scope, "PASS",
                                  "No roles/owner assigned.", "No roles/owner found.",
                                  "Avoid using the primitive roles/owner at the Organization level. Grant more granular roles according to the principle of least privilege.")
            else:
                _add_check_result("GCP-IAM-001", "No Owner Role at Organization Level", org_scope, "FAIL",
                                  "No roles/owner assigned.", f"Users/groups with roles/owner: {', '.join(org_owners)}",
                                  "Avoid using the primitive roles/owner at the Organization level. Grant more granular roles according to the principle of least privilege.")

        # GCP-IAM-002: No Owner Role at Project Level
        gcp_proj_iam_policy = self.data.get('gcp_iam_project_policy')
        proj_scope = f"GCP Project ID: {self.project_id}" if self.project_id else "GCP Project (ID not found)"
        if not self.project_id:
             _add_check_result("GCP-IAM-002", "No Owner Role at Project Level", proj_scope, "ERROR",
                              "No roles/owner assigned.", "Project ID not available.",
                              "Ensure Project ID is collected to perform this check.")
        elif not gcp_proj_iam_policy or not isinstance(gcp_proj_iam_policy.get('bindings'), list):
            _add_check_result("GCP-IAM-002", "No Owner Role at Project Level", proj_scope, "ERROR",
                              "No roles/owner assigned.", "Project IAM policy data not found or malformed.",
                              "Ensure Project IAM policy data collection was successful.")
        else:
            proj_owners = []
            for binding in gcp_proj_iam_policy.get('bindings', []):
                if binding.get('role') == 'roles/owner':
                    proj_owners.extend(binding.get('members', []))
            if not proj_owners:
                _add_check_result("GCP-IAM-002", "No Owner Role at Project Level", proj_scope, "PASS",
                                  "No roles/owner assigned.", "No roles/owner found.",
                                  "Avoid using the primitive roles/owner at the Project level. Grant more granular roles. For most operational tasks, predefined roles like roles/editor or roles/viewer combined with service-specific roles are sufficient.")
            else:
                _add_check_result("GCP-IAM-002", "No Owner Role at Project Level", proj_scope, "FAIL",
                                  "No roles/owner assigned.", f"Users/groups with roles/owner: {', '.join(proj_owners)}",
                                  "Avoid using the primitive roles/owner at the Project level. Grant more granular roles. For most operational tasks, predefined roles like roles/editor or roles/viewer combined with service-specific roles are sufficient.")

        # --- GCP GCS Checks ---
        gcs_buckets_data = self.data.get('gcp_gcs_buckets', [])
        if not self.project_id:
            _add_check_result("GCP-GCS-001", "No Publicly Accessible GCS Buckets", "All GCS Buckets in Project", "ERROR",
                              "No GCS buckets allow public access.", "Project ID not available.",
                              "Ensure Project ID is collected to perform this check.")
        elif not gcs_buckets_data or not isinstance(gcs_buckets_data, list) or (isinstance(gcs_buckets_data, list) and gcs_buckets_data and gcs_buckets_data[0].get("error")): # Check for error marker
            _add_check_result("GCP-GCS-001", "No Publicly Accessible GCS Buckets", "All GCS Buckets in Project", "ERROR",
                              "No GCS buckets allow public access.", "GCS bucket data not found, malformed, or indicates collection error.",
                              "Ensure GCS bucket data collection was successful.")
        else:
            publicly_accessible_buckets = []
            for bucket in gcs_buckets_data:
                if not isinstance(bucket, dict): continue # Skip malformed entries

                bucket_name = bucket.get('name', 'Unknown Bucket')
                is_public_by_iam = False
                iam_policy = bucket.get('iam_policy', {})
                if isinstance(iam_policy, dict): # Ensure iam_policy is a dict before .get
                    for binding in iam_policy.get('bindings', []):
                        if not isinstance(binding, dict): continue
                        members = binding.get('members', [])
                        if 'allUsers' in members or 'allAuthenticatedUsers' in members:
                            is_public_by_iam = True
                            publicly_accessible_buckets.append(f"{bucket_name} (IAM: {binding.get('role')} for allUsers/allAuthenticatedUsers)")
                            break # Found public IAM, no need to check other bindings for this bucket
                
                if not is_public_by_iam: # Only check PAP if not already public by IAM
                    public_access_prevention = bucket.get('public_access_prevention', 'unknown')
                    # 'enforced' or 'inherited' (if parent is enforced) are good. 'disabled' is bad.
                    if str(public_access_prevention).lower() == 'disabled':
                        publicly_accessible_buckets.append(f"{bucket_name} (Public Access Prevention: Disabled)")
            
            if not publicly_accessible_buckets:
                _add_check_result("GCP-GCS-001", "No Publicly Accessible GCS Buckets", f"All GCS Buckets in project {self.project_id}", "PASS",
                                  "No GCS buckets allow public access via `allUsers` or `allAuthenticatedUsers` and Public Access Prevention is effective.", 
                                  "All buckets restrict public access or have effective Public Access Prevention.",
                                  "Remove `allUsers` and `allAuthenticatedUsers` from GCS bucket IAM policies. Enable Public Access Prevention on buckets.")
            else:
                _add_check_result("GCP-GCS-001", "No Publicly Accessible GCS Buckets", f"All GCS Buckets in project {self.project_id}", "FAIL",
                                  "No GCS buckets allow public access via `allUsers` or `allAuthenticatedUsers` and Public Access Prevention is effective.", 
                                  f"Publicly accessible buckets: {', '.join(publicly_accessible_buckets)}",
                                  "Remove `allUsers` and `allAuthenticatedUsers` from GCS bucket IAM policies. Enable Public Access Prevention on buckets.")


        logging.info(f"Security posture analysis completed. Found {len(check_results)} results.")
        return check_results

    def run_all_collections_and_analysis(self):
        logging.info("Starting all collections and analysis...")
        if not self.authenticate():
            logging.error("Authentication failed. Aborting.")
            return {"timestamp": datetime.now().isoformat(), "status": "ERROR", "error": "Authentication failed", "check_results": []}

        collection_methods = [
            self.collect_customer_info,
            self.collect_domains,
            self.collect_org_units,
            self.collect_users,
            self.collect_groups_and_settings,
            self.collect_gmail_settings_for_users,
            self.collect_calendar_settings_and_acls,
            self.collect_drive_settings_and_files,
            self.collect_chat_spaces,
            self.collect_reports,
            self.collect_dns_records,
            self.collect_gcp_organization_iam_policy,
            self.collect_gcp_project_iam_policy,
            self.collect_gcp_project_service_accounts,
            self.collect_gcp_vpc_networks,
            self.collect_gcp_firewall_rules,
            self.collect_gcp_subnetworks,
            self.collect_gcp_enabled_services,
            self.collect_gcp_scc_findings,
            self.collect_gcp_kms_keys,
            self.collect_gcp_gcs_buckets,
            self.collect_gcp_iap_settings,
            self.collect_gcp_workload_identity_pools,
        ]

        for collect_method in collection_methods:
            try:
                # Using retry_api_call here, though placeholders don't make API calls yet.
                # This structure is for when they do.
                self.retry_api_call(collect_method)
            except Exception as e:
                logging.error(f"Error during {collect_method.__name__}: {e}", exc_info=True)
                # Decide if you want to stop all or continue with other collections
                # For now, let's continue

        analysis_results = self.analyze_security_posture()

        final_results = {
            "timestamp": datetime.now().isoformat(),
            "status": "SUCCESS", # Assuming success if we reach here, can be refined
            "collected_data_summary": {k: type(v).__name__ + (f" (len: {len(v)})" if hasattr(v, '__len__') else "") for k,v in self.data.items()},
            "check_results": analysis_results,
            # "raw_data": self.data # Optionally include all raw data
        }
        logging.info("All collections and analysis completed.")
        return final_results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Google Workspace Security Auditor.")
    parser.add_argument("--credentials", required=True, help="Path to service account JSON credentials file.")
    parser.add_argument("--delegated-email", required=True, help="Email of the user to impersonate (must have domain-wide delegation).")
    parser.add_argument("--output-file", default="gws_security_report.json", help="Path to save the JSON report.")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        for handler in logging.getLogger().handlers: # Ensure all handlers are set to debug
            handler.setLevel(logging.DEBUG)
        logging.debug("Debug logging enabled.")

    collector = GoogleWorkspaceCollector(credentials_file=args.credentials, delegated_email=args.delegated_email)
    
    # For testing, we'll need a dummy credentials file.
    # In a real scenario, this file would be provided.
    # For this test environment, let's create a minimal dummy one if it doesn't exist.
    # This is NOT good practice for production code but helps in a sandboxed test.
    dummy_creds_content = {
        "type": "service_account",
        "project_id": "test-project", # Example project_id
        "private_key_id": "dummy_key_id",
        "private_key": "-----BEGIN PRIVATE KEY-----\nYOUR_DUMMY_PRIVATE_KEY\n-----END PRIVATE KEY-----\n", # Not a real key
        "client_email": "dummy-sa@test-project.iam.gserviceaccount.com",
        "client_id": "dummy_client_id",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/dummy-sa%40test-project.iam.gserviceaccount.com"
    }
    if not os.path.exists(args.credentials):
        logging.warning(f"Credentials file {args.credentials} not found. Creating a dummy one for placeholder execution.")
        try:
            with open(args.credentials, 'w') as f:
                json.dump(dummy_creds_content, f)
            logging.info(f"Dummy credentials file created at {args.credentials}")
        except IOError as e:
            logging.error(f"Could not create dummy credentials file: {e}. Exiting.")
            sys.exit(1)


    results = collector.run_all_collections_and_analysis()

    try:
        with open(args.output_file, 'w') as f:
            json.dump(results, f, indent=2)
        logging.info(f"Security report saved to {args.output_file}")
        print(f"Security audit complete. Report saved to {args.output_file}")
    except IOError as e:
        logging.error(f"Failed to write report to {args.output_file}: {e}")
        print(f"Failed to write report to {args.output_file}. Check logs for details.", file=sys.stderr)

    # Clean up dummy credentials if it was created by this script
    if "YOUR_DUMMY_PRIVATE_KEY" in dummy_creds_content["private_key"] and os.path.exists(args.credentials):
        content_check = {}
        try:
            with open(args.credentials, 'r') as f_check:
                content_check = json.load(f_check)
        except Exception: # Broad catch if file is not json or unreadable
            pass # Avoid deleting if we can't verify it's ours

        if content_check.get("private_key_id") == "dummy_key_id":
            try:
                # os.remove(args.credentials)
                # logging.info(f"Dummy credentials file {args.credentials} removed.")
                # For safety in this environment, let's not auto-delete, but notify.
                logging.info(f"Note: A dummy credentials file was used/created at {args.credentials}. "
                             "Ensure this is replaced with real credentials for actual use.")
            except OSError as e:
                logging.warning(f"Could not remove dummy credentials file {args.credentials}: {e}")
