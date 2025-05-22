import json
import os
import logging
import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from google.cloud import asset_v1
from google.cloud import compute_v1
from google.cloud import storage
from google.cloud.exceptions import NotFound

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class GCPResourceCollector:
    def __init__(self, project_id, output_dir="gcp_data"):
        self.project_id = project_id
        self.output_dir = output_dir
        self.data = {"project_id": project_id, "resources": {}}
        os.makedirs(self.output_dir, exist_ok=True)

    def _execute_gcloud_command(self, command):
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            stdout, stderr = process.communicate()
            if process.returncode != 0:
                logging.error(f"Error executing command: {command}\nStderr: {stderr.decode()}")
                return None
            return json.loads(stdout.decode())
        except Exception as e:
            logging.error(f"Exception during gcloud command: {command}\n{e}")
            return None

    def list_gce_instances_all_zones(self):
        logging.info("Collecting GCE instances...")
        instances_client = compute_v1.InstancesClient()
        request = compute_v1.AggregatedListInstancesRequest(project=self.project_id)
        
        all_instances = []
        try:
            for zone, response in instances_client.aggregated_list(request=request):
                if response.instances:
                    for instance in response.instances:
                        all_instances.append({
                            "name": instance.name,
                            "zone": zone.split('/')[-1],
                            "machine_type": instance.machine_type.split('/')[-1],
                            "status": instance.status,
                            "creation_timestamp": instance.creation_timestamp,
                            "network_interfaces": [
                                {
                                    "network": ni.network.split('/')[-1] if ni.network else None,
                                    "network_ip": ni.network_i_p,
                                    "access_configs": [
                                        {"nat_ip": ac.nat_i_p for ac in ni.access_configs}
                                    ]
                                } for ni in instance.network_interfaces
                            ],
                            "disks": [
                                {
                                    "disk_name": disk.source.split('/')[-1] if disk.source else None,
                                    "disk_size_gb": self._get_disk_size(disk.source) if disk.source else None,
                                    "boot": disk.boot
                                } for disk in instance.disks
                            ],
                            "labels": dict(instance.labels),
                            "tags": list(instance.tags.items) if hasattr(instance.tags, 'items') else [],
                        })
            self.data["resources"]["gce_instances"] = all_instances
            logging.info(f"Collected {len(all_instances)} GCE instances.")
        except Exception as e:
            logging.error(f"Error collecting GCE instances: {e}")
            self.data["resources"]["gce_instances"] = {"error": str(e)}
        return all_instances

    def _get_disk_size(self, disk_self_link):
        try:
            # disk_self_link is like "projects/project-id/zones/zone/disks/disk-name"
            # or "https://www.googleapis.com/compute/v1/projects/project-id/zones/zone/disks/disk-name"
            parts = disk_self_link.split('/')
            project = parts[parts.index("projects") + 1]
            zone = parts[parts.index("zones") + 1]
            disk_name = parts[parts.index("disks") + 1]
            
            disks_client = compute_v1.DisksClient()
            disk = disks_client.get(project=project, zone=zone, disk=disk_name)
            return disk.size_gb
        except Exception as e:
            logging.warning(f"Could not get disk size for {disk_self_link}: {e}")
            return None


    def list_gcs_buckets(self):
        logging.info("Collecting GCS buckets...")
        storage_client = storage.Client(project=self.project_id)
        buckets_data = []
        try:
            for bucket in storage_client.list_buckets():
                bucket_info = {
                    "name": bucket.name,
                    "location": bucket.location,
                    "storage_class": bucket.storage_class,
                    "created": bucket.time_created.isoformat() if bucket.time_created else None,
                    "labels": dict(bucket.labels) if bucket.labels else {},
                }
                try:
                    iam_policy = bucket.get_iam_policy(requested_policy_version=3)
                    bindings = []
                    for binding in iam_policy.bindings:
                        bindings.append({"role": binding.role, "members": list(binding.members)})
                    bucket_info["iam_policy_bindings"] = bindings
                except Exception as e:
                    logging.warning(f"Could not retrieve IAM policy for bucket {bucket.name}: {e}")
                    bucket_info["iam_policy_bindings"] = {"error": str(e)}
                
                buckets_data.append(bucket_info)
            self.data["resources"]["gcs_buckets"] = buckets_data
            logging.info(f"Collected {len(buckets_data)} GCS buckets.")
        except Exception as e:
            logging.error(f"Error collecting GCS buckets: {e}")
            self.data["resources"]["gcs_buckets"] = {"error": str(e)}
        return buckets_data

    def list_vpc_networks(self):
        logging.info("Collecting VPC networks...")
        networks_client = compute_v1.NetworksClient()
        request = compute_v1.ListNetworksRequest(project=self.project_id)
        networks_data = []
        try:
            for network in networks_client.list(request=request):
                subnetworks = []
                for subnetwork_url in network.subnetworks:
                    # subnetwork_url is like "https://www.googleapis.com/compute/v1/projects/gcp-project-id/regions/us-central1/subnetworks/default"
                    subnetwork_name = subnetwork_url.split('/')[-1]
                    region = subnetwork_url.split('/')[-3]
                    subnetworks.append({"name": subnetwork_name, "self_link": subnetwork_url, "region": region})

                networks_data.append({
                    "name": network.name,
                    "description": network.description,
                    "self_link": network.self_link,
                    "auto_create_subnetworks": network.auto_create_subnetworks,
                    "routing_config_routing_mode": network.routing_config.routing_mode,
                    "subnetworks": subnetworks,
                    "creation_timestamp": network.creation_timestamp,
                })
            self.data["resources"]["vpc_networks"] = networks_data
            logging.info(f"Collected {len(networks_data)} VPC networks.")
        except Exception as e:
            logging.error(f"Error collecting VPC networks: {e}")
            self.data["resources"]["vpc_networks"] = {"error": str(e)}
        return networks_data

    def list_firewall_rules(self):
        logging.info("Collecting Firewall rules...")
        firewalls_client = compute_v1.FirewallsClient()
        request = compute_v1.ListFirewallsRequest(project=self.project_id)
        firewall_data = []
        try:
            for firewall in firewalls_client.list(request=request):
                firewall_data.append({
                    "name": firewall.name,
                    "description": firewall.description,
                    "network": firewall.network.split('/')[-1],
                    "priority": firewall.priority,
                    "direction": firewall.direction,
                    "action": "allow" if firewall.allowed else ("deny" if firewall.denied else "unknown"),
                    "rules": [
                        {
                            "protocol": rule.i_p_protocol,
                            "ports": list(rule.ports)
                        } for rule in (firewall.allowed or firewall.denied or [])
                    ],
                    "source_ranges": list(firewall.source_ranges),
                    "target_tags": list(firewall.target_tags),
                    "disabled": firewall.disabled,
                    "creation_timestamp": firewall.creation_timestamp,
                })
            self.data["resources"]["firewall_rules"] = firewall_data
            logging.info(f"Collected {len(firewall_data)} Firewall rules.")
        except Exception as e:
            logging.error(f"Error collecting Firewall rules: {e}")
            self.data["resources"]["firewall_rules"] = {"error": str(e)}
        return firewall_data


    def list_iam_policy(self):
        logging.info(f"Collecting IAM policy for project {self.project_id}...")
        command = f"gcloud projects get-iam-policy {self.project_id} --format=json"
        policy = self._execute_gcloud_command(command)
        if policy:
            self.data["resources"]["project_iam_policy"] = policy
            logging.info(f"Collected IAM policy for project {self.project_id}.")
        else:
            self.data["resources"]["project_iam_policy"] = {"error": "Failed to retrieve IAM policy."}
            logging.warning(f"Failed to collect IAM policy for project {self.project_id}.")
        return policy


    def list_sql_instances(self):
        logging.info("Collecting Cloud SQL instances...")
        # Uses gcloud as Python client library for sqladmin is a bit more complex for simple listing
        command = f"gcloud sql instances list --project={self.project_id} --format=json"
        sql_instances = self._execute_gcloud_command(command)
        if sql_instances is not None:
            self.data["resources"]["sql_instances"] = sql_instances
            logging.info(f"Collected {len(sql_instances)} Cloud SQL instances.")
        else:
            self.data["resources"]["sql_instances"] = {"error": "Failed to retrieve Cloud SQL instances."}
            logging.warning("Failed to collect Cloud SQL instances.")
        return sql_instances

    def list_gke_clusters(self):
        logging.info("Collecting GKE clusters...")
        command = f"gcloud container clusters list --project={self.project_id} --format=json"
        gke_clusters = self._execute_gcloud_command(command)
        if gke_clusters is not None:
            self.data["resources"]["gke_clusters"] = gke_clusters
            logging.info(f"Collected {len(gke_clusters)} GKE clusters.")
        else:
            self.data["resources"]["gke_clusters"] = {"error": "Failed to retrieve GKE clusters."}
            logging.warning("Failed to collect GKE clusters.")
        return gke_clusters
        
    def list_cloud_functions(self):
        logging.info("Collecting Cloud Functions (1st gen)...")
        # Note: Cloud Functions Gen2 are built on Cloud Run and might need a different approach
        # For 1st Gen:
        command_gen1 = f"gcloud functions list --project={self.project_id} --format=json"
        functions_gen1 = self._execute_gcloud_command(command_gen1)
        if functions_gen1 is not None:
            self.data["resources"]["cloud_functions_gen1"] = functions_gen1
            logging.info(f"Collected {len(functions_gen1)} Cloud Functions (1st gen).")
        else:
            self.data["resources"]["cloud_functions_gen1"] = {"error": "Failed to retrieve Cloud Functions (1st gen)."}
            logging.warning("Failed to collect Cloud Functions (1st gen).")
        return functions_gen1

    def list_cloud_run_services(self):
        logging.info("Collecting Cloud Run services...")
        # This command lists services across all regions
        command = f"gcloud run services list --project={self.project_id} --platform=managed --format=json"
        run_services = self._execute_gcloud_command(command)
        if run_services is not None:
            self.data["resources"]["cloud_run_services"] = run_services
            logging.info(f"Collected {len(run_services)} Cloud Run services.")
        else:
            self.data["resources"]["cloud_run_services"] = {"error": "Failed to retrieve Cloud Run services."}
            logging.warning("Failed to collect Cloud Run services.")
        return run_services

    def list_pubsub_topics(self):
        logging.info("Collecting Pub/Sub topics...")
        command = f"gcloud pubsub topics list --project={self.project_id} --format=json"
        topics = self._execute_gcloud_command(command)
        if topics is not None:
            self.data["resources"]["pubsub_topics"] = topics
            logging.info(f"Collected {len(topics)} Pub/Sub topics.")
        else:
            self.data["resources"]["pubsub_topics"] = {"error": "Failed to retrieve Pub/Sub topics."}
            logging.warning("Failed to collect Pub/Sub topics.")
        return topics

    def list_pubsub_subscriptions(self):
        logging.info("Collecting Pub/Sub subscriptions...")
        command = f"gcloud pubsub subscriptions list --project={self.project_id} --format=json"
        subscriptions = self._execute_gcloud_command(command)
        if subscriptions is not None:
            self.data["resources"]["pubsub_subscriptions"] = subscriptions
            logging.info(f"Collected {len(subscriptions)} Pub/Sub subscriptions.")
        else:
            self.data["resources"]["pubsub_subscriptions"] = {"error": "Failed to retrieve Pub/Sub subscriptions."}
            logging.warning("Failed to collect Pub/Sub subscriptions.")
        return subscriptions

    def collect_all(self, services=None):
        logging.info(f"Starting resource collection for project: {self.project_id}")
        
        # Define all possible collection methods
        all_methods = {
            "gce": self.list_gce_instances_all_zones,
            "gcs": self.list_gcs_buckets,
            "vpc": self.list_vpc_networks,
            "firewall": self.list_firewall_rules,
            "iam": self.list_iam_policy,
            "sql": self.list_sql_instances,
            "gke": self.list_gke_clusters,
            "functions": self.list_cloud_functions,
            "run": self.list_cloud_run_services,
            "pubsub_topics": self.list_pubsub_topics,
            "pubsub_subscriptions": self.list_pubsub_subscriptions,
        }

        methods_to_run = []
        if services:
            for service in services:
                if service.lower() in all_methods:
                    methods_to_run.append(all_methods[service.lower()])
                else:
                    logging.warning(f"Unknown service specified: {service}. Skipping.")
        else: # If no specific services are listed, run all
            methods_to_run = list(all_methods.values())
            
        # Using ThreadPoolExecutor to run collection methods in parallel
        # Adjust max_workers based on your environment and API quota limits
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(method) for method in methods_to_run]
            for future in as_completed(futures):
                try:
                    future.result()  # We call result to raise any exceptions that occurred
                except Exception as e:
                    # Logging is already done within each method, but good to catch here too
                    logging.error(f"Exception during a collection method: {e}")
        
        logging.info("Finished all resource collection.")
        return self.data

    def save_data(self, filename="gcp_resources.json"):
        filepath = os.path.join(self.output_dir, filename)
        try:
            with open(filepath, 'w') as f:
                json.dump(self.data, f, indent=2)
            logging.info(f"Successfully saved data to {filepath}")
        except IOError as e:
            logging.error(f"Error saving data to {filepath}: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Collect GCP resource information.")
    parser.add_argument("project_id", help="GCP Project ID")
    parser.add_argument("--output-dir", default="gcp_data", help="Directory to save the output JSON file.")
    parser.add_argument("--filename", default="gcp_resources.json", help="Filename for the output JSON.")
    parser.add_argument("--services", nargs='+', 
                        help="Specific services to collect (e.g., gce gcs vpc). Collects all if not specified.",
                        choices=['gce', 'gcs', 'vpc', 'firewall', 'iam', 'sql', 'gke', 'functions', 'run', 'pubsub_topics', 'pubsub_subscriptions'],
                        metavar='SERVICE')
    parser.add_argument("--quiet", action="store_true", help="Suppress console output (still logs to file if logging is configured).")


    args = parser.parse_args()

    # Reconfigure logging if quiet
    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING) # Or logging.CRITICAL to suppress almost everything
        # If you want to disable console output specifically:
        for handler in logging.getLogger().handlers:
            if isinstance(handler, logging.StreamHandler):
                handler.setLevel(logging.CRITICAL + 1) # Effectively disables it


    collector = GCPResourceCollector(project_id=args.project_id, output_dir=args.output_dir)
    
    # Collect specified services or all if none specified
    collected_data = collector.collect_all(services=args.services)
    
    collector.save_data(filename=args.filename)

    if not args.quiet:
        # Output to console only if not in quiet mode
        # Small summary to avoid overwhelming the console if data is large
        summary = {
            "project_id": collected_data["project_id"],
            "collected_resources": list(collected_data["resources"].keys())
        }
        print("Summary of collected data:")
        print(json.dumps(summary, indent=2))
        print(f"\nFull data saved to {os.path.join(args.output_dir, args.filename)}")
    else:
        print(json.dumps(collector.data, indent=2))
