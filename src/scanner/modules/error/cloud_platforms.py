from dataclasses import dataclass
from typing import List, Literal
from scanner.modules.error.signature import Signature

CloudCategory = Literal[
    "hyperscale_cloud",
    "edge_cdn",
    "paas_serverless",
    "iaas_hosting",
    "private_cloud",
    "analytics_platform",
    "specialized",
]

CLOUD_PLATFORM_SIGNATURES: List[Signature] = [
    Signature(
        display_name="Amazon Web Services",
        category="hyperscale_cloud",
        aliases=[
            "amazon web services", "aws", "aws lambda", "aws ec2",
        ],
    ),
    Signature(
        display_name="Microsoft Azure",
        category="hyperscale_cloud",
        aliases=[
            "microsoft azure", "azure", "azure functions", "azure app service",
        ],
    ),
    Signature(
        display_name="Google Cloud",
        category="hyperscale_cloud",
        aliases=[
            "google cloud", "google cloud platform", "gcp",
            "cloud run", "app engine",
        ],
    ),
    Signature(
        display_name="Cloudflare",
        category="edge_cdn",
        aliases=[
            "cloudflare", "cloudflare pages", "cloudflare workers",
        ],
    ),
    Signature(
        display_name="Firebase",
        category="paas_serverless",
        aliases=[
            "firebase", "firebase hosting",
        ],
    ),
    Signature(
        display_name="Vercel",
        category="paas_serverless",
        aliases=[
            "vercel",
        ],
    ),
    Signature(
        display_name="DigitalOcean",
        category="iaas_hosting",
        aliases=[
            "digitalocean", "digital ocean",
        ],
    ),
    Signature(
        display_name="Heroku",
        category="paas_serverless",
        aliases=[
            "heroku", "herokuapp.com",
        ],
    ),
    Signature(
        display_name="Netlify",
        category="paas_serverless",
        aliases=[
            "netlify",
        ],
    ),
    Signature(
        display_name="VMware",
        category="private_cloud",
        aliases=[
            "vmware", "vcenter", "vsphere",
        ],
    ),
    Signature(
        display_name="Hetzner",
        category="iaas_hosting",
        aliases=[
            "hetzner",
        ],
    ),
    Signature(
        display_name="Supabase (Cloud)",
        category="specialized",
        aliases=[
            "supabase",
        ],
    ),
    Signature(
        display_name="Linode (Akamai)",
        category="iaas_hosting",
        aliases=[
            "linode", "linode.com", "akamai", "linode now akamai",
        ],
    ),
    Signature(
        display_name="OVH",
        category="iaas_hosting",
        aliases=[
            "ovh", "ovhcloud",
        ],
    ),
    Signature(
        display_name="Managed Hosting",
        category="iaas_hosting",
        aliases=[
            "managed hosting",
        ],
    ),
    Signature(
        display_name="Oracle Cloud Infrastructure",
        category="hyperscale_cloud",
        aliases=[
            "oracle cloud infrastructure", "oracle cloud", "oci",
        ],
    ),
    Signature(
        display_name="Render",
        category="paas_serverless",
        aliases=[
            "render.com", "render",
        ],
    ),
    Signature(
        display_name="Fly.io",
        category="paas_serverless",
        aliases=[
            "fly.io", "flyio", "fly io",
        ],
    ),
    Signature(
        display_name="OpenShift",
        category="private_cloud",
        aliases=[
            "openshift", "red hat openshift",
        ],
    ),
    Signature(
        display_name="Databricks",
        category="analytics_platform",
        aliases=[
            "databricks", "databricks sql",
        ],
    ),
    Signature(
        display_name="PythonAnywhere",
        category="paas_serverless",
        aliases=[
            "pythonanywhere",
        ],
    ),
    Signature(
        display_name="Vultr",
        category="iaas_hosting",
        aliases=[
            "vultr",
        ],
    ),
    Signature(
        display_name="OpenStack",
        category="private_cloud",
        aliases=[
            "openstack",
        ],
    ),
    Signature(
        display_name="Alibaba Cloud",
        category="hyperscale_cloud",
        aliases=[
            "alibaba cloud", "aliyun",
        ],
    ),
    Signature(
        display_name="IBM Cloud / Watson",
        category="hyperscale_cloud",
        aliases=[
            "ibm cloud", "ibm cloud or watson", "ibm watson",
        ],
    ),
    Signature(
        display_name="Scaleway",
        category="iaas_hosting",
        aliases=[
            "scaleway",
        ],
    ),
    Signature(
        display_name="Colocation",
        category="iaas_hosting",
        aliases=[
            "colocation", "colo",
        ],
    ),
]

CLOUD_PLATFORM_NAMES = [c.display_name for c in CLOUD_PLATFORM_SIGNATURES]
