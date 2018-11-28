# AWS-SAML-ADFS3-MultiRoles

This script provides a more simple method of authenticating to AWS CLI via SAML and ADFS3 when you have multiple roles to choose from.

Feel free to modify the code to suit your needs.

NOTE: Change the <url><port> in the 'idpentryurl' to your URL.

PREREQUISITES:

A few modules are required for this program that aren't typically included with the default python libraries. Be sure to check them out.

- Python 3.6
- AWS SDK for Python (Boto3) https://aws.amazon.com/sdk-for-python/
- BeautifulSoup4
- lxml

USAGE:

```sh
sudo python aws-saml-adfs3-multiroles.py
```
