# Deploy DataPower Objects

## Overview
This project gives a framework from which files and objects can be deployed to a target DataPower doamin, and exported from a source DataPower domain.  Files can be any file needed to support an implementation, including SSL certificates.  Objects include any object needed for the implementation/solution.

The framework uses the DataPower REST API instead of the usual SOMA interface, and as such all objects are stored and manipulated as JSON files.

The export is implemented much in the same way as exporting an object from the console.  All children objects and files referenced by those objects are exported.  Files referenced in files however are not exported at this time.

Objects and files are templatized with environment specific values stored in configuration files.  This allows the object to be transportable between environments, and at the same time unique for each enviornment.

## Structure
The framework uses a defined file structure where configuration files, regular files, SSL certificates, and objects are found.

### Top Level
The top directory is where the deployment engine (buildDP.py) and DataPower Domain Object config file (dpDomObj.json) are found.

### Environments
The environments directory holds the configuration files for each environment.

### Files
The files directory is where regular files and SSL certificates are stored.  The file structure here correlates directly to the file structure in a DataPower domain.  That means, any file located in files/cert will be copied to the domain's cert folder.  Any file in files/sharedcert will be copied to the domain's sharedcert folder.  The files and file structures under files/local will be created and/or copied to the domain's local folder.

#### Certificates
Certificate files must be in PEM format and must not contain bag attributes.  Files not in this format will fail to upload.

### Objects
DataPower objects are stored in the objects directory, with subdirecories by type if you grouping is desired.  These are JSON files which are the representation of exported objects via the REST API.

## Configuration Files
Configuration files allow for objects and files to be unique across environments.    

### Environment Config Files
Specific values that change from environment to environment are stored in the environment JSON file.

These are the field defintions:
| Field Name | Description |
| ---------- | ----------- |
| **environment** | Name of the environment |
| **description** | Description of the environment (optional) |
| **dpgateways** | Dictionary of DataPower devices that define this environment |
| __*dp gateway name*__ | The name of the DataPower Gateway |
| **hosts** | List of DataPower hosts with hostname and IP |
| **restPort** | Port enabled for DataPower REST Management |
| **variables** | Dictionary whose key/values will be used in templating files and objects |


Example of an environment configuration file:
```javascript
{  
   "environment":"ENV1",
   "description":"DP Gateway Customization Variables for ENV1",
   "dpgateways": {  
      "DP Security Gateway": {  
         "hosts": [
            ["dpsg.hostname.com", "1.2.3.4"]
         ],
         "restPort": 5554
      },
      "DP ODR": {  
         "hosts": [
            ["dpodr.hostname.com", "5.6.7.8"]
         ],
         "restPort": 5554
      }
   },
   "variables": {
      "ssl_key_passphrase": "cGFzc3dvcmQ=",
      "certs": {
         "sg_ssl_key": ["cert", "key.pem"],
         "sg_ssl_cert": ["cert", "cert.pem"],
      },
      "controller": "controller.hostname.com",
      "controller_port": 9443,
      "controller_password": "cGFzc3dvcmQ=",
      "odr_ssl_key_passphrase": "cGFzc3dvcmQ=",
      "log_tgt_host": "myvm.hostname.com",
      "dp_sg_host": "apip-env.hostname.com",
      "api_port": ":9447",
      "f5_cidr": {
         "allow": [
            "1.2.3.20/29"
         ]
      },
      "odr_conn_group": "ODR_CG"
   }
}
```

### Object Configuration File 
The *dpDomObj.json* file holds configuration for the different objects.  In looking at the example below, it utilizes Jinja2 templating to assign values to keys from the environment JSON file.

The configuraiton holds objects by DataPower type.  Each DataPower type holds a dictionary of parent objects with four fields.

These are the field defintions:
| Field Name | Description |
| ---------- | ----------- |
| **domain** | Name of the domain to which the object belongs |
| **name** | Name of the parent object |
| **type** | Type of object as defined by REST API |
| **parms** | Dictionary of values to override in the object tree |

Example of *dpDomObj.json* file:
```javascript
{
   "DP Security Gateway": {
      "mpg-routing": {
         "domain": "{{env}}",
         "name": "MPG-Routing",
         "type": "MultiProtocolGateway",
         "parms": {
            "f5-acl.AccessControlEntry": "{{f5_cidr|acllist}}",
            "fsh-https-443.LocalAddress": "<<hostIP>>",
            "mpg-routing_multiprotocolgateway.BackendUrl": "{{mpg_routing_backendurl}}",
            "ssl-alias.Password": "{{ssl_key_passphrase|b64decode}}",
            "ssl-key.Filename": "{{certs.sg_ssl_key[0]}}:///{{certs.sg_ssl_key[1]}}",
            "ssl-cert.Filename": "{{certs.sg_ssl_cert[0]}}:///{{certs.sg_ssl_cert[1]}}"
         }
      }
   },
   "DP ODR": {
      "hostalias": {
         "domain": "default",
         "name": "{{dp_sg_host}}",
         "type": "HostAlias",
         "parms": {
            "hostname.name": "{{dp_sg_host}}",
            "hostname.IPAddress": "<<hostIP>>"
         }
      },
      "dp-globalpolicy": {
         "domain": "{{env}}",
         "name": "DP_GlobalPolicy",
         "type": "MultiProtocolGateway",
         "parms": {
            "ssl-alias.Password": "{{ssl_key_passphrase|b64decode}}",
            "ssl-key.Filename": "{{certs.odr_ssl_key[0]}}:///{{certs.odr_ssl_key[1]}}",
            "ssl-cert.Filename": "{{certs.odr_ssl_cert[0]}}:///{{certs.odr_ssl_cert[1]}}",
            "https-9443.LocalAddress": "<<hostIP>>",
            "bluemix-01.Password": "{{bluemix_cms_password|b64decode}}",
            "dp-globalpolicy_multiprotocolgateway.BackendUrl": "https://{{dp_sg_host}}{{api_port}}", 
            "dp-globalpolicy_multiprotocolgateway.DebugMode": "off" 
         }
      },
      "odr-conn-group" : {
         "domain": "default",
         "name": "ODR_CG_{{env|upper}}",
         "type": "ODRConnectorGroup",
         "parms": {
            "controller-password.Password": "{{controller_password|b64decode}}",
            "odr-useragent.BasicAuthPolicies.RegExp": "*{{controller}}*", 
            "odr-ssl-alias.Password": "{{odr_ssl_key_passphrase|b64decode}}",
            "odr-ssl-key.Filename": "{{certs.odr_ssl_key[0]}}:///{{certs.odr_ssl_key[1]}}",
            "odr-ssl-cert.Filename": "{{certs.odr_ssl_cert[0]}}:///{{certs.odr_ssl_cert[1]}}",
            "controller-cert.Filename": "{{certs.controller_cert[0]}}:///{{certs.controller_cert[1]}}",
            "odr-cg.ODRGroupConnectors.DmgrHostname": "{{controller}}",
            "odr-cg.ODRGroupConnectors.DmgrPort": "{{controller_port}}"
         }
      },
      "log-target" : {
         "domain": "{{env}}",
         "name": "Global_Policy_Logging",
         "type": "LogTarget",
         "parms": {
            "global-policy-logging.LocalFile": "logtemp:///<<env|lower>>-<<host|hostId>>", 
            "global-policy-logging.RemoteAddress": "{{log_tgt_host}}",
            "global-policy-logging.RemoteDirectory": "/logs/dp/odr"
         }
      },
      "mpg-config-svc" : {
         "domain": "{{env}}",
         "name": "MPG_Config_Svc",
         "type": "MultiProtocolGateway",
         "parms": {
            "bluemix-01.Password": "{{bluemix_cms_password|b64decode}}",
            "ssl-alias.Password": "{{ssl_key_passphrase|b64decode}}",
            "ssl-key.Filename": "{{certs.odr_ssl_key[0]}}:///{{certs.odr_ssl_key[1]}}",
            "ssl-cert.Filename": "{{certs.odr_ssl_cert[0]}}:///{{certs.odr_ssl_cert[1]}}",
            "mpg-config-svc_multiprotocolgateway.BackendUrl": "{{config_svc_url}}"
         }
      }
   }
}
```
The *parms* dictionary is used to override specific key value pairs in objects.  The format of a parameter is *objectname*.*key*.  When the object is imported into DataPower, the object data structure is scanned for that given key and the value in the object overridden with the new value.

Values that are surrounded by '<< >>' are replaced in object with a templated variable during import time.  For example, in looking at the **hostalias** object above, we see:
```javascript
         "parms": {
            "hostname.name": "{{dp_sg_host}}",
            "hostname.IPAddress": "<<hostIP>>"
         }
```

On export of the **hostalias** object from the **DP ODR**, the corresponding JSON file will contain
```javascript
{
   "hostname": {
      "HostAlias": {
         "name": "hostname.com", 
         "mAdminState": "enabled", 
         "IPAddress": "{{hostIP}}"
      }
   }
}
```

This convention can be used if you want to template objects at export time.

## Requirements to Run
The *buildDP.py* Python script has been tested using Python 2.7.15.  It requires the *jinja2* module to handle templating.

While an attmept to was made to write this script to be generic and handle all cases, it was written to address a specific problem.  As such, it may need to be further modified to truly address the user's particular needs.