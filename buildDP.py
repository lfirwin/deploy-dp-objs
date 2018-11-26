import jinja2, sys, os, urllib, httplib, base64, json, ssl, string, argparse, time
from collections import OrderedDict
import types

# Use to define DataPower gateway types
# GATEWAY_TYPES = {"sg":"DP Security Gateway","odr":"DP ODR"}
GATEWAY_TYPES = {"dp":"DP Gateway"}
# Use the following dictionary to translate source domain names to actual domain names
# DOMAINS = {"SOME_DOM":"REAL_DOM"}
DOMAINS = {}
FILE_REQUEST = {"file": {"name":"","content":""}}
DIR_REQUEST = {"directory": {"name": ""}}
SAVE_CONFIG = json.dumps({"SaveConfig":{}}, indent=3)
CHECKPOINT = {"SaveCheckpoint":{"ChkName":""}}
ACTIONS = ["AddPasswordMap"]
DELETE_PASS_MAP = {"DeletePasswordMap": {"AliasName": ""}}
REF_OBJECTS = {'user-agent':'HTTPUserAgent', 'key':'CryptoKey'}

def createObject(templateEnv, template, envVars):
   # Read the template file using the environment object.
   # This also constructs our Template object.
   if not '.' in template:
      template +=  ".json"
   #print "   Building object(s) from template " + template
   template = templateEnv.get_template(template)
   # Finally, process the template to produce our final text.
   return template.render(envVars)


def saveObjects(requestConn, headers, domain):
   requestConn.request("POST", "/mgmt/actionqueue/%s" % (domain), SAVE_CONFIG, headers)
   response = requestConn.getresponse()
   print response.status, response.reason
   print response.read()


def encodeFile(file):
   with open(file) as f:
      encoded = base64.b64encode(f.read())
      return encoded


def uploadCert(files, cert, host, port, headers, domain="default"):
   file = files + cert[0] + "/" + cert[1]
   print file
   fileRequest = FILE_REQUEST
   #fileRequest["file"]["name"] = file.split("/")[-1]
   fileRequest["file"]["name"] = cert[1]
   fileRequest["file"]["content"] = encodeFile(file)
   targetFile = "/".join(cert)
   if 'sharedcert' in targetFile:
      domain = 'default'
   print "/mgmt/filestore/%s/%s" % (domain, targetFile)
   body = json.dumps(fileRequest, indent=3, sort_keys=True)
   if options.debug:
      print body
      return
   connection = httplib.HTTPSConnection(host, port,context=ssl._create_unverified_context())
   connection.request("PUT", "/mgmt/filestore/%s/%s" % (domain, targetFile), body, headers)
   response = connection.getresponse()
   print response.status, response.reason
   print response.read()


def b64decode(encoded):
    return base64.b64decode(encoded)


def hostId(fqdn):
   fqdn = fqdn.split('.')[0]
   for c in fqdn:
      if c in string.letters or c == '0':
         fqdn = fqdn[1:]
      else:
         break
   return fqdn


def acllist(value):
   acl = []
   for access, addresses in value.iteritems():
      for address in addresses:
         entry = {}
         entry['Access'] = access
         entry['Address'] = address
         acl.append(entry)
   return json.dumps(acl)


def loadEnvConfig(currDir, env):
   environments = currDir + "/environments"
   envConfig = environments + "/" + env + ".json"
   if os.path.isfile(envConfig):
      with open(envConfig,'r') as envConfigFile:
         envConfigJSON = json.loads(envConfigFile.read())
   else:
      print "The environment configuration file " + envConfig + " does not exist."
      exit()
   return envConfigJSON


def loadDomainObjConfig(currDir, envVars):
   templateLoaderFiles = jinja2.FileSystemLoader(searchpath=currDir)
   templateDomObjFile = jinja2.Environment(loader=templateLoaderFiles)
   templateDomObjFile.filters['b64decode'] = b64decode
   templateDomObjFile.filters['acllist'] = acllist
   dpDomainObjJSON = createObject(templateDomObjFile, "dpDomObj.json", envVars)
   return json.loads(dpDomainObjJSON, object_pairs_hook=OrderedDict)


def getDomainObjects(envConfigJSON, dpDomainObjects, gwType, gwObject):
   # Get object type and name
   objConfig = dpDomainObjects[GATEWAY_TYPES[gwType]].get(gwObject, None)
   if not objConfig:
      print "The object " + gwObject + " was not found in the dpDomObj.json config file"
      exit()
   gwObjType = objConfig.get("type", None)
   if not gwObjType:
      print "The object " + gwObject + " doesn't have an object type configured in dpDomObj.json"
      exit()
   gwObjectName = objConfig.get("name", None)
   if not gwObjectName:
      print "The object " + gwObject + " doesn't have an object name configured in dpDomObj.json"
      exit()
   gwObjectParms = objConfig.get("parms", None)
   if not gwObjectParms:
      print "WARNING: The object " + gwObject + " doesn't have an object parms configured in dpDomObj.json"

   # Determine the object domain
   gwObjectDomain = objConfig.get("domain", None)
   if not gwObjectDomain:
      print "The object " + gwObject + " doesn't have an domain configured in dpDomObj.json"
      exit()
   if gwObjectDomain != "default":
      subDomain = envConfigJSON["dpgateways"][GATEWAY_TYPES[gwType]].get("domain", None)
      if subDomain:
          gwObjectDomain = subDomain
      gwObjectDomain = DOMAINS.get(gwObjectDomain,gwObjectDomain)
   return gwObjType, gwObjectName, gwObjectParms, gwObjectDomain


def getAuthHeader():
   # Set BasicAuth for REST requests
   password = ''
   while not password:
      password = raw_input("Enter admin password: ")
   basicAuth = base64.encodestring('admin:' + password).replace("\n","")
   authHeader = {}
   authHeader["Authorization"] = "Basic " + basicAuth
   return authHeader


def getObject(requestConn, uri, authHeader, objects, env):
   requestConn.request("GET", uri, "", authHeader)
   response = requestConn.getresponse()
   respJSON = json.loads(response.read(), object_pairs_hook=OrderedDict)
   respJSON.pop('_links', None)

   objectType = next(iter(respJSON))
   object = respJSON[objectType]
   for element in object:
      if type(object[element]) is OrderedDict:
         if object[element].get("href", None):
            getObject(requestConn, object[element]["href"], authHeader, objects, env)
            object[element] = object[element]["value"]
         else:
            subObject = object[element]
            for subElement in subObject:
               if type(subObject[subElement]) is OrderedDict and subObject[subElement].get("href",None):
                  getObject(requestConn, subObject[subElement]["href"], authHeader, objects, env)
                  subObject[subElement] = subObject[subElement]["value"]
      elif type(object[element]) is list:
         objectList = object[element]
         for member in objectList:
           if type(member) is OrderedDict:
              if member.get("href",None):
                 getObject(requestConn, member["href"], authHeader, objects, env)
                 objectList[objectList.index(member)] = member["value"]
              else:
                 for memberObject in member:
                    if type(member[memberObject]) is OrderedDict and member[memberObject].get("href",None):
                       getObject(requestConn, member[memberObject]["href"], authHeader, objects, env)
                       member[memberObject] = member[memberObject]["value"]

   if 'kaiserpermanente.org' in object['name'] or 'kp.org' in object['name']:
      name = 'hostname'
   else:
      name = object['name'].lower().replace('_','-')
   if env.lower() + '-' in name:
      name = name.replace(env.lower() + '-','')
   if '-' + env.lower() in name:
      name = name.replace('-' + env.lower(),'')
   if objectType == "PasswordAlias":
      objects[name] = OrderedDict([('AddPasswordMap',OrderedDict([('AliasName',object['name']),('Password','{{password}}')]))])
      respJSON = objects[name]
      print "   Exported " + name
      return
   if objectType == "Matching":
      name = 'match-rule-' + name
   collision = objects.get(name, None)
   if not collision:
      objects[name] = respJSON
   elif collision != respJSON:
      name += "_" + objectType.lower()
      objects[name] = respJSON
   else:
      return
   print "   Exported " + name


def getFiles(requestConn, domain, searchLines, authHeader, filesDir, files):
   lines = searchLines
   for line in lines:
      # Find and parse file names
      if "local:///" in line:
         tLine = line.strip().split('local:///')[1][::-1]
         for c in tLine:
            if c in string.letters or c in string.digits:
               break
            tLine = tLine[1:]
         fileURI = 'local/' + tLine[::-1]
      elif "include href" in line:
         fileURI = 'local/ext/' + line.split()[1][6:-1]
      else:
         continue
      # Download the file
      print "   Downloading file " + fileURI
      requestConn.request("GET", "/mgmt/filestore/%s/%s" % (domain, fileURI), "", authHeader)
      response = requestConn.getresponse()
      respJSON = json.loads(response.read(), object_pairs_hook=OrderedDict)

      # Remove extraneous elements
      respJSON.pop('_links', None)

      # Append to list of files for this object
      files.append(fileURI)
      fileCont = b64decode(respJSON["file"])

      # Save the decoded contents of the file
      if options.debug:
         print fileCont
      else:
         fileDir = '/'.join(fileURI.split('/')[:-1])
         if not os.path.exists(filesDir + "/" + fileDir):
            os.makedirs(filesDir + "/" + fileDir)
         with open(filesDir + "/" + fileURI, 'w') as file:
            file.write(fileCont)

      # Search for files in this file
      getFiles(requestConn, domain, fileCont.split('\n'), authHeader, filesDir, files)


def exportObject(envConfigJSON, dpDomainObjects, gwType, gwObject):
   # Set environment variables
   restPort = envConfigJSON["dpgateways"][GATEWAY_TYPES[gwType]]["restPort"]
   gwHost = envConfigJSON["dpgateways"][GATEWAY_TYPES[gwType]]["hosts"][0][0]

   # Get Object Configurations
   gwObjType, gwObjectName, gwObjectParms, gwObjectDomain = getDomainObjects(envConfigJSON, dpDomainObjects, gwType, gwObject)

   # Get BasicAuth credentials
   authHeader = getAuthHeader()

   # Create a connection request
   if len(envConfigJSON["dpgateways"][GATEWAY_TYPES[gwType]]["hosts"][0]) == 2:
      requestConn = httplib.HTTPSConnection(envConfigJSON["dpgateways"][GATEWAY_TYPES[gwType]]["hosts"][0][0], restPort, context=ssl._create_unverified_context())
   else:
      requestConn = httplib.HTTPSConnection(envConfigJSON["dpgateways"][GATEWAY_TYPES[gwType]]["hosts"][0][2], restPort, context=ssl._create_unverified_context())

   # Download all objects associated with the requested object
   print "Exporting " + gwObjectName + " and it's associated objects..."
   objects = OrderedDict()
   getObject(requestConn, "/mgmt/config/%s/%s/%s" % (gwObjectDomain, gwObjType, gwObjectName), authHeader, objects, envConfigJSON["environment"])

   # Download all files associated with downloaded objects
   print;print "Downloading files for " + gwObjectName + "..."
   objectsJSON = json.dumps(objects, indent=3)
   files = []
   getFiles(requestConn, gwObjectDomain, objectsJSON.split('\n'), authHeader, currDir + '/files', files)
   if len(files) == 0:
      print "   No files to download"
   objects["files"] = files

   # Parameterize the object
   print;print "Parameterizing values for " + gwObjectName + "..."
   if gwObjectParms:
      for path, parm in gwObjectParms.iteritems():
         if '<<' in parm:
            parm = parm.replace('<<','{{')
            parm = parm.replace('>>','}}')
            levels = path.split('.')
            element = levels[-1]
            obj = objects[levels[0]]
            obj = obj[next(iter(obj))]
            levels = levels[1:-1]
            for level in levels:
               obj = obj[level]
            obj[element] = parm
            print "   Parameterized path '" + path + "' with '" + parm + "'"
   else:
      print "   No values to parameterize"

   # Handle default domain objects with environment in the name
   env = envConfigJSON["environment"]
   envLower = env.lower()
   envUpper = env.upper()
   lines = json.dumps(objects, indent=1).split('\n')
   update = []
   for i, line in enumerate(lines):
      line = line.replace(envLower, '{{env|lower}}')
      line = line.replace(envUpper, '{{env|upper}}')
      update.append(line)
   objects = json.loads(''.join(update), object_pairs_hook=OrderedDict)

   # Display objects if debug mode
   if options.debug:
      print;print "JSON for " + gwObjectName + ":"
      print json.dumps(objects, indent=3)
      return

   # Write object JSON definition to a file
   if not os.path.exists(currDir + "/objects/") or not os.path.exists(currDir + "/objects/" + gwType):
      os.makedirs(currDir + "/objects/" + gwType)
   jsonFileName = currDir + "/objects/" + gwType + "/" + gwObject + ".json"
   with open(jsonFileName, "w") as jsonFile:
      json.dump(objects,jsonFile,indent=3)
   print;print "JSON for object " + gwObjectName + " written to " + jsonFileName
   print


def loadCerts(lines, filesDir, certs):
   for line in lines:
      if "sharedcert:///" in line:
         certType = "sharedcert"
      elif "cert:///" in line:
         certType = "cert"
      else:
         continue
      cert = line.strip().split(certType + ':///')[1][::-1]
      for c in cert:
         if c in string.letters or c in string.digits:
            break
         cert = cert[1:]
      certFile = cert[::-1]
      cert = "%s/%s" % (certType, certFile)
      if certs.get(cert,None):
         continue
      certs[cert] = OrderedDict([('file',OrderedDict([('name',certFile),('content', encodeFile('%s/%s/%s' % (filesDir, certType, certFile)))]))])


def uploadCerts(requestConn, certs, domain, authHeader):
   for certURI, cert in certs.iteritems():
      if 'sharedcert' in certURI:
         uriDomain = 'default'
      else:
         uriDomain = domain
      if options.debug:
         print "/mgmt/filestore/%s/%s" % (uriDomain, certURI)
         print json.dumps(cert, indent=3)
         continue
      requestConn.request("PUT", "/mgmt/filestore/%s/%s" % (uriDomain, certURI), json.dumps(cert, indent=3), authHeader)
      response = requestConn.getresponse()
      print response.status, response.reason
      print response.read()


def uploadFiles(requestConn, files, filesDir, domain, envVars, authHeader):
   builtDirs = []
   for dpFile in files:
      fileParts = dpFile.split("/")
      dpFile = fileParts[-1]
      dirs = fileParts[0]
      for i in range(1, len(fileParts)-1):
         dirs += "/" + fileParts[i]
         if dirs in builtDirs:
            continue
         dirRequest = DIR_REQUEST
         dirRequest ["directory"]["name"] = fileParts[i]
         requestBody = json.dumps(dirRequest, indent=3, sort_keys=True)
         if options.debug:
            print dpFile
            print "/mgmt/filestore/%s/%s" % (domain, dirs)
            print requestBody
            builtDirs.append(dirs)
            continue
         #requestConn = httplib.HTTPSConnection(gwHost, restPort, context=ssl._create_unverified_context())
         requestConn.request("PUT", "/mgmt/filestore/%s/%s" % (domain, dirs), requestBody, authHeader)
         response = requestConn.getresponse()
         print response.status, response.reason
         print response.read()
      templateLoaderFiles = jinja2.FileSystemLoader(searchpath=filesDir+"/"+dirs)
      templateEnvFiles = jinja2.Environment(loader=templateLoaderFiles)
      templateEnvFiles.filters['b64decode'] = b64decode
      outputText = createObject(templateEnvFiles, dpFile, envVars)
      fileRequest = FILE_REQUEST
      fileRequest["file"]["name"] = dpFile
      fileRequest["file"]["content"] = base64.encodestring(outputText)
      requestBody = json.dumps(fileRequest, indent=3, sort_keys=True)
      if options.debug:
         print "/mgmt/filestore/%s/%s/%s" % (domain, dirs, dpFile)
         print requestBody
         print outputText
         continue
      #requestConn = httplib.HTTPSConnection(gwHost, restPort, context=ssl._create_unverified_context())
      requestConn.request("PUT", "/mgmt/filestore/%s/%s/%s" % (domain, dirs, dpFile), requestBody, authHeader)
      response = requestConn.getresponse()
      print response.status, response.reason
      print response.read()


def updatePasswordAlias(requestConn, object, domain, authHeader):
   deletePassMap = DELETE_PASS_MAP
   deletePassMap['DeletePasswordMap']['AliasName'] = object['AddPasswordMap']['AliasName']
   requestConn.request("POST", "/mgmt/actionqueue/%s" % (domain), json.dumps(deletePassMap), authHeader)
   response = requestConn.getresponse()
   respJSON = json.loads(response.read())
   respJSON.pop('_links', None)
   error = respJSON.get('error', None)
   if error:
      error = error[1]
   else:
      return
   if error.startswith('Cannot find config'):
      return
   if error.startswith('Cannot be deleted'):
      reference = error.split()[-1]
      objClass = reference.split('(')[0]
      objName = reference.split('(')[1][:-1]
      requestConn.request("GET", "/mgmt/config/%s/%s/%s" % (domain, REF_OBJECTS[objClass], objName), "", authHeader)
      response = requestConn.getresponse()
      respJSON = json.loads(response.read(), object_pairs_hook=OrderedDict)
      respJSON.pop('_links', None)
      if objClass == 'user-agent':
         respJSON['HTTPUserAgent']['BasicAuthPolicies']['PasswordAlias'] = ""
      elif objClass == 'key':
         respJSON['CryptoKey']['Alias'] = ""
         respJSON['CryptoKey']['PasswordAlias'] = "off"
      if options.debug:
         print json.dumps(respJSON, indent=3)
         print json.dumps(deletePassMap, indent=3)
      else:
         print json.dumps(respJSON, indent=3)
         requestConn.request("PUT", "/mgmt/config/%s/%s/%s" % (domain, REF_OBJECTS[objClass], objName), json.dumps(respJSON), authHeader)
         response = requestConn.getresponse()
         print response.status, response.reason
         print response.read()
         saveObjects(requestConn, authHeader, domain)
         requestConn.request("POST", "/mgmt/actionqueue/%s" % (domain), json.dumps(deletePassMap), authHeader)
         response = requestConn.getresponse()
         print response.status, response.reason
         print response.read()
         saveObjects(requestConn, authHeader, domain)
   return


def createDomain(gwObjectDomain, requestConn, authHeader):
   # Get list of domains
   requestConn.request("GET", "/mgmt/domains/config/", "", authHeader)
   response = requestConn.getresponse()
   respJSON = json.loads(response.read())
   if respJSON.get('error', None):
      print json.dumps(respJSON)
      exit()
   respJSON.pop('_links', None)
   # Check for domain existance
   if isinstance(respJSON['domain'], list):
      for domain in respJSON['domain']:
         if domain['name'] == gwObjectDomain:
            return

   # Create the domain
   payload = {"Domain": {"name": gwObjectDomain, "mAdminState": "enabled"}}
   requestConn.request("PUT", "/mgmt/config/default/Domain/%s" % (gwObjectDomain), json.dumps(payload), authHeader)
   response = requestConn.getresponse()
   print "Created domain"
   print response.status, response.reason
   print response.read()
   saveObjects(requestConn, authHeader, "default")


def importObject(envConfigJSON, dpDomainObjects, gwType, gwObject, gwComponents):
   # Set environment variables
   restPort = envConfigJSON["dpgateways"][GATEWAY_TYPES[gwType]]["restPort"]
   envVars = envConfigJSON["variables"]

   # Get Object Configurations
   gwObjType, gwObjectName, gwObjectParms, gwObjectDomain = getDomainObjects(envConfigJSON, dpDomainObjects, gwType, gwObject)

   # Get BasicAuth credentials
   authHeader = getAuthHeader()

   print "Importing " + gwObjectName + " and it's associated objects, certs, and files into " + envConfigJSON["environment"] + "..."

   # Import objects into each host for this environment
   for gwHost in envConfigJSON["dpgateways"][GATEWAY_TYPES[gwType]]["hosts"]:
      print "Updating " + gwHost[0]

      # Update environment variables for this host
      envVars["host"] = gwHost[0]
      envVars["hostIP"] = gwHost[1]

      # Create a connection request
      if len(gwHost) == 2:
        requestConn = httplib.HTTPSConnection(gwHost[0], restPort, context=ssl._create_unverified_context())
      else:
        requestConn = httplib.HTTPSConnection(gwHost[2], restPort, context=ssl._create_unverified_context())

      # Create Domain if does not exist
      createDomain(gwObjectDomain, requestConn, authHeader)

      # Take a checkpoint
      if options.checkpoint:
         saveCheckpoint(envConfigJSON, gwObjectDomain, requestConn, authHeader)

      # Build the objects from the objects template
      objectsFile = "%s/objects/%s" % (currDir, gwType)
      templateLoaderObjects = jinja2.FileSystemLoader(searchpath=objectsFile)
      templateEnvObjects = jinja2.Environment( loader=templateLoaderObjects)
      templateEnvObjects.filters['b64decode'] = b64decode
      templateEnvObjects.filters['hostId'] = hostId
      objectsJSON = createObject(templateEnvObjects, gwObject, envVars)
      objects = json.loads(objectsJSON, object_pairs_hook=OrderedDict)

      # Parameterize the object
      print;print "Updating " + gwObjectName + " with environment specific values..."
      if gwObjectParms:
         for path, parm in gwObjectParms.iteritems():
            if '<<' in parm and '>>' in parm:
               continue
            levels = path.split('.')
            element = levels[-1]
            obj = objects[levels[0]]
            obj = obj[next(iter(obj))]
            levels = levels[1:-1]
            for level in levels:
               obj = obj[level]
            obj[element] = parm
            print "   Parameterized path '" + path + "' with:"
            print parm
      else:
         print "   No values to parameterize"

      #Upload certs
      if 'certs' in gwComponents:
         objectsJSON = json.dumps(objects, indent=1)
         certs = OrderedDict()
         loadCerts(objectsJSON.split('\n'), currDir + '/files', certs)
         uploadCerts(requestConn, certs, gwObjectDomain, authHeader)

      #Upload Files
      if 'files' in gwComponents:
         uploadFiles(requestConn, objects["files"], currDir + '/files', gwObjectDomain, envVars, authHeader)

      # Import the objects
      if not 'objects' in gwComponents:
         print
         continue

      for objectId, object in objects.iteritems():
         if objectId == "files":
            continue
         objectType = next(iter(object))
         requestBody = json.dumps(object, indent=3)

         if objectType in ACTIONS:
            if objectType == 'AddPasswordMap':
               updatePasswordAlias(requestConn, object, gwObjectDomain, authHeader)
            if options.debug:
               print requestBody
               continue
            requestConn.request("POST", "/mgmt/actionqueue/%s" % (gwObjectDomain), requestBody, authHeader)
            response = requestConn.getresponse()
            print response.status, response.reason
            print response.read()
            continue

         if options.debug:
            print "/mgmt/config/%s/%s/%s" % (gwObjectDomain, objectType, object[objectType]["name"])
            print requestBody
            continue
         print "/mgmt/config/%s/%s/%s" % (gwObjectDomain, objectType, object[objectType]["name"])
         requestConn.request("PUT", "/mgmt/config/%s/%s/%s" % (gwObjectDomain, objectType, object[objectType]["name"]), requestBody, authHeader)
         response = requestConn.getresponse()
         print response.status, response.reason
         print response.read()
         saveObjects(requestConn, authHeader, gwObjectDomain)
      print


def createCheckpoint(envConfigJSON):
   # Set environment variables
   restPort = envConfigJSON["dpgateways"][GATEWAY_TYPES[gwType]]["restPort"]
   envVars = envConfigJSON["variables"]

   # Get BasicAuth credentials
   authHeader = getAuthHeader()

   print "Creating Checkpoint for " + envConfigJSON["environment"] + "..."

   # Create a checkpoint each host for this environment
   for gwHost in envConfigJSON["dpgateways"][GATEWAY_TYPES[gwType]]["hosts"]:
      print "   Updating " + gwHost[0]

      # Update environment variables for this host
      envVars["host"] = gwHost[0]
      envVars["hostIP"] = gwHost[1]

      # Create a connection request
      requestConn = httplib.HTTPSConnection(gwHost[0], restPort, context=ssl._create_unverified_context())

      gwObjectDomain = DOMAINS.get(envConfigJSON["environment"], envConfigJSON["environment"])

      saveCheckpoint(envConfigJSON, gwObjectDomain, requestConn, authHeader)


def saveCheckpoint(envConfigJSON, gwObjectDomain, requestConn, authHeader):
   CHECKPOINT["SaveCheckpoint"]["ChkName"] =  envConfigJSON["environment"] + "_" + str(time.time()).split(".")[0]
   requestBody = json.dumps(CHECKPOINT, indent=3)
   if options.debug:
      print requestBody
      return
   gwObjectDomain = DOMAINS.get(envConfigJSON["environment"], envConfigJSON["environment"])
   requestConn.request("POST", "/mgmt/actionqueue/%s" % (gwObjectDomain), requestBody, authHeader)
   response = requestConn.getresponse()
   print response.status, response.reason
   print response.read()


def parseOptions(copyargs):
   parser = argparse.ArgumentParser()
   parser.add_argument("-a", "--action", dest='action', choices=('i','x','c'), help="Actions: (i)mport, e(x)port", required=True)
   parser.add_argument("-e", "--env", dest="env", help="Environment to build: dev10, hint3", required=True)
   parser.add_argument("-g", "--gwType", dest="gwType", help="Type of Gateway - Security Gateway (sg), ODR (odr), All (all)", required=True)
   parser.add_argument("-o", "--object", dest="gwObject", help="Object name in dpDomObj.json config file.")
   parser.add_argument("-d", "--debug", action="store_true", dest="debug", help="Run in Debug Mode", default=False)
   parser.add_argument("-c", "--components", dest="gwComponents", help="Specific object components to process: certs, objects, files, actions, all (Optional)", default="all")
   parser.add_argument("-p", "--chkpoint", action="store_true", dest="checkpoint", help="Save a Checkpoint", default=False)
   args = parser.parse_args(args=copyargs)
   return args


### MAIN ###

# Parse options and init variables
options = parseOptions(sys.argv[1:])
gwType = options.gwType # edit against GATEWAY_TYPES
gwObject = options.gwObject


# Get path of the script
currDir = os.path.abspath(os.path.dirname(sys.argv[0]))

# Load the environment configuration file
envConfigJSON = loadEnvConfig(currDir, options.env)
envConfigJSON["variables"]["env"] = envConfigJSON["environment"]

# Load the DP Domain Objects
dpDomainObjects = loadDomainObjConfig(currDir, envConfigJSON["variables"])

# Export object
if options.action == 'x':
   exportObject(envConfigJSON, dpDomainObjects, gwType, gwObject)
   exit()

# Import object
gwComponents = options.gwComponents
if 'all' in options.gwComponents:
   gwComponents = 'certs,files,objects'

if options.action == 'i':
   importObject(envConfigJSON, dpDomainObjects, gwType, gwObject, gwComponents)

# Create checkpoint
if options.action == 'c':
   createCheckpoint(envConfigJSON)
