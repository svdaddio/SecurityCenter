class SecurityCenter:

    # initialization method
	# Object should be initialized with IP or Hostname of SC Server
	# i.e. my_server = SecurityCenter.SecurityCenter('192.168.1.2)
    def __init__(self, server):
        self._server = server  # type: str
        self._token = "None"  # type: str
        self._cookie = "None"  # type: str
        self._json = __import__('json')
        self._sys = __import__('sys')
        self._urllib3 = __import__('urllib3')

    # Method to check for authentication token
    def authenticated(self):
        if self._token == '':
            return False
        else:
            return True

    # Method to login to SC Server
	# This is designed to use a hard coded account if no credentials are provided
	# It can be called with username and PW like this:
	# my_server.login('User1', 'MyP@55w0rd')
    def login(self, username='', password=''):
        # Sets password to App account if no Creds recieved
        if username == '':
            username = 'API'
        if password == '':
            try:
                import base64
            except ImportError or ImportWarning:
                print("unable to import base64")
                sys.exit(1)
            password = base64.b64decode('<base64 Encoded Default Password>').decode("utf-8")

        # Creates variable with info for token request
        auth = {'username': username, 'password': password}
        # Token request via internal connect method
        response = self.connect('POST', 'token', auth)  # type: dict

        # Extract token from response
        self._token = response['response']['token']

    # Method to send API Requests to SC
    # Receives HTTP Method, API Resource, and form data
	# This provides the core functionality and can be used to call any SC API method
	# my_server.connect('GET', 'scan')
	# my_server.connect('POST', 'analysis', '{"type": "vuln", "query": {"12345"}}' )
    def connect(self, method, resource, data=None):
        https = self._urllib3.PoolManager()
        self._urllib3.disable_warnings()
        # Sets up HTTP Header
        head = {
            'Content-Type': 'application/json',
        }

        if self._token is not None:
            head['X-SecurityCenter'] = self._token

        if self._cookie is not None:
            head['Cookie'] = self._cookie

        # Sets up request URL
        url = "https://{0}/rest/{1}".format(self._server, resource)

        # Makes request including Headers if authenticated, otherwise headers are not included
        try:
            if self._cookie != "None":
                if method == 'POST':
                    r = https.urlopen(method, url, headers=head, body=data)
                else:
                    r = https.request(method, url, headers=head, fields=data)
            else:
                r = https.request(method, url, fields=data)
                rcookie = r.headers.get('set-cookie')
		cookie1, cookie2 = map(str, rcookie, split(“,”))
		self._cookie = cookie2.lstrip()
        except:
                return "Failed to parse request to a command"

        # Tries to parse JSON response
        try:
            contents = self._json.loads(r.data.decode('utf-8'))
        except ValueError as e:
            return None

        # Returns the JSON response if the command completed successfully
        if contents['error_code'] != 0:
            print(contents['error_msg'])
            self._sys.exit(1)
        return contents

    # Method to run the query method of the Security Center API.
	# This method is used to return vulnerability data
    # Returns a JSON dictionary of vulnerabilities and metadata
    # Takes a correctly formated filter as input.
	# Steps I use to create filters:
	# 1. Create desired query in Security Center GUI
	# 2. Use queries = my_server.connect('GET', 'query')
	# 3. Find the query you created in step 1 in the output of step 2 and note the id.
	# 4. queries = my_server.connect('GET', 'query/id')
	# 5. filter = queries[response][filter]
	# 6. my_server.query(filter, "iplist")
	# Valid tools:
	# sumip, sumclassa, sumclassb, sumclassc, sumport, sumprotocol, sumid, sumseverity, 
	# sumfamily, listvuln, vulndetails, listwebclients, listwebservers, listos, iplist, 
	# listmailclients, listservices, listsshservers, sumasset, vulnipsummary, vulnipdetail, 
	# sumcve, summsbulletin, sumiavm, listsoftware, sumdnsname, cveipdetail, iavmipdetail, 
	# sumcce, cceipdetail, sumremediation, sumuserresponsibility, popcount, trend
    def query(self, query_filters, tool):
        # Creates query string
        qry = {"query": {"name": "", "description": "", "context": "analysis", "status": -1, "createdTime": 0,
                         "modifiedTime": 0, "groups": [], "tags": "", "type": "vuln", "tool": tool,
                         "sourceType": "cumulative", "startOffset": 0, "endOffset": 999, "filters": query_filters,
                         "vulnTool": "vulndetails"}, "sourceType": "cumulative", "type": "vuln", "sortDir": "ASC",
               "sortField": "pluginID"}
        # formats query as JSON
        qry = self._json.dumps(qry)
        # Uses connect method to make query request to Security Center
        q_data = self.connect('POST', 'analysis', qry)
        # Returns JSON formated results of query.
        if q_data is None:
            print("The query returned no results.")
            print("The filter may be incorrect. Check the filter config and try again.")
            self._sys.exit(1)
        else:
            return q_data

    # Logs out of Security Center
    def logout(self):
        close = self.connect('DELETE', 'token')
        return close
