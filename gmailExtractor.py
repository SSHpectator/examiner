import hashlib
import requests
import base64

import os.path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


from dotenv import load_dotenv
import os

load_dotenv()
apiKey = os.getenv('virusTotal_Key')

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

class GMAIL_EXTRACTOR:
    def sayHello(self):
        print("\nWelcome to Gmail File Analyzer,\ndeveloped by SSHPECTATOR")
    
    def initVars(self):
        self.mail = object
        self.mailbox = ""
        self.resp = None
        self.messages = []
        self.res = None
        self.msg_data = []
        self.file = ""
        self.hash = ""
    
    def getLogin(self):
        print("\nUse your GMAIL login details to login")
        creds = None
        if os.path.exists("token.json"):
            creds = Credentials.from_authorized_user_file("token.json", SCOPES)
        
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
                creds = flow.run_local_server(port=0)
            with open("token.json", "w") as token:
                token.write(creds.to_json())

        try:
            service = build("gmail", "v1", credentials=creds)
            return service 
        except HttpError as error:
            print(f"An error occurred: {error}")
            return None
    
    # def attemptLogin(self):
    #     self.mail = imaplib.IMAP4_SSL("imap.gmail.com", 993)
    #     if self.mail.login(self.usr, self.pwd):
    #         print("\nLogin Successful")
    #     else:
    #         print("\nLogin Failed")
    #         return False
    
    def getSHA256(self, file):
        h = hashlib.sha256()

        with open(file, 'rb') as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                h.update(chunk)
        
        self.hash= h.hexdigest()
        return h.hexdigest()
    
    def getSHA256_from_bytes(self, data):
        h = hashlib.sha256()
        h.update(data)
        self.hash = h.hexdigest()
        return self.hash
    
    def useVirusTotal(self, hash):
        url = "https://www.virustotal.com/api/v3/files/{}".format(hash)
        headers = {
            "accept": "application/json",
            "x-apikey": apiKey
        }

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()

            try:
                verdict = data['data']['attributes'].get('threat_verdict', "VERDICT_UNKOWN")
                return verdict
            except KeyError:
                stats = data['data']['attributes']['last_analysis_stats']
                if stats['malicious'] > 0:
                    return "MALICIOUS"
                return "VERDICT_UNDECTED"
        elif response.status_code == 404:
            return "FILE_NOT_FOUND"
        else:
            return "ERROR"

    def getPDF(self,service):
        try:
            results = service.users().messages().list(userId="me", 
                                                      q="is:unread has:attachment filename:pdf",
                                                      labelIds=['INBOX']
                                                      ).execute()
            self.messages = results.get('messages', [])

            if not self.messages:
                print("\n[!] No messages with PDF attachements to analyze [!]")
                return
            
            for msg in self.messages:
                self.msg_data = service.users().messages().get(userId="me", id=msg['id']).execute()
                payload = self.msg_data.get('payload', {})

                self._processParts(service, msg['id'], payload.get('parts', []))

        except Exception as e:
            print("ERROR: {}".format(e))

    """Support function to treat multipart emails"""
    def _processParts(self, service, message_id, parts):
        for part in parts:
            filename = part.get('filename')

            if filename and filename.lower().endswith('.pdf'):
                att_id = part['body'].get('attachmentId')
                attachment = service.users().messages().attachments().get(
                    userId='me', messageId=message_id, id=att_id
                ).execute()

                file_data = base64.urlsafe_b64decode(attachment['data'].encode('UTF-8'))
                print("\n[*] Analyzing file: {} [*]".format(filename))
                sha = self.getSHA256_from_bytes(file_data)
                print(f"[!] SHA256: {sha}")
                
                verdict = self.useVirusTotal(sha)
                print(f"[RESULTS] {verdict}")

            if 'parts' in part:
                self._processParts(service, message_id, part['parts'])


