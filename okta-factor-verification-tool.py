#!/usr/bin/env python3

_AUTH_ = 'RWG' # 04AUG2023

'''
Purpose: Verify user MFA factors to prevent social engineering attacks.
'''

try:
    from PyQt5.QtWidgets import *
    from PyQt5.QtCore import *
    from PyQt5.QtGui import *
    import requests
    import json
    import time
    import sys
    import os
except Exception as e:
    import sys
    print("[!] Library error: {0}".format(e))
    sys.exit(1)

class Window(QWidget):
     
    def __init__(self,parent=None):
        #
        super().__init__(parent)
        #
        self.next   = True  # Sentinel value for the pagination function
        #
        QMainWindow.__init__(self)
        QWidget.__init__(self)
        QLabel.__init__(self)
        #
        self.setWindowTitle('Okta Factor Verification Tool')
        self.setGeometry(550,100,1050,750)
        self.setStyleSheet("background-color: #403c39; border: 2px black solid")
        #
        self.domain_field = QLineEdit()                                          
        self.domain_field.setPlaceholderText("(Domain)")
        self.domain_field.setStyleSheet("height: 35px; background-color: grey; color: black; border: 2px solid #fc5e03; border-radius: 10px; font-style: bold; font-size: 16px; font-family: Arial")
        self.domain_field.setAlignment(Qt.AlignCenter)
        #
        self.api_key_field = QLineEdit()                                          
        self.api_key_field.setPlaceholderText("(Okta Administrator API Key)")
        self.api_key_field.setStyleSheet("height: 35px; background-color: grey; color: black; border: 2px solid #fc5e03; border-radius: 10px; font-style: bold; font-size: 16px; font-family: Arial")
        self.api_key_field.setAlignment(Qt.AlignCenter)
        #
        self.api_key_field = QLineEdit()                                          
        self.api_key_field.setPlaceholderText("(Okta Administrator API Key)")
        self.api_key_field.setStyleSheet("height: 35px; background-color: grey; color: black; border: 2px solid #fc5e03; border-radius: 10px; font-style: bold; font-size: 16px; font-family: Arial")
        self.api_key_field.setAlignment(Qt.AlignCenter)
        #
        self.user_query = QLineEdit()                                          
        self.user_query.setPlaceholderText("(Search Users)")
        self.user_query.setStyleSheet("height: 35px; background-color: grey; color: black; border: 2px solid #fc5e03; border-radius: 10px; font-style: bold; font-size: 16px; font-family: Arial")
        self.user_query.setAlignment(Qt.AlignCenter)
        self.user_query.textChanged.connect(self.QueryUsers)
        #
        self.populate = QPushButton("Populate Users", self)
        self.populate.setGeometry(100,100,600,400)
        self.populate.setStyleSheet("""
                                       QPushButton {
                                                     height: 35px; 
                                                     background-color: grey; 
                                                     color: black; 
                                                     border: 2px solid #fc5e03; 
                                                     border-radius: 10px; 
                                                     font-style: bold; 
                                                     font-size: 18px; 
                                                     font-family: Arial
                                                    }
                                       QPushButton:hover {
                                                            color: #fc5e03;
                                                            background-color: black;
                                                         }
                                       """)
        #
        self.select_user = QPushButton("Select User", self)
        self.select_user.setGeometry(100,100,600,400)
        self.select_user.setStyleSheet("""
                                       QPushButton {
                                                     height: 35px; 
                                                     background-color: grey; 
                                                     color: black; 
                                                     border: 2px solid #fc5e03; 
                                                     border-radius: 10px; 
                                                     font-style: bold; 
                                                     font-size: 18px; 
                                                     font-family: Arial
                                                    }
                                       QPushButton:hover {
                                                            color: #fc5e03;
                                                            background-color: black;
                                                         }
                                       """)
        #
        self.factor_combo_box  = QComboBox()
        self.factor_combo_box.setStyleSheet("height: 35px; width: 35px; background-color: grey; color: black; border: 2px solid #fc5e03; border-radius: 5px; font-style: bold; font-size: 18px; font-family: Arial")
        self.factor_combo_box.setCurrentIndex(0)
        #
        self.transmit = QPushButton("Send Verification", self)
        self.transmit.setGeometry(100,100,600,400)
        self.transmit.setStyleSheet("""
                                       QPushButton {
                                                     height: 35px; 
                                                     background-color: grey; 
                                                     color: black; 
                                                     border: 2px solid #fc5e03; 
                                                     border-radius: 10px; 
                                                     font-style: bold; 
                                                     font-size: 18px; 
                                                     font-family: Arial
                                                    }
                                       QPushButton:hover {
                                                            color: #fc5e03;
                                                            background-color: black;
                                                         }
                                       """)
        #
        self.token_field = QLineEdit()                                          
        self.token_field.setPlaceholderText("(Token Validation Factor - Current Value)")
        self.token_field.setStyleSheet("height: 35px; max-width: 500px; background-color: grey; color: black; border: 2px solid #fc5e03; border-radius: 10px; font-style: bold; font-size: 16px; font-family: Arial")
        self.token_field.setAlignment(Qt.AlignCenter)
        #
        self.check_token = QPushButton("Validate Token", self)
        self.check_token.setGeometry(100,100,600,400)
        self.check_token.setStyleSheet("""
                                       QPushButton {
                                                     height: 35px; 
                                                     background-color: grey; 
                                                     color: black; 
                                                     border: 2px solid #fc5e03; 
                                                     border-radius: 10px; 
                                                     font-style: bold; 
                                                     font-size: 18px; 
                                                     font-family: Arial
                                                    }
                                       QPushButton:hover {
                                                            color: #fc5e03;
                                                            background-color: black;
                                                         }
                                       """)
        #
        self.output_window = QPlainTextEdit("")
        self.output_window.setStyleSheet("height: 10px; width: 200px; background-color: black; color: #fc5e03;; border: 2px solid #fc5e03; border-radius: 10px; font-style: bold; font-size: 18px; font-family: Arial")
        self.output_window.resize(100,100)
        self.output_window.ensureCursorVisible()
        self.output_window.insertPlainText("""
Requirements:
____________
-> Okta API Token with Administrative Context
-> The subject domain for MFA factor validation
-> Authorization to conduct MFA factor validation tests
-> Genuine necessity regarding Okta user MFA factor validation tests
-> Network connectivity
                                           
^^^ Embed your credentials in the form fields and get started
\n""")
        #
        self.clear_terminal = QPushButton("Clear Terminal", self)
        self.clear_terminal.setGeometry(100,100,600,400)
        self.clear_terminal.setStyleSheet("""
                                       QPushButton {
                                                     height: 35px; 
                                                     background-color: grey; 
                                                     color: black; 
                                                     border: 2px solid #fc5e03; 
                                                     border-radius: 10px; 
                                                     font-style: bold; 
                                                     font-size: 18px; 
                                                     font-family: Arial
                                                    }
                                       QPushButton:hover {
                                                            color: #fc5e03;
                                                            background-color: black;
                                                         }
                                       """)
        #
        self.tableWidget = QTableWidget()
        self.tableWidget.setStyleSheet("background-color: black; color: #fc5e03; border: 2px groove #fc5e03; border-radius: 2px; font-style: bold; font-size: 16px; font-family: Arial")
        self.tableWidget.verticalHeader().setVisible(False)
        self.tableWidget.horizontalHeader().setVisible(False)
        self.tableWidget.horizontalHeader().setStretchLastSection(True)
        self.tableWidget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tableWidget.setColumnCount(3)
        self.tableWidget.setRowCount(1)
        self.tableWidget.setItem(0,0,QTableWidgetItem("User Name"))
        self.tableWidget.setItem(0,1,QTableWidgetItem("Account Status"))
        self.tableWidget.setItem(0,2,QTableWidgetItem("Email Address"))
        #
        self.populate.clicked.connect(self.EmbedAndTestParameters)
        self.select_user.clicked.connect(self.ListFactors)
        self.transmit.clicked.connect(self.SendFactorVerification)
        self.check_token.clicked.connect(self.ValidateToken)
        self.clear_terminal.clicked.connect(self.ClearTerminal)
        #
        main_layout       = QVBoxLayout()
        form_hbox_layout  = QHBoxLayout()
        form_left_layout  = QVBoxLayout()
        form_right_layout = QVBoxLayout()
        vbox_controls     = QVBoxLayout()
        hbox_controls_r1  = QHBoxLayout()
        hbox_controls_r2  = QHBoxLayout()
        vbox_terminal     = QVBoxLayout()
        #
        form_left_layout.addWidget(self.domain_field)
        form_left_layout.addWidget(self.api_key_field)
        form_left_layout.addWidget(self.populate)
        form_left_layout.addWidget(self.user_query)
        form_right_layout.addWidget(self.tableWidget)
        form_hbox_layout.addLayout(form_left_layout)
        form_hbox_layout.addLayout(form_right_layout)
        #
        hbox_controls_r1.addWidget(self.select_user)
        hbox_controls_r1.addWidget(self.factor_combo_box)
        hbox_controls_r1.addWidget(self.transmit)
        #
        hbox_controls_r2.addWidget(self.token_field)
        hbox_controls_r2.addWidget(self.check_token)
        #
        vbox_controls.addLayout(hbox_controls_r1,0)
        vbox_controls.addLayout(hbox_controls_r2,0)
        #
        vbox_terminal.addWidget(self.output_window)
        vbox_terminal.addWidget(self.clear_terminal)
        #
        main_layout.addLayout(form_hbox_layout,1)
        main_layout.addLayout(vbox_controls,1)
        main_layout.addLayout(vbox_terminal,1)
        self.setLayout(main_layout)

    def ClearTerminal(self):
        # Clear the output window
        self.output_window.clear()

    def QueryUsers(self,input):
        '''
        Input   -> User supplied query
        Process -> Traverse the PyQT table items searching for a matching entry
        Output  -> If a match is found, set the current table widget cell to the result
        '''
        matched_values = self.tableWidget.findItems(input, Qt.MatchContains)
        if(matched_values):
            self.current_user =  matched_values[0]
            self.tableWidget.setCurrentItem(self.current_user)

    def ValidateToken(self):
        '''
        Input   -> User provided token
        Process -> Send the token to the corresponding verification URL
        Output  -> Result of the token validation transmission
        '''
        current_index  = self.factor_combo_box.currentIndex() 
        current_token  = {"passCode":self.token_field.text()}
        payload        = json.dumps(current_token)
        current_factor = self.current_factors[current_index]['type']
        current_link   = self.current_factors[current_index]['link']
        self.output_window.insertPlainText("Attempting validation of {0} \n".format(current_factor))
        req            = requests.post(headers=self.headers,data=payload,url=current_link,timeout=5)
        if(req.status_code == 200):
            self.output_window.insertPlainText("Valid token issued for {0}. \n".format(self.current_user.text()))
        else:
            self.output_window.insertPlainText("Token validation failed for {0}. \n".format(self.current_user.text()))

    def ListFactors(self):
        '''
        Input   -> Current PyQT.Table selected user
        Process -> Query the user specific API endpoint for available MFA factors
        Output  -> PyQT.Combobox populated with user specific MFA factors
        '''
        self.current_factors = []
        self.output_window.clear()
        self.factor_combo_box.clear()
        selected_user    = self.current_user.text()
        self.user_id     = ''
        self.user_name   = ''
        self.user_email  = ''
        self.user_status = ''
        for entry in self.employees_refined:
            for item in entry.keys():
                if(entry[item] == selected_user):
                    self.user_id     = entry['ID']
                    self.user_name   = entry['name']
                    self.user_email  = entry['email']
                    self.user_status = entry['status']
        if(self.user_id != ''):
            self.output_window.insertPlainText("Selected: {0} \n".format(self.user_name))
            url                  = "https://{0}.okta.com/api/v1/users/{1}/factors".format(self.domain,self.user_id)
            req                  = requests.get(headers=self.headers,url=url,timeout=5)
            data                 = req.json()
            for entry in data:
                if('verify' in entry['_links']):
                    self.current_factors.append({'type':entry['factorType'],'link':entry['_links']['verify']['href']})   
            for entry in self.current_factors:
                factor_type = entry['type']
                self.factor_combo_box.addItem(factor_type)
        else:
            self.output_window.insertPlainText("Failed to identify an account associated with the selection \n")

    def SendFactorVerification(self):
        '''
        Input   -> MFA factor selected in the combination box
        Process -> Send a POST request to the factor specific verification endpoing
                   Poll the status endpoint via the CheckFactorVerification subroutine 
        Output  -> Write the verification result to the output window
        '''
        current_index  = self.factor_combo_box.currentIndex()
        current_factor = self.current_factors[current_index]['type']
        current_link   = self.current_factors[current_index]['link']
        self.output_window.insertPlainText("Sending: {0} to {1} \n".format(current_factor,self.current_user))
        req            = requests.post(headers=self.headers,url=current_link,timeout=5)
        if(req.status_code == 201):
            self.output_window.insertPlainText("Validation action successful for: {0} \n".format(current_factor))
            data = req.json()
            transaction = data['_links']['poll']['href']
            self.CheckFactorVerification(transaction)
        else:
            self.output_window.insertPlainText("Validation action failed for: {0} \n".format(current_factor))
            time.sleep(1)
            self.output_window.clear()
            return

    def CheckFactorVerification(self,url):
        '''
        Input   -> Transaction URL
        Process -> Poll the transaction URL until a result is returned
        Output  -> Verification transaction status
        '''
        self.output_window.clear()
        req      = requests.get(headers=self.headers,url=url,timeout=5)
        result   = req.json()['factorResult']
        while(result == "WAITING"):
            req      = requests.get(headers=self.headers,url=url,timeout=5)
            result   = req.json()['factorResult']
            self.output_window.insertPlainText("Status: {0} \n".format(result))
            time.sleep(5)
            self.output_window.clear()
        self.output_window.insertPlainText("Factor validation result for: {0} \n".format(result))

    def EmbedAndTestParameters(self):
        '''
        -> Input  : Domain and API text field inputs
        -> Process: 
            -> Instantiate key and domain variable values
            -> Test key, domain, and headers with a single API call        
        -> Output : 
            -> API Key, Domain, and Header values
            -> Parameter validation feedback in the UI
        '''
        self.output_window.clear()
        try:
            self.key     = self.api_key_field.text()
            self.domain  = self.domain_field.text()
            self.headers = {
                            "Content-Type": "application/json",
                            "Authorization": "SSWS {0}".format(self.key)
                           }
            url       = "https://{0}.okta.com/api/v1/users?limit=200".format(self.domain)
            req       = requests.get(headers=self.headers,url=url)
            if(req.status_code == 200):
                self.output_window.insertPlainText("Valid credentials. Populating user data... \n")
                self.CollectAllUsers()
                for employee in self.employees_refined:
                    current_row = self.tableWidget.rowCount()
                    self.tableWidget.setRowCount(current_row+1)
                    col_index   = 0
                    cell_value  = QTableWidgetItem(employee['name'])
                    cell_value.setForeground(QBrush(QColor('#fc5e03')))
                    self.tableWidget.setItem(current_row,col_index,cell_value)
                    col_index   = 1
                    cell_value  = QTableWidgetItem(employee['status'])
                    cell_value.setForeground(QBrush(QColor('#fc5e03')))
                    self.tableWidget.setItem(current_row,col_index,cell_value)
                    col_index   = 2
                    cell_value  = QTableWidgetItem(employee['email'])
                    cell_value.setForeground(QBrush(QColor('#fc5e03')))
                    self.tableWidget.setItem(current_row,col_index,cell_value)
                    self.tableWidget.update()
            else:
                sys.exit(1)
        except Exception as e:
            self.output_window.insertPlainText("Exception raised: {0} \n".format(e))
        finally:
            self.output_window.clear() 

    def ParseHeaders(self,headers):
        '''
        ***
        This function supports pagination.
        Instead of using an integer index, the Okta API returns the link
        for the next API call in the headers of the current call.
        ***
        -> Input   : Headers returned from an API call
        -> Process : 
            -> Parse headers
            -> Identify the 'next' value with the corresponding link
            -> Return link for the next API call
            -> Return False is the link is not located
        -> Output  : link variable is returned with URL value ; link is otherwise False
        '''
        link     = False
        for entry in headers.keys():
            if(entry == 'link' and ("next" in headers[entry])):
                link = headers[entry]
                link = link.split(',')[1]
                link = link.split(';')[0]
                link = link.lstrip(' <')
                link = link.rstrip('>')
                return link
            if(entry == 'link' and ("next" not in headers[entry]) and (self.next == False)):
                link = headers[entry]
                link = link.split(';')[0]
                link = link.lstrip(' <')
                link = link.rstrip('>')
                self.next = True
                return link
        return link

    def CollectAllUsers(self):
        '''
        -> Input   :
            -> API Key
            -> Domain Value
            -> Headers
        -> Process :
            -> API call to the users endpoint
            -> If the first call is successful, subsequent calls are made via pagination
        -> Output  :
            -> List of user dictionaries with employee data
        '''
        url                      = "https://{0}.okta.com/api/v1/users?limit=200".format(self.domain)
        req                      = requests.get(headers=self.headers,url=url)
        status                   = req.status_code
        next_url                 = self.ParseHeaders(req.headers)
        employees                = []
        self.employees_refined   = [] 
        try:
            if(status == 200):
                content = req.json()
                for entry in content:
                    id              = entry['id']
                    status          = entry['status']
                    created         = entry['created']
                    activated       = entry['activated']
                    changed         = entry['statusChanged']
                    lastLogin       = entry['lastLogin']
                    lastUpdated     = entry['lastUpdated']
                    passwordChanged = entry['passwordChanged']

                    employeeDictionary = {
                                            "ID": id,
                                            "Status": status,
                                            "Created": created,
                                            "Activated": activated,
                                            "Status Changed": changed,
                                            "Last Login": lastLogin,
                                            "Last Updated": lastUpdated,
                                            "Password Changed": passwordChanged
                                            }
                    for item in entry['profile'].keys():
                        employeeDictionary[item] = entry['profile'][item]
                    employeeDictionary['Credentials'] = entry['credentials']
                    employeeDictionary['Links']       = entry['_links']
                    employees.append(employeeDictionary)
                while(next_url):
                    url       = "https://{0}.okta.com/api/v1/users?limit=200".format(self.domain)
                    req       = requests.get(headers=self.headers,url=next_url)
                    status    = req.status_code
                    next_url  = self.ParseHeaders(req.headers)
                    content   = req.json()
                    for entry in content:
                        id              = entry['id']
                        status          = entry['status']
                        created         = entry['created']
                        activated       = entry['activated']
                        changed         = entry['statusChanged']
                        lastLogin       = entry['lastLogin']
                        lastUpdated     = entry['lastUpdated']
                        passwordChanged = entry['passwordChanged']

                        employeeDictionary = {
                                                "ID": id,
                                                "Status": status,
                                                "Created": created,
                                                "Activated": activated,
                                                "Status Changed": changed,
                                                "Last Login": lastLogin,
                                                "Last Updated": lastUpdated,
                                                "Password Changed": passwordChanged
                                            }
                        
                        for item in entry['profile'].keys():
                            employeeDictionary[item] = entry['profile'][item]
                        employeeDictionary['Credentials'] = entry['credentials']
                        employeeDictionary['Links']       = entry['_links']
                        employees.append(employeeDictionary)
            else:
                sys.exit(1)
        except Exception as e:
            pass
        for employee in employees:
            emp_name = employee['firstName']+' '+employee['lastName']
            temp_dict = {'ID':employee['ID'],'name':emp_name,'status':employee['Status'],'email':employee['email']}
            self.employees_refined.append(temp_dict)
            
if(__name__ == '__main__'):
    app = QApplication(sys.argv)
    screen = Window()
    screen.show()
    sys.exit(app.exec_())