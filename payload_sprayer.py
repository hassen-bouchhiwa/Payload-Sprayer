import array
from burp import IBurpExtender, IMessageEditorController, ITab, IContextMenuFactory, IParameter
from java.awt import GridBagLayout, GridBagConstraints, Insets, Color, Font, Dimension, BorderLayout, FontMetrics
from java.awt.image import BufferedImage
from javax.swing import JTabbedPane, JTable, ListSelectionModel,JPopupMenu, JMenuItem, SwingUtilities, Box, JTextArea, JMenuItem, JFrame, JPanel, JButton, JLabel, JTextField, JSplitPane, SwingConstants, JCheckBox, JScrollPane, BorderFactory, BoxLayout, JComboBox
from java.util import ArrayList
from java.awt.event import ActionListener, MouseAdapter
from javax.swing.event import ListSelectionListener
from java.net import URL
from urlparse import urlparse
import javax.swing.JFileChooser as JFileChooser
from javax.swing.table import AbstractTableModel
import threading
import json
import base64
import difflib
import os
import shutil
import subprocess
import time
import sys
import urllib
 
class BurpExtender(IBurpExtender, IMessageEditorController, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Payload Sprayer")
        self.requests = []
        self.clean_directory()

        self.config = self.load_config()

        self.ui_manager = UIManager()
        try:
            (
                self.top_panel, 
                self.payload_input, 
                self.wordlist_input, 
                self.level_input, 
                self.timeout, 
                self.risk_input, 
                self.dalfox_options_input, 
                self.tplmap_options_input, 
                self.url_encode_single, 
                self.url_encode_wordlist, 
                self.rate_limit_single_input, 
                self.rate_limit_wordlist_input, 
                self.dalfox_timeout_input, 
                self.tplmap_timeout_input, 
                self.tplmap_level_input, 
                self.commix_options_input, 
                self.commix_level_input, 
                self.commix_timeout_input, 
                self.custom_payload_input, 
                self.url_encode_custom, 
                self.rate_limit_custom_input, 
                self.chatgpt_assist_single, 
                self.chatgpt_assist_wordlist, 
                self.chatgpt_assist_custom
            ) = self.ui_manager.create_top_panel(
                self.launch_single_payload, 
                self.launch_wordlist_payload, 
                self.launch_sqlmap, 
                self.launch_dalfox_action, 
                self.launch_tplmap_action, 
                self.launch_commix_action, 
                self.launch_custom_payload
            )
        except ValueError as e:
            print("Error during UI initialization:", str(e))

        self.main_tab = JPanel(BorderLayout())
        self.tabbed_pane = JTabbedPane()

        self.main_tab = JPanel(BorderLayout())
        self.tabbed_pane = JTabbedPane()

        self.tool_panel = JPanel()
        self.tool_panel.setLayout(BoxLayout(self.tool_panel, BoxLayout.Y_AXIS))

        self.tool_panel.add(self.top_panel)

        self.tabbed_pane.addTab("Tool", JScrollPane(self.tool_panel))

        self.tabbed_pane.addTab("Config Tab", self.create_file_subtab())

        self.main_tab.add(self.tabbed_pane, BorderLayout.CENTER)

        callbacks.customizeUiComponent(self.main_tab)
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)

    def create_file_subtab(self):
        file_tab_panel = JPanel(BorderLayout())
        file_path = "./config.json"
        config_editor_panel = self.create_file_editor_panel(file_path)
        file_tab_panel.add(config_editor_panel, BorderLayout.CENTER)

        return file_tab_panel

    def create_file_editor_panel(self, file_path):
        panel = JPanel(BorderLayout())

        text_area = JTextArea(20, 50)
        scroll_pane = JScrollPane(text_area)

        try:
            with open(file_path, 'r') as file:
                text_area.setText(file.read())
        except Exception as e:
            text_area.setText("Error loading file")

        save_button = JButton("Save", actionPerformed=lambda event: self.save_file_content(file_path, text_area))

        panel.add(scroll_pane, BorderLayout.CENTER)
        panel.add(save_button, BorderLayout.SOUTH)

        return panel

    def save_file_content(self,file_path, text_area):
        try:
            with open(file_path, 'w') as file:
                file.write(text_area.getText())
            print("Saved content to " + file_path)
        except Exception as e:
            print(str(e))

    def load_config(self):
        try:
            with open('config.json', 'r') as f:
                return json.load(f)
        except Exception as e:
            print(str(e))
            return {}

    def getTabCaption(self):
        return "Sprayer"

    def getUiComponent(self):
        return self.main_tab

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Send with Params", actionPerformed=lambda event: self.add_request(invocation, "params")))
        menu_list.add(JMenuItem("Send with Headers", actionPerformed=lambda event: self.add_request(invocation, "headers")))
        menu_list.add(JMenuItem("Send with Endpoint", actionPerformed=lambda event: self.add_request(invocation, "endpoint")))
        return menu_list

    def add_request(self, invocation, mode):
        request = invocation.getSelectedMessages()[0]
        request_info = self._helpers.analyzeRequest(request)
        request_obj = Request(request, request_info, self._callbacks, self._helpers, mode)
        
        if not self.is_request_already_added(request_info):
            self.requests.append(request_obj)
            request_panel = RequestPanel(request_obj, self.tool_panel, self)
            self.tool_panel.add(request_panel)
            self.tool_panel.revalidate()
            self.tool_panel.repaint()

    def is_request_already_added(self, new_request_info):
        new_url = new_request_info.getUrl()
        new_method = new_request_info.getMethod()
        new_params = set(param.getName() for param in new_request_info.getParameters())

        for existing_request in self.requests:
            existing_info = existing_request.request_info
            if Utils.is_same_request(existing_info, new_url, new_method, new_params):
                return True
        return False

    def clean_directory(self):
        try:
            directory = "/tmp/burp_requests"
            if os.path.exists(directory):
                shutil.rmtree(directory)
                os.makedirs(directory)
            else:
                os.makedirs(directory)
        except Exception as e:
            print("Error cleaning directory:", str(e))

    def save_request_file(self, request, param):
        try:
            request_info = self._helpers.analyzeRequest(request)
            headers = request_info.getHeaders()
            body_offset = request_info.getBodyOffset()
            body_bytes = request.getRequest()[body_offset:]
            body = self._helpers.bytesToString(body_bytes)

            request_string = "\n".join(headers) + "\n\n" + body
            directory = "/tmp/burp_requests"
            url = request_info.getUrl()
            param_name = param.getName() if isinstance(param, IParameter) else param[0] if isinstance(param, tuple) else param
            file_path = os.path.join(directory, url.getPath().replace("/", "_") + param_name + ".txt")

            with open(file_path, 'w') as file:
                file.write(request_string)
        except Exception as e:
            print("Error saving request file:", str(e))

        return file_path

    def launch_single_payload(self, payload, rate_limit):
        try:
            rate_limit = int(rate_limit) if rate_limit.isdigit() else 0
            if self.url_encode_single.isSelected():
                payload = urllib.quote(payload)
            self.ui_manager.create_single_payload_frame(
                payload, 
                self.requests, 
                self._callbacks, 
                self._helpers, 
                rate_limit, 
                self.chatgpt_assist_single  
            )
        except Exception as e:                    
            print("Error launching single payload:", str(e))

    def launch_wordlist_payload(self, wordlist_path, rate_limit):
        try:
            rate_limit = int(rate_limit) if rate_limit.isdigit() else 0
            with open(wordlist_path, 'r') as file:
                payloads = [urllib.quote(payload.strip()) if self.url_encode_wordlist.isSelected() else payload.strip() for payload in file.readlines()]
            self.ui_manager.create_wordlist_payload_frame(
                payloads, 
                self.requests, 
                self._callbacks, 
                self._helpers, 
                rate_limit, 
                self.chatgpt_assist_wordlist  
            )
        except Exception as e:
            print("Error launching wordlist payload:", str(e))

    def launch_custom_payload(self, payload, url_encode, rate_limit):
        rate_limit = int(rate_limit) if rate_limit.isdigit() else 0
        self.ui_manager.create_custom_payload_frame(
            payload, 
            self.requests, 
            self._callbacks, 
            self._helpers, 
            url_encode, 
            rate_limit, 
            self.chatgpt_assist_custom  
        )

    def launch_sqlmap(self, level, timeout, risk, options):
        try:
            self.ui_manager.create_sqlmap_frame(level, timeout, risk, options, self.requests, self._callbacks, self._helpers, self, self.config)
        except Exception as e:
            print("Error launching SQLMap:", str(e))

    def launch_dalfox_action(self, options, timeout):
        try:
            self.ui_manager.create_dalfox_frame(options, timeout, self.requests, self._callbacks, self._helpers, self, self.config)
        except Exception as e:
            print("Error launching Dalfox:", str(e))

    def launch_tplmap_action(self, options, level, timeout):
        try:
            self.ui_manager.create_tplmap_frame(options, level, timeout, self.requests, self._callbacks, self._helpers, self, self.config)
        except Exception as e:
            print("Error launching Tplmap:", str(e))

    def launch_commix_action(self, options, level, timeout):
        try:
            self.ui_manager.create_commix_frame(options, level, timeout, self.requests, self._callbacks, self._helpers, self, self.config)
        except Exception as e:
            print("Error launching Commix:", str(e))

class Request:
    def __init__(self, request, request_info, callbacks, helpers, mode):
        self.request = request
        self.request_info = request_info
        self.testing_params = []
        self.testing_headers = []
        self.testing_endpoints = []
        self.headers = []
        self.endpoints = []
        self._callbacks = callbacks
        self._helpers = helpers  
        self.response = None
        self.response_info = None
        self.status_code, self.body_str = "000", "<></>"
        self.mode = mode
        self.extract_testing_parts()
        threading.Thread(target=self.make_request).start()

    def extract_testing_parts(self):
        try:
            if self.mode == "params":
                self.params = self.request_info.getParameters()
            elif self.mode == "headers":
                headers = self.request_info.getHeaders()
                for header in headers[1:]:
                    if not header.lower().startswith("cookie"):
                        if ": " in header:
                            name, value = header.split(": ", 1)
                        else:
                            name, value = header, ""
                        self.headers.append((name, value))
            elif self.mode == "endpoint":
                path_segments = self.request_info.getUrl().getPath().split('/')
                self.endpoints = [segment for segment in path_segments if segment]
        except Exception as e:
            print("Error extracting testing parts:", str(e))

    def make_request(self):
        try:
            httpService = self.request.getHttpService()
            self.response = self._callbacks.makeHttpRequest(httpService, self.request.getRequest())
            if self.response:
                response_bytes = self.response.getResponse()
                if response_bytes:
                    self.status_code, self.body_str = self.analyze_response(response_bytes)
                else:
                    self.status_code, self.body_str = "No Response", "<No response body>"
            else:
                self.status_code, self.body_str = "No Response", "<No response from server>"
        except Exception as e:
            print("Error making request:", str(e))

    def analyze_response(self, response_bytes):
        try:
            if response_bytes is None or len(response_bytes) == 0:
                return "000", "<Empty Response>"
            
            response_info = self._helpers.analyzeResponse(response_bytes)
            headers = response_info.getHeaders()

            if headers is None or len(headers) == 0:
                return "000", "<Missing Headers>"

            body_offset = response_info.getBodyOffset()
            body_bytes = response_bytes[body_offset:]
            status_line = headers[0]

            if status_line:
                status_code = status_line.split()[1]
            else:
                status_code = "000"

            body_str = self._helpers.bytesToString(body_bytes)
            return status_code, body_str

        except IndexError:
            print("Malformed response: Missing status line or headers.")
            return "000", "<Malformed Response>"
        except Exception as e:
            print("Error analyzing response: " + str(e))
            return "000", "<Error Processing Response>"
 
class LaunchedRequest:
    def __init__(self, request, param, payload, callbacks, helpers, mode, chatGPT):
        self.original_request = request
        self.request_bytes = self.original_request.request.getRequest()[:]
        self.param = param
        self.payload = payload
        self._callbacks = callbacks
        self._helpers = helpers
        self.mode = mode
        self.chatGPT = chatGPT
        self.panel = None
        self.response = None
        self.response_info = None
        self.diff = '--'
        self.status_code, self.body_str, self.response_time = "--", "<></>", "--"
        self.unusual_headers, self.unusual_content, self.find_result = "--", "--", "--"
        self.modified_request_bytes = None 
        threading.Thread(target=self.modify_and_send_request).start()

    def set_panel(self, panel):
        self.panel = panel

    def modify_and_send_request(self):
        try:
            new_request_bytes = self.modify_request()
            self.modified_request_bytes = new_request_bytes 
            httpService = self.original_request.request.getHttpService()
            start_time = time.time()
            self.response = self._callbacks.makeHttpRequest(httpService, new_request_bytes)
            end_time = time.time()
            self.response_time = end_time - start_time
            response_bytes = self.response.getResponse()
            if self.response:
                response_bytes = self.response.getResponse()
                if response_bytes:
                    self.status_code, self.body_str = self.analyze_response(response_bytes)
                else:
                    self.status_code, self.body_str = "No Response", "<No response body>"
            else:
                self.status_code, self.body_str = "No Response", "<No response from server>"
        except Exception as e:
            print("Error modifying and sending request:", str(e))
        
        if self.response and self.response.getResponse():
            response_bytes = self.response.getResponse()
            self.response_info = self._helpers.analyzeResponse(response_bytes)
            self.status_code, self.body_str = self.analyze_response(response_bytes)
        else:
            self.response_info = None
            self.status_code, self.body_str = "No Response", "<No response from server>"

        if self.panel:
            self.diff = Utils.compare_response_bodies(self.body_str, self.original_request.body_str)
            self.unusual_headers = Utils.check_unsual_header(self.original_request.response_info.getHeaders(), self.response_info.getHeaders())
            if self.chatGPT:
                self.unusual_content = Utils.check_unusual_content(self.body_str)
            print(self.status_code, self.diff, self.response_time, self.unusual_headers, self.unusual_content)
            self.panel.update_panel(self.status_code, self.diff, self.response_time, self.unusual_headers, self.unusual_content)

    def modify_request(self):
        try:
            new_request_bytes = self.request_bytes[:]
            self.request_info = self._helpers.analyzeRequest(self.original_request.request)
            body_offset = self.request_info.getBodyOffset()
            request_body_bytes = new_request_bytes[body_offset:]
            self.request_body_str = self._helpers.bytesToString(request_body_bytes)
        except Exception as e:
            print("Error modifying request:", str(e))

        try:
            request_body_json = json.loads(self.request_body_str)
            is_json = True
        except Exception:
            is_json = False

        if is_json:
            new_request_bytes = self.modify_json_request(new_request_bytes, request_body_json, body_offset)
        else:
            new_request_bytes = self.modify_non_json_request(new_request_bytes)

        return self.update_content_length(new_request_bytes)

    def modify_json_request(self, new_request_bytes, request_body_json, body_offset):
        try:
            if self.param.getName() in request_body_json:
                original_value = request_body_json[self.param.getName()]
                try:
                    if isinstance(original_value, int):
                        self.payload = int(self.payload)
                    elif isinstance(original_value, float):
                        self.payload = float(self.payload)
                    elif isinstance(original_value, bool):
                        self.payload = self.payload.lower() in ['true', '1', 'yes']
                except ValueError:
                    pass  

                request_body_json[self.param.getName()] = self.payload
                new_request_body_str = json.dumps(request_body_json)
                new_request_bytes = new_request_bytes[:body_offset] + self._helpers.stringToBytes(new_request_body_str)
                self.request_info = self._helpers.analyzeRequest(new_request_bytes)
                body_offset = self.request_info.getBodyOffset()
                new_request_body_bytes = new_request_bytes[body_offset:]
                self.request_body_str = self._helpers.bytesToString(new_request_body_bytes)
            else:
                new_request_bytes = self.modify_parameters(new_request_bytes)
        except Exception as e:
            print("Error modifying JSON request:", str(e))
        return new_request_bytes

    def modify_non_json_request(self, new_request_bytes):
        try:
            if self.mode == "headers":
                new_request_bytes = self.modify_headers(new_request_bytes)
            elif self.mode == "endpoint":
                new_request_bytes = self.modify_endpoints(new_request_bytes)
            else:  
                new_request_bytes = self.modify_parameters(new_request_bytes)

            self.request_info = self._helpers.analyzeRequest(new_request_bytes)
            body_offset = self.request_info.getBodyOffset()
            new_request_body_bytes = new_request_bytes[body_offset:]
            self.request_body_str = self._helpers.bytesToString(new_request_body_bytes)
        except Exception as e:
            print("Error modifying non-JSON request:", str(e))
        return new_request_bytes

    def modify_parameters(self, new_request_bytes):
        try:
            for parameter in self.request_info.getParameters():
                if parameter.getName() == self.param.getName() and parameter.getType() == self.param.getType():
                    new_request_bytes = self._helpers.removeParameter(new_request_bytes, parameter)
                    new_param = self._helpers.buildParameter(self.param.getName(), self.payload, parameter.getType())
                    new_request_bytes = self._helpers.addParameter(new_request_bytes, new_param)
                    self.request_info = self._helpers.analyzeRequest(new_request_bytes)
                    body_offset = self.request_info.getBodyOffset()
                    new_request_body_bytes = new_request_bytes[body_offset:]
                    self.request_body_str = self._helpers.bytesToString(new_request_body_bytes)
        except Exception as e:
            print("Error modifying parameters:", str(e))
        return new_request_bytes

    def modify_headers(self, new_request_bytes):
        try:
            headers = self.request_info.getHeaders()
            new_headers = []
            for header in headers:
                if header.lower().startswith(self.param[0].lower() + ":"):
                    new_headers.append(self.param[0] + ": " + self.payload)
                else:
                    new_headers.append(header)
            return self._helpers.buildHttpMessage(new_headers, new_request_bytes[self.request_info.getBodyOffset():])
        except Exception as e:
            print("Error modifying headers:", str(e))
            return new_request_bytes

    def modify_endpoints(self, new_request_bytes):
        try:
            url = urlparse(self.request_info.getUrl().toString())
            path_segments = url.path.split('/')
            new_path = "/".join([self.payload if segment == self.param else segment for segment in path_segments])
            new_url = url.scheme + "://" + url.netloc + new_path

            initial_request_bytes = self._helpers.buildHttpRequest(URL(new_url))
            initial_request_str = self._helpers.bytesToString(initial_request_bytes)
            initial_request_headers = initial_request_str.split("\r\n\r\n", 1)[0]
            initial_new_request_info = self._helpers.analyzeRequest(self._helpers.stringToBytes(initial_request_headers))
            new_headers = initial_new_request_info.getHeaders()

            for i in range(len(new_headers)):
                if new_headers[i].lower().startswith("host:"):
                    new_headers[i] = "Host: " + url.netloc

            new_request_bytes = self._helpers.buildHttpMessage(new_headers, new_request_bytes[self.request_info.getBodyOffset():])
            self.request_info = self._helpers.analyzeRequest(new_request_bytes)
        except Exception as e:
            print("Error modifying endpoints:", str(e))
        return new_request_bytes

    def update_content_length(self, new_request_bytes):
        try:
            self.request_info = self._helpers.analyzeRequest(new_request_bytes)
            body_offset = self.request_info.getBodyOffset()
            new_request_body_bytes = new_request_bytes[body_offset:]
            content_length = len(new_request_body_bytes)

            headers = self.request_info.getHeaders()
            new_headers = [header for header in headers if not header.lower().startswith("content-length:")]
            new_headers.append("Content-Length: " + str(content_length))

            return self._helpers.buildHttpMessage(new_headers, new_request_body_bytes)
        except Exception as e:
            print("Error updating content length:", str(e))
            return new_request_bytes

    def analyze_response(self, response_bytes):
        try:
            if response_bytes is None or len(response_bytes) == 0:
                return "No Response", "<Empty Response>"

            try:
                response_info = self._helpers.analyzeResponse(response_bytes)
                headers = response_info.getHeaders()

                if headers is None or len(headers) == 0:
                    return "No Response", "<Missing Headers>"

                body_offset = response_info.getBodyOffset()
                body_bytes = response_bytes[body_offset:]
                status_line = headers[0]

                if status_line:
                    status_code = status_line.split()[1]
                else:
                    status_code = "No Status Code"

                body_str = self._helpers.bytesToString(body_bytes)
                return status_code, body_str
            except Exception as e:
                return "Error", str(e)
        except Exception as e:
            print("Error analyzing response:", str(e))
            return "000", "<></>"

class UIManager:
    @staticmethod
    def create_top_panel(launch_single_payload_action, launch_wordlist_payload_action, launch_sqlmap_action, launch_dalfox_action, launch_tplmap_action, launch_commix_action, launch_custom_payload_action):
        top_panel = JPanel(GridBagLayout())
        constraints = GridBagConstraints()
        constraints.insets = Insets(10, 10, 10, 10)
             
        payload_input, url_encode_single, rate_limit_single_input, chatgpt_assist_single = UIManager.add_payload_components(
            top_panel, constraints, 0, launch_single_payload_action)
        
        wordlist_input, url_encode_wordlist, rate_limit_wordlist_input, chatgpt_assist_wordlist = UIManager.add_wordlist_components(
            top_panel, constraints, 1, launch_wordlist_payload_action)

        custom_payload_input, url_encode_custom, rate_limit_custom_input, chatgpt_assist_custom = UIManager.add_custom_payload_components(
            top_panel, constraints, 2, launch_custom_payload_action)

        sqlmap_options_input, level_input, risk_input, timeout_input = UIManager.add_sqlmap_components(
            top_panel, constraints, 3, launch_sqlmap_action)
        
        dalfox_options_input, dalfox_timeout_input = UIManager.add_dalfox_components(
            top_panel, constraints, 5, launch_dalfox_action)

        tplmap_options_input, tplmap_level_input, tplmap_timeout_input = UIManager.add_tplmap_components(
            top_panel, constraints, 7, launch_tplmap_action)

        commix_options_input, commix_level_input, commix_timeout_input = UIManager.add_commix_components(
            top_panel, constraints, 9, launch_commix_action)
        
        return (top_panel, payload_input, wordlist_input, level_input, timeout_input, risk_input, dalfox_options_input,
                tplmap_options_input, url_encode_single, url_encode_wordlist, rate_limit_single_input, rate_limit_wordlist_input,
                dalfox_timeout_input, tplmap_timeout_input, tplmap_level_input, commix_options_input, commix_level_input, commix_timeout_input,
                custom_payload_input, url_encode_custom, rate_limit_custom_input, chatgpt_assist_single, chatgpt_assist_wordlist, chatgpt_assist_custom)

    @staticmethod
    def add_payload_components(panel, constraints, row, action):
        constraints.gridx = 0
        constraints.gridy = row
        panel.add(JLabel("Single Payload:", SwingConstants.RIGHT), constraints)
        
        payload_input = JTextField(20)
        constraints.gridx = 1
        panel.add(payload_input, constraints)
        
        url_encode_single = JCheckBox("URL Encode")
        constraints.gridx = 2
        panel.add(url_encode_single, constraints)
        
        chatgpt_assist_single = JCheckBox("ChatGPT Assistance")
        constraints.gridx = 3
        panel.add(chatgpt_assist_single, constraints)
        
        constraints.gridx = 4
        panel.add(JLabel("Rate Limit (ms):", SwingConstants.RIGHT), constraints)
        
        rate_limit_single_input = JTextField(5)
        constraints.gridx = 5
        panel.add(rate_limit_single_input, constraints)
        
        launch_button = JButton("Launch", actionPerformed=lambda event: action(payload_input.getText(), rate_limit_single_input.getText()))
        launch_button.setBackground(Color(255, 87, 34))
        launch_button.setForeground(Color.WHITE)
        launch_button.setFont(Font(launch_button.getFont().getName(), Font.BOLD, launch_button.getFont().getSize()))
        constraints.gridx = 6
        panel.add(launch_button, constraints)
        
        return payload_input, url_encode_single, rate_limit_single_input, chatgpt_assist_single

    @staticmethod
    def add_wordlist_components(panel, constraints, row, action):
        constraints.gridx = 0
        constraints.gridy = row
        panel.add(JLabel("Wordlist Payload:", SwingConstants.RIGHT), constraints)
        
        wordlist_input = JTextField(20)
        constraints.gridx = 1
        panel.add(wordlist_input, constraints)
        
        url_encode_wordlist = JCheckBox("URL Encode")
        constraints.gridx = 2
        panel.add(url_encode_wordlist, constraints)
        
        chatgpt_assist_wordlist = JCheckBox("ChatGPT Assistance")
        constraints.gridx = 3
        panel.add(chatgpt_assist_wordlist, constraints)
        
        constraints.gridx = 4
        panel.add(JLabel("Rate Limit (ms):", SwingConstants.RIGHT), constraints)

        rate_limit_wordlist_input = JTextField(5)
        constraints.gridx = 5
        panel.add(rate_limit_wordlist_input, constraints)

        browse_button = JButton("Browse", actionPerformed=lambda event: UIManager.browse_file(wordlist_input))
        constraints.gridx = 6
        panel.add(browse_button, constraints)
        
        wordlist_launch_button = JButton("Launch Wordlist", actionPerformed=lambda event: action(wordlist_input.getText(), rate_limit_wordlist_input.getText()))
        wordlist_launch_button.setBackground(Color(255, 87, 34))
        wordlist_launch_button.setForeground(Color.WHITE)
        wordlist_launch_button.setFont(Font(wordlist_launch_button.getFont().getName(), Font.BOLD, wordlist_launch_button.getFont().getSize()))
        constraints.gridx = 7
        panel.add(wordlist_launch_button, constraints)
        
        return wordlist_input, url_encode_wordlist, rate_limit_wordlist_input, chatgpt_assist_wordlist

    @staticmethod
    def add_custom_payload_components(panel, constraints, row, action):
        constraints.gridx = 0
        constraints.gridy = row
        panel.add(JLabel("Custom Payload:", SwingConstants.RIGHT), constraints)
        
        custom_payload_input = JTextField(20)
        constraints.gridx = 1
        panel.add(custom_payload_input, constraints)
        
        url_encode_custom = JCheckBox("URL Encode")
        constraints.gridx = 2
        panel.add(url_encode_custom, constraints)
        
        chatgpt_assist_custom = JCheckBox("ChatGPT Assistance")
        constraints.gridx = 3
        panel.add(chatgpt_assist_custom, constraints)
        
        constraints.gridx = 4
        panel.add(JLabel("Rate Limit (ms):", SwingConstants.RIGHT), constraints)
        
        rate_limit_custom_input = JTextField(5)
        constraints.gridx = 5
        panel.add(rate_limit_custom_input, constraints)
        
        custom_launch_button = JButton("Launch", actionPerformed=lambda event: action(custom_payload_input.getText(), url_encode_custom.isSelected(), rate_limit_custom_input.getText()))
        custom_launch_button.setBackground(Color(255, 87, 34))
        custom_launch_button.setForeground(Color.WHITE)
        custom_launch_button.setFont(Font(custom_launch_button.getFont().getName(), Font.BOLD, custom_launch_button.getFont().getSize()))
        constraints.gridx = 6
        panel.add(custom_launch_button, constraints)
        
        return custom_payload_input, url_encode_custom, rate_limit_custom_input, chatgpt_assist_custom

    @staticmethod
    def add_sqlmap_components(panel, constraints, row, action):
        constraints.gridx = 0
        constraints.gridy = row
        panel.add(JLabel("SQLMap Options:", SwingConstants.RIGHT), constraints)
        sqlmap_options_input = JTextField(20)
        constraints.gridx = 1
        panel.add(sqlmap_options_input, constraints)
        constraints.gridx = 2
        panel.add(JLabel("SQLMap Level:", SwingConstants.RIGHT), constraints)
        level_input = JTextField(5)
        constraints.gridx = 3
        panel.add(level_input, constraints)
        constraints.gridx = 4
        panel.add(JLabel("SQLMap Risk:", SwingConstants.RIGHT), constraints)
        risk_input = JTextField(5)
        constraints.gridx = 5
        panel.add(risk_input, constraints)
        constraints.gridx = 6
        panel.add(JLabel("Command Timeout:", SwingConstants.RIGHT), constraints)
        timeout_input = JTextField(5)
        constraints.gridx = 7
        panel.add(timeout_input, constraints)
        sqlmap_launch_button = JButton("Launch SQLMap", actionPerformed=lambda event: action(level_input.getText(), timeout_input.getText(), risk_input.getText(), sqlmap_options_input.getText()))
        sqlmap_launch_button.setBackground(Color(255, 87, 34))
        sqlmap_launch_button.setForeground(Color.WHITE)
        sqlmap_launch_button.setFont(Font(sqlmap_launch_button.getFont().getName(), Font.BOLD, sqlmap_launch_button.getFont().getSize()))
        constraints.gridx = 8
        constraints.gridy = row
        constraints.gridheight = 2
        panel.add(sqlmap_launch_button, constraints)
        return sqlmap_options_input, level_input, risk_input, timeout_input

    @staticmethod
    def add_dalfox_components(panel, constraints, row, action):
        constraints.gridx = 0
        constraints.gridy = row
        panel.add(JLabel("Dalfox Options:", SwingConstants.RIGHT), constraints)
        dalfox_options_input = JTextField(20)
        constraints.gridx = 1
        panel.add(dalfox_options_input, constraints)
        constraints.gridx = 2
        panel.add(JLabel("Command Timeout:", SwingConstants.RIGHT), constraints)
        dalfox_timeout_input = JTextField(5)
        constraints.gridx = 3
        panel.add(dalfox_timeout_input, constraints)
        dalfox_launch_button = JButton("Launch Dalfox", actionPerformed=lambda event: action(dalfox_options_input.getText(), dalfox_timeout_input.getText()))
        dalfox_launch_button.setBackground(Color(255, 87, 34))
        dalfox_launch_button.setForeground(Color.WHITE)
        dalfox_launch_button.setFont(Font(dalfox_launch_button.getFont().getName(), Font.BOLD, dalfox_launch_button.getFont().getSize()))
        constraints.gridx = 4
        panel.add(dalfox_launch_button, constraints)
        return dalfox_options_input, dalfox_timeout_input

    @staticmethod
    def add_tplmap_components(panel, constraints, row, action):
        constraints.gridx = 0
        constraints.gridy = row
        panel.add(JLabel("Tplmap Options:", SwingConstants.RIGHT), constraints)
        tplmap_options_input = JTextField(20)
        constraints.gridx = 1
        panel.add(tplmap_options_input, constraints)
        constraints.gridx = 2
        panel.add(JLabel("Tplmap Level:", SwingConstants.RIGHT), constraints)
        tplmap_level_input = JTextField(5)
        constraints.gridx = 3
        panel.add(tplmap_level_input, constraints)
        constraints.gridx = 4
        panel.add(JLabel("Command Timeout:", SwingConstants.RIGHT), constraints)
        tplmap_timeout_input = JTextField(5)
        constraints.gridx = 5
        panel.add(tplmap_timeout_input, constraints)
        tplmap_launch_button = JButton("Launch Tplmap", actionPerformed=lambda event: action(tplmap_options_input.getText(), tplmap_level_input.getText(), tplmap_timeout_input.getText()))
        tplmap_launch_button.setBackground(Color(255, 87, 34))
        tplmap_launch_button.setForeground(Color.WHITE)
        tplmap_launch_button.setFont(Font(tplmap_launch_button.getFont().getName(), Font.BOLD, tplmap_launch_button.getFont().getSize()))
        constraints.gridx = 6
        panel.add(tplmap_launch_button, constraints)
        return tplmap_options_input, tplmap_level_input, tplmap_timeout_input

    @staticmethod
    def add_commix_components(panel, constraints, row, action):
        constraints.gridx = 0
        constraints.gridy = row
        panel.add(JLabel("Commix Options:", SwingConstants.RIGHT), constraints)
        commix_options_input = JTextField(20)
        constraints.gridx = 1
        panel.add(commix_options_input, constraints)
        constraints.gridx = 2
        panel.add(JLabel("Commix Level:", SwingConstants.RIGHT), constraints)
        commix_level_input = JTextField(5)
        constraints.gridx = 3
        panel.add(commix_level_input, constraints)
        constraints.gridx = 4
        panel.add(JLabel("Command Timeout:", SwingConstants.RIGHT), constraints)
        commix_timeout_input = JTextField(5)
        constraints.gridx = 5
        panel.add(commix_timeout_input, constraints)
        commix_launch_button = JButton("Launch Commix", actionPerformed=lambda event: action(commix_options_input.getText(), commix_level_input.getText(), commix_timeout_input.getText()))
        commix_launch_button.setBackground(Color(255, 87, 34))
        commix_launch_button.setForeground(Color.WHITE)
        commix_launch_button.setFont(Font(commix_launch_button.getFont().getName(), Font.BOLD, commix_launch_button.getFont().getSize()))
        constraints.gridx = 6
        panel.add(commix_launch_button, constraints)
        return commix_options_input, commix_level_input, commix_timeout_input

    @staticmethod
    def browse_file(wordlist_input):
        file_chooser = JFileChooser()
        ret = file_chooser.showOpenDialog(None)
        if ret == JFileChooser.APPROVE_OPTION:
            file_path = file_chooser.getSelectedFile().getAbsolutePath()
            wordlist_input.setText(file_path)

    @staticmethod
    def create_sort_panel(launched_request_table, table_model, update_panel_callback):
        sort_panel = JPanel(GridBagLayout())
        constraints = GridBagConstraints()
        constraints.insets = Insets(10, 10, 10, 10)
        constraints.gridx = 0
        constraints.gridy = 0
        sort_panel.add(JLabel("Sort by:", SwingConstants.RIGHT), constraints)
        sort_options = ["diff", "status_code", "response_time", "unusual_headers", "unusual_content"]
        sort_combobox = JComboBox(sort_options)
        constraints.gridx = 1
        sort_panel.add(sort_combobox, constraints)
        sort_button = JButton("Sort", actionPerformed=lambda event: UIManager.sort_launched_requests(table_model, sort_combobox.getSelectedItem(), update_panel_callback))
        constraints.gridx = 2
        sort_panel.add(sort_button, constraints)
        return sort_panel

    @staticmethod
    def sort_launched_requests(table_model, sort_key, update_panel_callback):
        table_model.launched_requests.sort(key=lambda request: getattr(request, sort_key, ""))
        table_model.fireTableDataChanged()  
        update_panel_callback()  

    @staticmethod
    def create_find_panel(launched_request_table, table_model):
        find_panel = JPanel(GridBagLayout())
        constraints = GridBagConstraints()
        constraints.insets = Insets(10, 10, 10, 10)
        constraints.gridx = 0
        constraints.gridy = 0
        find_panel.add(JLabel("Pattern:", SwingConstants.RIGHT), constraints)
        find_input = JTextField(20)
        constraints.gridx = 1
        find_panel.add(find_input, constraints)
        find_button = JButton("Find", actionPerformed=lambda event: UIManager.find_function(find_input.getText(), table_model.launched_requests, table_model))
        constraints.gridx = 2
        find_panel.add(find_button, constraints)
        return find_panel

    @staticmethod
    def find_function(find, launched_requests, table_model):
        for launched_request in launched_requests:
            if find.lower() in launched_request.body_str.lower():
                launched_request.find_result = "Found!"
            else:
                launched_request.find_result = "--"
        table_model.fireTableDataChanged()

    @staticmethod
    def update_main_panel(main_panel, launched_request_panels):
        main_panel.removeAll()
        for panel in launched_request_panels:
            main_panel.add(panel)
        main_panel.revalidate()
        main_panel.repaint()

    @staticmethod
    def create_single_payload_frame(payload, requests, callbacks, helpers, rate_limit , chatgpt_checkbox):
        frame = JFrame("Single Payload")
        frame.setSize(1150, 800)
        frame.setLayout(BorderLayout())
        
        launched_requests = []  
        launched_request_panels = []  

        table_model = LaunchedRequestTableModel(launched_requests)
        launched_request_table = JTable(table_model)
        launched_request_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)

        
        launched_request_table.addMouseListener(TableMouseAdapter(launched_request_table, launched_requests))

        
        table_container_panel = JPanel(BorderLayout())
        table_container_panel.add(JScrollPane(launched_request_table), BorderLayout.CENTER)
        table_container_panel.setPreferredSize(Dimension(1000, 300))
        
        top_panel = JPanel()
        top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
        top_panel.setPreferredSize(Dimension(1000, 50))
        
        
        
        find_panel = UIManager.create_find_panel(launched_request_table, table_model)
        sort_panel = UIManager.create_sort_panel(launched_request_table, table_model, lambda: None)

        request_text_area = JTextArea('Request', 20, 600)
        response_text_area = JTextArea('Response', 20, 600)
        bottom_panel = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, JScrollPane(request_text_area), JScrollPane(response_text_area))
        bottom_panel.setDividerLocation(0.5)
        bottom_panel.setResizeWeight(0.5)
        
        top_panel.add(find_panel)
        top_panel.add(sort_panel)

        request_panels_container = JPanel()
        request_panels_container.setLayout(BoxLayout(request_panels_container, BoxLayout.Y_AXIS))
        
        main_panel = JPanel()
        main_panel.setLayout(BoxLayout(main_panel, BoxLayout.Y_AXIS))
        main_panel.setPreferredSize(Dimension(1000, 450))
        main_panel.add(top_panel)
        main_panel.add(table_container_panel)
        
        frame.add(main_panel, BorderLayout.NORTH)
        frame.add(bottom_panel, BorderLayout.CENTER)
        frame.setVisible(True)

        def process_requests():
            for request in requests:
                for param in (request.testing_params if request.mode == "params" else
                            request.testing_headers if request.mode == "headers" else
                            request.testing_endpoints):
                    
                    launched_request = LaunchedRequest(request, param, payload, callbacks, helpers, request.mode, chatgpt_checkbox.isSelected())
                    
                    launched_request_panel = LaunchedRequestPanel(launched_request, request_text_area, response_text_area)
                    
                    launched_request.set_panel(launched_request_panel)
                    
                    launched_requests.append(launched_request)
                    
                    launched_request_panels.append(launched_request_panel)
                    
                    table_model.fireTableRowsInserted(len(launched_requests) - 1, len(launched_requests) - 1)
                    
                    SwingUtilities.invokeLater(lambda: request_panels_container.add(launched_request_panel))
                    SwingUtilities.invokeLater(lambda: request_panels_container.revalidate())
                    SwingUtilities.invokeLater(lambda: request_panels_container.repaint())
                    
                    if rate_limit > 0:
                        time.sleep(rate_limit / 1000.0)

        threading.Thread(target=process_requests).start()

        def on_row_selected(event):
            if not event.getValueIsAdjusting():
                selected_row = launched_request_table.getSelectedRow()
                if selected_row != -1:
                    launched_request = launched_requests[selected_row]
                    
                    temp_panel = LaunchedRequestPanel(launched_request, request_text_area, response_text_area)
                    
                    formatted_request = temp_panel.format_http_request(launched_request.request_info, launched_request.request_body_str)
                    formatted_response = temp_panel.format_http_response(launched_request.response_info, launched_request.body_str)
                    
                    request_text_area.setText(formatted_request)
                    response_text_area.setText(formatted_response)

        launched_request_table.getSelectionModel().addListSelectionListener(lambda event: on_row_selected(event))

    @staticmethod
    def create_wordlist_payload_frame(payloads, requests, callbacks, helpers, rate_limit, chatgpt_checkbox):
        frame = JFrame("Wordlist Payload")
        frame.setSize(1150, 800)
        frame.setLayout(BorderLayout())

        launched_requests = []
        launched_request_panels = []

        table_model = LaunchedRequestTableModel(launched_requests)
        launched_request_table = JTable(table_model)
        launched_request_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)

        launched_request_table.addMouseListener(TableMouseAdapter(launched_request_table, launched_requests))

        table_container_panel = JPanel(BorderLayout())
        table_container_panel.add(JScrollPane(launched_request_table), BorderLayout.CENTER)
        table_container_panel.setPreferredSize(Dimension(1000, 300))

        top_panel = JPanel()
        top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
        top_panel.setPreferredSize(Dimension(1000, 50))

        find_panel = UIManager.create_find_panel(launched_request_table, table_model)
        sort_panel = UIManager.create_sort_panel(launched_request_table, table_model, lambda: None)

        request_text_area = JTextArea('Request', 20, 600)
        response_text_area = JTextArea('Response', 20, 600)
        bottom_panel = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, JScrollPane(request_text_area), JScrollPane(response_text_area))
        bottom_panel.setDividerLocation(0.5)
        bottom_panel.setResizeWeight(0.5)

        top_panel.add(find_panel)
        top_panel.add(sort_panel)

        request_panels_container = JPanel()
        request_panels_container.setLayout(BoxLayout(request_panels_container, BoxLayout.Y_AXIS))

        
        
        

        main_panel = JPanel()
        main_panel.setLayout(BoxLayout(main_panel, BoxLayout.Y_AXIS))
        main_panel.setPreferredSize(Dimension(1000, 450))
        main_panel.add(top_panel)
        main_panel.add(table_container_panel)

        frame.add(main_panel, BorderLayout.NORTH)
        frame.add(bottom_panel, BorderLayout.CENTER)
        frame.setVisible(True)

        def process_requests():
            for payload in payloads:
                payload = payload.strip()
                for request in requests:
                    for param in (request.testing_params if request.mode == "params" else
                                request.testing_headers if request.mode == "headers" else
                                request.testing_endpoints):
                        
                        
                        launched_request = LaunchedRequest(request, param, payload, callbacks, helpers, request.mode, chatgpt_checkbox.isSelected())
                        
                        
                        launched_request_panel = LaunchedRequestPanel(launched_request, request_text_area, response_text_area)
                        
                        
                        launched_request.set_panel(launched_request_panel)
                        
                        
                        launched_requests.append(launched_request)
                        
                        
                        launched_request_panels.append(launched_request_panel)
                        
                        
                        table_model.fireTableRowsInserted(len(launched_requests) - 1, len(launched_requests) - 1)
                        
                        
                        SwingUtilities.invokeLater(lambda: request_panels_container.add(launched_request_panel))
                        SwingUtilities.invokeLater(lambda: request_panels_container.revalidate())
                        SwingUtilities.invokeLater(lambda: request_panels_container.repaint())
                        
                        
                        if rate_limit > 0:
                            time.sleep(rate_limit / 1000.0)

        
        threading.Thread(target=process_requests).start()

        def on_row_selected(event):
            if not event.getValueIsAdjusting():  
                selected_row = launched_request_table.getSelectedRow()
                if selected_row != -1:
                    launched_request = launched_requests[selected_row]

                    temp_panel = LaunchedRequestPanel(launched_request, request_text_area, response_text_area)

                    formatted_request = temp_panel.format_http_request(launched_request.request_info, launched_request.request_body_str)
                    formatted_response = temp_panel.format_http_response(launched_request.response_info, launched_request.body_str)

                    request_text_area.setText(formatted_request)
                    response_text_area.setText(formatted_response)

        launched_request_table.getSelectionModel().addListSelectionListener(lambda event: on_row_selected(event))

    @staticmethod
    def create_custom_payload_frame(payload, requests, callbacks, helpers, url_encode, rate_limit, chatgpt_checkbox):
        frame = JFrame("Custom Payload")
        frame.setSize(1150, 800)
        frame.setLayout(BorderLayout())

        
        launched_requests = []  
        launched_request_panels = []  

        
        table_model = LaunchedRequestTableModel(launched_requests)
        launched_request_table = JTable(table_model)
        launched_request_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)

        
        launched_request_table.addMouseListener(TableMouseAdapter(launched_request_table, launched_requests))

        
        table_container_panel = JPanel(BorderLayout())
        table_container_panel.add(JScrollPane(launched_request_table), BorderLayout.CENTER)

        
        top_panel = JPanel()
        top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
        top_panel.setPreferredSize(Dimension(1000, 50))

        
        find_panel = UIManager.create_find_panel(launched_request_table, table_model)
        sort_panel = UIManager.create_sort_panel(launched_request_table, table_model, lambda: None)

        request_text_area = JTextArea('Request', 20, 600)
        response_text_area = JTextArea('Response', 20, 600)
        bottom_panel = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, JScrollPane(request_text_area), JScrollPane(response_text_area))
        bottom_panel.setDividerLocation(0.5)
        bottom_panel.setResizeWeight(0.5)

        top_panel.add(find_panel)
        top_panel.add(sort_panel)

        
        request_panels_container = JPanel()
        request_panels_container.setLayout(BoxLayout(request_panels_container, BoxLayout.Y_AXIS))

        
        scrollable_table_container_panel = JScrollPane(table_container_panel)
        scrollable_table_container_panel.setPreferredSize(Dimension(1000, 300))

        main_panel = JPanel()
        main_panel.setLayout(BoxLayout(main_panel, BoxLayout.Y_AXIS))
        main_panel.setPreferredSize(Dimension(1000, 450))
        main_panel.add(top_panel)
        main_panel.add(scrollable_table_container_panel)

        frame.add(main_panel, BorderLayout.NORTH)
        frame.add(bottom_panel, BorderLayout.CENTER)
        frame.setVisible(True)

        def process_requests():
            for request in requests:
                for param in request.testing_params:
                    original_value = param.getValue()
                    modified_payload = payload.replace("ORIGINAL", original_value)
                    if url_encode:
                        modified_payload = urllib.quote(modified_payload)

                    
                    launched_request = LaunchedRequest(request, param, modified_payload, callbacks, helpers, request.mode, chatgpt_checkbox.isSelected())

                    
                    launched_request_panel = LaunchedRequestPanel(launched_request, request_text_area, response_text_area)

                    
                    launched_request.set_panel(launched_request_panel)
                     
                    launched_requests.append(launched_request)

                    
                    launched_request_panels.append(launched_request_panel)

                    
                    table_model.fireTableRowsInserted(len(launched_requests) - 1, len(launched_requests) - 1)

                    if chatgpt_checkbox.isSelected():
                        launched_request.unusual_content = Utils.check_unusual_content(launched_request.body_str)
                    else:
                        launched_request.unusual_content = "--"

                    SwingUtilities.invokeLater(lambda: request_panels_container.add(launched_request_panel))
                    SwingUtilities.invokeLater(lambda: request_panels_container.revalidate())
                    SwingUtilities.invokeLater(lambda: request_panels_container.repaint())

                    if rate_limit > 0:
                        time.sleep(rate_limit / 1000.0)

        
        threading.Thread(target=process_requests).start()

        def on_row_selected(event):
            if not event.getValueIsAdjusting():  
                selected_row = launched_request_table.getSelectedRow()
                if selected_row != -1:
                    launched_request = launched_requests[selected_row]

                    temp_panel = LaunchedRequestPanel(launched_request, request_text_area, response_text_area)

                    formatted_request = temp_panel.format_http_request(launched_request.request_info, launched_request.request_body_str)
                    formatted_response = temp_panel.format_http_response(launched_request.response_info, launched_request.body_str)

                    request_text_area.setText(formatted_request)
                    response_text_area.setText(formatted_response)

        launched_request_table.getSelectionModel().addListSelectionListener(lambda event: on_row_selected(event))

    @staticmethod
    def create_sqlmap_frame(level, timeout, risk, options, requests, callbacks, helpers, burp_extender, config):
        frame = JFrame("SQLMap")
        frame.setSize(550, 800)
        frame.setLayout(BorderLayout())

        launched_requests = []  
        sqlmap_response_area = JTextArea('SQLMap Response', 10, 40)
        bottom_panel = JScrollPane(sqlmap_response_area)

        
        table_model = SQLMapTableModel(launched_requests)
        launched_request_table = JTable(table_model)
        launched_request_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)

        
        launched_request_table.addMouseListener(ToolTableMouseAdapter(launched_request_table, launched_requests))

        
        launched_request_table.getSelectionModel().addListSelectionListener(
            lambda event: on_row_selected(event, launched_request_table, launched_requests, sqlmap_response_area))

        
        table_container_panel = JPanel(BorderLayout())
        table_container_panel.add(JScrollPane(launched_request_table), BorderLayout.CENTER)
        table_container_panel.setPreferredSize(Dimension(550, 300))

        
        main_panel = JPanel()
        main_panel.setLayout(BoxLayout(main_panel, BoxLayout.Y_AXIS))
        main_panel.setPreferredSize(Dimension(550, 300))
        main_panel.add(table_container_panel)

        frame.add(main_panel, BorderLayout.NORTH)
        frame.add(bottom_panel, BorderLayout.CENTER)
        frame.setVisible(True)

        
        for request in requests:
            for param in (request.testing_params if request.mode == "params" else
                        request.testing_headers if request.mode == "headers" else
                        request.testing_endpoints):
                sqlmap_request = SQLMapRequest(request, param, level, timeout, risk, options, callbacks, helpers, burp_extender, config)
                sqlmap_request_panel = SQLMapRequestPanel(sqlmap_request, sqlmap_response_area, sqlmap_response_area)
                sqlmap_request.set_panel(sqlmap_request_panel)
                launched_requests.append(sqlmap_request)
                table_model.fireTableRowsInserted(len(launched_requests) - 1, len(launched_requests) - 1)

        def on_row_selected(event, table, launched_requests, response_area):
            if not event.getValueIsAdjusting():  
                selected_row = table.getSelectedRow()
                if selected_row != -1:
                    launched_request = launched_requests[selected_row]
                    response_area.setText(launched_request.result)

    @staticmethod
    def create_dalfox_frame(options, timeout, requests, callbacks, helpers, burp_extender, config):
        frame = JFrame("Dalfox")
        frame.setSize(550, 800)
        frame.setLayout(BorderLayout())

        
        launched_requests = []  
        launched_request_panels = []  

        
        dalfox_response_area = JTextArea('Dalfox Response', 10, 40)
        bottom_panel = JScrollPane(dalfox_response_area)

        
        table_model = DalfoxTableModel(launched_requests)
        launched_request_table = JTable(table_model)
        launched_request_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)

        
        launched_request_table.addMouseListener(ToolTableMouseAdapter(launched_request_table, launched_requests))

        
        table_container_panel = JPanel(BorderLayout())
        table_container_panel.add(JScrollPane(launched_request_table), BorderLayout.CENTER)
        table_container_panel.setPreferredSize(Dimension(550, 200))

        
        main_panel = JPanel()
        main_panel.setLayout(BoxLayout(main_panel, BoxLayout.Y_AXIS))
        main_panel.setPreferredSize(Dimension(550, 300))
        main_panel.add(table_container_panel)

        frame.add(main_panel, BorderLayout.NORTH)
        frame.add(bottom_panel, BorderLayout.CENTER)
        frame.setVisible(True)

        
        for request in requests:
            for param in request.testing_params:
                
                dalfox_request = DalfoxRequest(request, param, options, timeout, callbacks, helpers, burp_extender, config)

                
                dalfox_request_panel = DalfoxRequestPanel(dalfox_request, dalfox_response_area, dalfox_response_area)

                
                dalfox_request.set_panel(dalfox_request_panel)

                
                launched_requests.append(dalfox_request)

                
                launched_request_panels.append(dalfox_request_panel)

                
                table_model.fireTableRowsInserted(len(launched_requests) - 1, len(launched_requests) - 1)

        def on_row_selected(event):
            if not event.getValueIsAdjusting():  
                selected_row = launched_request_table.getSelectedRow()
                if selected_row != -1:
                    dalfox_request = launched_requests[selected_row]
                    
                    formatted_response = dalfox_request.result
                    dalfox_response_area.setText(formatted_response)

        launched_request_table.getSelectionModel().addListSelectionListener(lambda event: on_row_selected(event))

    @staticmethod
    def create_tplmap_frame(options, level, timeout, requests, callbacks, helpers, burp_extender, config):
        frame = JFrame("Tplmap")
        frame.setSize(550, 800)
        frame.setLayout(BorderLayout())

        
        launched_requests = []  
        launched_request_panels = []  

        
        tplmap_response_area = JTextArea('Tplmap Response', 10, 40)
        bottom_panel = JScrollPane(tplmap_response_area)

        
        table_model = TplmapTableModel(launched_requests)
        launched_request_table = JTable(table_model)
        launched_request_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)

        
        launched_request_table.addMouseListener(ToolTableMouseAdapter(launched_request_table, launched_requests))

        
        table_container_panel = JPanel(BorderLayout())
        table_container_panel.add(JScrollPane(launched_request_table), BorderLayout.CENTER)
        table_container_panel.setPreferredSize(Dimension(550, 300))

        
        main_panel = JPanel()
        main_panel.setLayout(BoxLayout(main_panel, BoxLayout.Y_AXIS))
        main_panel.setPreferredSize(Dimension(550, 300))
        main_panel.add(table_container_panel)

        frame.add(main_panel, BorderLayout.NORTH)
        frame.add(bottom_panel, BorderLayout.CENTER)
        frame.setVisible(True)

        
        for request in requests:
            for param in request.testing_params:
                
                tplmap_request = TplmapRequest(request, param, options, level, timeout, callbacks, helpers, burp_extender, config)

                
                tplmap_request_panel = TplmapRequestPanel(tplmap_request, tplmap_response_area, tplmap_response_area)

                
                tplmap_request.set_panel(tplmap_request_panel)

                
                launched_requests.append(tplmap_request)

                
                launched_request_panels.append(tplmap_request_panel)

                
                table_model.fireTableRowsInserted(len(launched_requests) - 1, len(launched_requests) - 1)

        def on_row_selected(event):
            if not event.getValueIsAdjusting():  
                selected_row = launched_request_table.getSelectedRow()
                if selected_row != -1:
                    tplmap_request = launched_requests[selected_row]
                    
                    
                    formatted_response = tplmap_request.result
                    tplmap_response_area.setText(formatted_response)

        launched_request_table.getSelectionModel().addListSelectionListener(lambda event: on_row_selected(event))

    @staticmethod
    def create_commix_frame(options, level, timeout, requests, callbacks, helpers, burp_extender, config):
        frame = JFrame("Commix")
        frame.setSize(550, 800)
        frame.setLayout(BorderLayout())

        launched_requests = []  
        commix_response_area = JTextArea('Commix Response', 10, 40)
        bottom_panel = JScrollPane(commix_response_area)

        
        table_model = CommixTableModel(launched_requests)
        launched_request_table = JTable(table_model)
        launched_request_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)

        
        launched_request_table.addMouseListener(ToolTableMouseAdapter(launched_request_table, launched_requests))

        
        launched_request_table.getSelectionModel().addListSelectionListener(
            lambda event: on_row_selected(event, launched_request_table, launched_requests, commix_response_area))

        
        table_container_panel = JPanel(BorderLayout())
        table_container_panel.add(JScrollPane(launched_request_table), BorderLayout.CENTER)
        table_container_panel.setPreferredSize(Dimension(550, 300))

        
        main_panel = JPanel()
        main_panel.setLayout(BoxLayout(main_panel, BoxLayout.Y_AXIS))
        main_panel.setPreferredSize(Dimension(550, 300))
        main_panel.add(table_container_panel)

        frame.add(main_panel, BorderLayout.NORTH)
        frame.add(bottom_panel, BorderLayout.CENTER)
        frame.setVisible(True)

        for request in requests:
            for param in (request.testing_params if request.mode == "params" else
                        request.testing_headers if request.mode == "headers" else
                        request.testing_endpoints):
                commix_request = CommixRequest(request, param, options, level, timeout, callbacks, helpers, burp_extender, config)
                commix_request_panel = CommixRequestPanel(commix_request, commix_response_area, commix_response_area)
                commix_request.set_panel(commix_request_panel)
                launched_requests.append(commix_request)
                table_model.fireTableRowsInserted(len(launched_requests) - 1, len(launched_requests) - 1)
                
        def on_row_selected(event, table, launched_requests, response_area):
            if not event.getValueIsAdjusting():  
                selected_row = table.getSelectedRow()
                if selected_row != -1:
                    launched_request = launched_requests[selected_row]
                    response_area.setText(launched_request.result)  
 
class RequestPanel(JPanel):
    def __init__(self, request, parent_panel, burp_extender):
        super(RequestPanel, self).__init__(GridBagLayout())
        self.request = request
        self.parent_panel = parent_panel
        self.burp_extender = burp_extender
        self.setBorder(BorderFactory.createLineBorder(Color(0, 0, 0, 0.1), 2))
        self.add_request_components(request)

    def add_request_components(self, request):
        constraints = GridBagConstraints()
        constraints.insets = Insets(10, 10, 10, 10)
        constraints.anchor = GridBagConstraints.WEST
        constraints.fill = GridBagConstraints.HORIZONTAL
        constraints.weightx = 1

        constraints.gridx = 0
        constraints.gridy = 0
        constraints.gridwidth = 4
        request_label = JLabel(str(request.request.getUrl()))
        request_label.setFont(Font("Dialog", Font.BOLD, 19))
        self.add(request_label, constraints)
        constraints.gridx = 5
        constraints.gridy = 0
        constraints.gridwidth = 1
        constraints.weightx = 0
        constraints.anchor = GridBagConstraints.EAST
        delete_button = JButton("X", actionPerformed=self.delete_request)
        self.add(delete_button, constraints)

        constraints.gridwidth = 1
        constraints.weightx = 0
        constraints.anchor = GridBagConstraints.WEST
        constraints.gridx = 0
        constraints.gridy = 1

        param_type_map = {0: "Get", 1: "Body", 2: "Cookie", 3: "XML", 4: "JSON", 5: "AMF", 6: "Multipart Attribute", 7: "WebSocket"}
        for index, param in enumerate(request.params if request.mode == "params" else
                                      request.headers if request.mode == "headers" else
                                      request.endpoints):
            constraints.gridy = index + 2
            if request.mode == "params":
                param_type = param_type_map.get(param.getType(), "Unknown")
                checkbox_label = param.getName() + " (" + param_type + ")"
            elif request.mode == "headers":
                checkbox_label = param[0] + " (Header)"
            else:
                checkbox_label = param + " (Endpoint)"
            checkbox = JCheckBox(checkbox_label)
            checkbox.setOpaque(False)
            checkbox.addActionListener(CheckboxActionListener(request, param))
            self.add(checkbox, constraints)

    def delete_request(self, event):
        self.parent_panel.remove(self)
        self.parent_panel.revalidate()
        self.parent_panel.repaint()
        self.burp_extender.requests.remove(self.request)

class LaunchedRequestPanel(JPanel):
    def __init__(self, launched_request, request_text_area, response_text_area):
        self.launchedRequest = launched_request
        self.request_text_area = request_text_area
        self.response_text_area = response_text_area
        self.setupUI()
        self.addMouseListener(PanelMouseListener(self))
        self.init_context_menu()

    def setupUI(self):
        self.setLayout(BoxLayout(self, BoxLayout.X_AXIS))
        self.setPreferredSize(Dimension(1100, 30))
        self.setMaximumSize(Dimension(sys.maxint, 30))
        self.setBorder(BorderFactory.createLineBorder(Color(0, 0, 0, 0.1), 2))

        url = urlparse(self.launchedRequest.original_request.request_info.getUrl().toString())
        endpoint = url.path
        method = self.launchedRequest.original_request.request_info.getMethod()
        title = method + " - " + endpoint
        
        self.request_label = JLabel(title)
        self.request_label.setFont(Font("Dialog", Font.BOLD, 18))
        
        param = (self.launchedRequest.param.getName() 
                 if isinstance(self.launchedRequest.param, IParameter) 
                 else self.launchedRequest.param[0] 
                 if isinstance(self.launchedRequest.param, tuple) 
                 else self.launchedRequest.param)
        self.param_label = JLabel(param)
        
        status = str(self.launchedRequest.status_code)
        self.status_label = JLabel(status)
        
        diff = str(self.launchedRequest.diff)+"%"
        self.diff_label = JLabel(diff)
        
        
        try:
            response_time = str(int((self.launchedRequest.response_time * 1000)))+" ms"
        except (TypeError, ValueError):
            response_time = "-- ms"
        self.time_label = JLabel(response_time)
        
        unusual_content = str(self.launchedRequest.unusual_content)
        self.content_label = JLabel(unusual_content)
        
        unusual_headers = str(self.launchedRequest.unusual_headers)
        self.headers_label = JLabel(unusual_headers)
        
        find_result = str(self.launchedRequest.find_result)
        self.find_label = JLabel(find_result)
        
        self.set_label_sizes()
        self.add(self.request_label)
        self.add(Box.createRigidArea(Dimension(25, 0)))
        self.add(self.param_label)
        self.add(Box.createRigidArea(Dimension(25, 0)))
        self.add(self.status_label)
        self.add(Box.createRigidArea(Dimension(25, 0)))
        self.add(self.diff_label)
        self.add(Box.createRigidArea(Dimension(25, 0)))
        self.add(self.time_label)
        self.add(Box.createRigidArea(Dimension(25, 0)))
        self.add(self.content_label)
        self.add(Box.createRigidArea(Dimension(25, 0)))
        self.add(self.headers_label)
        self.add(Box.createRigidArea(Dimension(25, 0)))
        self.add(self.find_label)

    def set_label_sizes(self):
        size = Dimension(175, 30)
        for label in [self.request_label, self.param_label, self.status_label, self.diff_label, self.time_label, self.content_label, self.headers_label, self.find_label]:
            label.setPreferredSize(size)
        self.request_label.setPreferredSize(Dimension(500, 30))

    def update_panel(self, status_code, diff, response_time, unusual_headers, unusual_content):
        def update_components():
            self.status_label.setText(status_code if status_code else "No Response")
            self.diff_label.setText("{}%".format(str(diff)) if diff is not None else "--%")
            response_time_ms = "{} ms".format(int(response_time * 1000)) if response_time is not None else "-- ms"
            self.time_label.setText(response_time_ms)
            self.content_label.setText(unusual_content if unusual_content else "--")
            self.headers_label.setText(unusual_headers if unusual_headers else "--")
            self.revalidate()
            self.repaint()
        SwingUtilities.invokeLater(update_components)

    def update_find(self, result):
        def update_find_panel():
            self.find_label.setText(result)
            self.revalidate()
            self.repaint()
        SwingUtilities.invokeLater(update_find_panel)

    def on_panel_clicked(self):
        formatted_request = self.format_http_request(self.launchedRequest.request_info, self.launchedRequest.request_body_str)
        formatted_response = self.format_http_response(self.launchedRequest.response_info, self.launchedRequest.body_str)
        SwingUtilities.invokeLater(lambda: self.request_text_area.setText(formatted_request))
        SwingUtilities.invokeLater(lambda: self.response_text_area.setText(formatted_response))

    @staticmethod
    def format_http_request(request_info, body):
        headers = "\n".join(request_info.getHeaders())
        return headers + "\n\n" + body

    @staticmethod
    def format_http_response(response_info, body):
        if response_info is None:
            headers = ""
        else:
            headers = "\n".join(response_info.getHeaders())
        return headers + "\n\n" + body

    def get_sort_value(self, sort_key):
        return getattr(self.launchedRequest, sort_key, "")

    def init_context_menu(self):
        self.context_menu = JPopupMenu()
        send_to_repeater_item = JMenuItem("Send to Repeater", actionPerformed=self.send_to_repeater)
        self.context_menu.add(send_to_repeater_item)
        self.addMouseListener(MouseAdapterContextMenu(self))

    def send_to_repeater(self, event):
        request_info = self.launchedRequest.original_request.request_info
        http_service = self.launchedRequest.original_request.request.getHttpService()
        modified_request_bytes = self.launchedRequest.modified_request_bytes
        self.launchedRequest._callbacks.sendToRepeater(http_service.getHost(), http_service.getPort(), http_service.getProtocol == 'https', modified_request_bytes, None)

    def update_panel(self, status_code, diff, response_time, unusual_headers, unusual_content):
        def update_components():
            self.status_label.setText(status_code)
            self.diff_label.setText(str(diff) + "%")
            response_time_ms = str(int(response_time * 1000)) + " ms"
            self.time_label.setText(response_time_ms)
            self.content_label.setText(unusual_content)
            self.headers_label.setText(unusual_headers)
            self.revalidate()
            self.repaint()
        SwingUtilities.invokeLater(update_components)

    def update_find(self, result):
        def update_find_panel():
            self.find_label.setText(result)
            self.revalidate()
            self.repaint()
        SwingUtilities.invokeLater(update_find_panel)

class MouseAdapterContextMenu(MouseAdapter):
    def __init__(self, panel):
        self.panel = panel

    def mousePressed(self, event):
        self.checkForTriggerEvent(event)

    def mouseReleased(self, event):
        self.checkForTriggerEvent(event)

    def checkForTriggerEvent(self, event):
        if event.isPopupTrigger():
            self.panel.context_menu.show(event.getComponent(), event.getX(), event.getY())

class CheckboxActionListener(ActionListener):
    def __init__(self, request, param):
        self.request = request
        self.param = param

    def actionPerformed(self, event):
        checkbox = event.getSource()
        try:
            if checkbox.isSelected():
                if self.param not in (self.request.testing_params if self.request.mode == "params" else
                                      self.request.testing_headers if self.request.mode == "headers" else
                                      self.request.testing_endpoints):
                    (self.request.testing_params if self.request.mode == "params" else
                     self.request.testing_headers if self.request.mode == "headers" else
                     self.request.testing_endpoints).append(self.param)
            else:
                if self.param in (self.request.testing_params if self.request.mode == "params" else
                                  self.request.testing_headers if self.request.mode == "headers" else
                                  self.request.testing_endpoints):
                    (self.request.testing_params if self.request.mode == "params" else
                     self.request.testing_headers if self.request.mode == "headers" else
                     self.request.testing_endpoints).remove(self.param)
        except Exception as e:
            print("Error handling checkbox action:", str(e))

class PanelMouseListener(MouseAdapter):
    def __init__(self, panel):
        self.panel = panel

    def mouseClicked(self, event):
        self.panel.on_panel_clicked()

class HeaderPanel(JPanel):
    def __init__(self):
        super(HeaderPanel, self).__init__()
        self.setLayout(BoxLayout(self, BoxLayout.X_AXIS))
        self.setupUI()

    def setupUI(self):
        self.setPreferredSize(Dimension(1100, 30))
        self.setMaximumSize(Dimension(sys.maxint, 30))
        self.setBorder(BorderFactory.createLineBorder(Color(0, 0, 0, 0.1), 2))

        labels = ["Request", "Parameter", "Status Code", "Difference", "Response Time", "AI Analysis", "Headers Changes", "Find Results"]
        for i, text in enumerate(labels):
            if i:
                text = Utils.fix_string_size(text, 100)
            else:
                text = Utils.fix_string_size(text, 250)
            label = JLabel(text)
            self.add(label)
            if i < len(labels) - 1:
                self.add(Box.createRigidArea(Dimension(25, 0)))
        self.set_label_sizes()

    def set_label_sizes(self):
        size = Dimension(175, 30)
        for label in self.getComponents():
            if isinstance(label, JLabel):
                label.setPreferredSize(size)
        self.getComponent(0).setFont(Font("Dialog", Font.BOLD, 18))
        self.getComponent(0).setPreferredSize(Dimension(500, 30))  

class SQLMapRequest:
    def __init__(self, request, param, level, timeout, risk, options, callbacks, helpers, burp_extender, config):
        self.original_request = request
        self.param = param
        if level == "":
            self.level = 1
        else:
            self.level = level
        self.timeout = timeout
        if risk == "":
            self.risk = 1
        else:
            self.risk = risk
        self.options = options  
        self._callbacks = callbacks
        self._helpers = helpers
        self.burp_extender = burp_extender
        self.panel = None
        self.result = "Not yet"
        self.thread = threading.Thread(target=self.run_sqlmap)
        self.thread.start()
        self.config = config
 
    def set_panel(self, panel):
        self.panel = panel

    def run_sqlmap(self):
        try:
            file_path = self.burp_extender.save_request_file(self.original_request.request, self.param)
            flags = self.get_flags(self.param)
        except Exception as e:
            print("Error getting SQLMap flags:", str(e))

        try:
            if self.original_request.mode == "headers":
                test_param = ' --header="' + self.param[0] + ': *"'
            else:
                test_param = " -p " + self.param.getName()

            command = "timeout " + str(self.timeout) + "s "+ self.config['sqlmap']['command'] + " -r " + file_path + test_param + " --batch --level=" + str(self.level) \
                  + " --risk=" + str(self.risk) + flags + " --flush-session --ignore-stdin " + self.options  
            print("Command:", command)

            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            timer = threading.Timer(1800, process.kill) 
            try:
                timer.start()
                stdout, stderr = process.communicate()
                self.result = stdout
            finally:
                timer.cancel()
        except Exception as e:
            print("Error running SQLMap:", str(e))

        if self.panel:
            self.panel.update_result(self.result, self.param)

    def get_flags(self, param):
        flags = " "
        url = urlparse(self.original_request.request_info.getUrl().toString())
        if url.scheme.lower() == "https":
            flags += " --force-ssl "
        if isinstance(param, IParameter) and Utils.is_base64_encoded(param.getValue()):
            flags += "--base64='" + param.getName() + "' "
        return flags

class SQLMapRequestPanel(JPanel):
    def __init__(self, sqlmap_request, request_text_area, response_text_area):
        self.sqlmap_request = sqlmap_request
        self.request_text_area = request_text_area
        self.response_text_area = response_text_area
        self.setupUI()
        self.addMouseListener(PanelMouseListener(self))

    def setupUI(self):
        self.setLayout(BoxLayout(self, BoxLayout.X_AXIS))
        self.setPreferredSize(Dimension(1100, 30))
        self.setMaximumSize(Dimension(sys.maxint, 30))
        self.setBorder(BorderFactory.createLineBorder(Color(0, 0, 0, 0.1), 2))

        url = urlparse(self.sqlmap_request.original_request.request_info.getUrl().toString())
        endpoint = url.path

        self.request_label = JLabel(endpoint)
        self.request_label.setFont(Font("Dialog", Font.BOLD, 17))
        self.param_label = JLabel(str(self.sqlmap_request.param.getName()) if isinstance(self.sqlmap_request.param, IParameter) else str(self.sqlmap_request.param))
        self.result_label = JLabel("Pending")

        self.set_label_sizes()

        self.add(self.request_label)
        self.add(Box.createRigidArea(Dimension(25, 0)))
        self.add(self.param_label)
        self.add(Box.createRigidArea(Dimension(25, 0)))
        self.add(self.result_label)

    def set_label_sizes(self):
        size = Dimension(175, 30)
        for label in [self.request_label, self.param_label, self.result_label]:
            label.setPreferredSize(size)

    def update_result(self, result, param):
        def update_components():
            vulnerable_string = "'" + (param.getName() if isinstance(param, IParameter) else param) + "'" + " is vulnerable"
            injectable_string = "'" + (param.getName() if isinstance(param, IParameter) else param) + "'" + " might be injectable"
            if vulnerable_string in result or injectable_string in result:
                self.result_label.setText("Vulnerable")
            else:
                self.result_label.setText("Safe")
            self.revalidate()
            self.repaint()
        SwingUtilities.invokeLater(update_components)

    def on_panel_clicked(self):
        SwingUtilities.invokeLater(lambda: self.response_text_area.setText(self.sqlmap_request.result))

class DalfoxRequest:
    def __init__(self, request, param, options, timeout, callbacks, helpers, burp_extender, config):
        self.original_request = request
        self.param = param
        self.options = options
        self._callbacks = callbacks
        self.timeout = timeout
        self._helpers = helpers
        self.burp_extender = burp_extender
        self.panel = None
        self.result = "Not yet"
        self.thread = threading.Thread(target=self.run_dalfox)
        self.thread.start()
        self.config = config
 
    def set_panel(self, panel):
        self.panel = panel

    def run_dalfox(self):
        try:
            request_info = self._helpers.analyzeRequest(self.original_request.request)
            url = str(request_info.getUrl())
            headers = request_info.getHeaders()
            method = request_info.getMethod()
            body_offset = request_info.getBodyOffset()
            body_bytes = self.original_request.request.getRequest()[body_offset:]
            body = self._helpers.bytesToString(body_bytes)
            command = self.construct_dalfox_command(url, method, headers, body, self.param.getName() if isinstance(self.param, IParameter) else self.param, self.options, self.timeout)
            print(command)
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            stdout, stderr = process.communicate()
            self.result = stdout
        except Exception as e:
            self.result = str(e)
        if self.panel:
            print(self.result)
            self.panel.update_result(self.result, self.param)

    def construct_dalfox_command(self, url, method, headers, body, param_name, options, timeout):
        base_command = "timeout "+ str(timeout) + "s " + self.config['dalfox']['command']+ " url '" + url + "' -p " + param_name + " --method " + method
        if body:
            base_command += " --data '" + body + "'"
        base_command += " --no-color \\"
        header_part = ""
        for header in headers:
            if ": " in header:
                header_name, header_value = header.split(": ", 1)
                if '"' not in header_value:
                    header_part += " -H '" + header_name + ": " + header_value + "'"
        full_command = base_command + header_part
        return 'echo "' + full_command + '" | sh 2>&1'

class DalfoxRequestPanel(JPanel):
    def __init__(self, dalfox_request, request_text_area, response_text_area):
        self.dalfox_request = dalfox_request
        self.request_text_area = request_text_area
        self.response_text_area = response_text_area
        self.setupUI()
        self.addMouseListener(PanelMouseListener(self))

    def setupUI(self):
        self.setLayout(BoxLayout(self, BoxLayout.X_AXIS))
        self.setPreferredSize(Dimension(1100, 30))
        self.setMaximumSize(Dimension(sys.maxint, 30))
        self.setBorder(BorderFactory.createLineBorder(Color(0, 0, 0, 0.1), 2))
        url = urlparse(self.dalfox_request.original_request.request_info.getUrl().toString())
        endpoint = url.path
        self.request_label = JLabel(endpoint)
        self.request_label.setFont(Font("Dialog", Font.BOLD, 20))
        self.param_label = JLabel(str(self.dalfox_request.param.getName()) if isinstance(self.dalfox_request.param, IParameter) else str(self.dalfox_request.param))
        self.result_label = JLabel("Pending")
        self.set_label_sizes()
        self.add(self.request_label)
        self.add(Box.createRigidArea(Dimension(25, 0)))
        self.add(self.param_label)
        self.add(Box.createRigidArea(Dimension(25, 0)))
        self.add(self.result_label)

    def set_label_sizes(self):
        size = Dimension(175, 30)
        for label in [self.request_label, self.param_label, self.result_label]:
            label.setPreferredSize(size)

    def update_result(self, result, param):
        def update_components():
            if "Vulnerable" in result or "POC" in result:
                self.result_label.setText("Vulnerable")
            else:
                self.result_label.setText("Safe")
            self.revalidate()
            self.repaint()
        SwingUtilities.invokeLater(update_components)

    def on_panel_clicked(self):
        SwingUtilities.invokeLater(lambda: self.response_text_area.setText(self.dalfox_request.result))

class TplmapRequest:
    def __init__(self, request, param, options, level, timeout, callbacks, helpers, burp_extender, config):
        self.original_request = request
        self.param = param
        self.options = options
        if level == "":
            self.level = 1
        else:
            self.level = level
        self.timeout = timeout
        self._callbacks = callbacks
        self._helpers = helpers
        self.burp_extender = burp_extender
        self.panel = None
        self.result = "Not yet"
        self.thread = threading.Thread(target=self.run_tplmap)
        self.thread.start()
        self.config = config

    def set_panel(self, panel):
        self.panel = panel

    def construct_tplmap_command(self, url, method, headers, body, param_name, options):
        base_command = "timeout "+ self.timeout + "s " + self.config['tplmap']['command'] + " -u '"+ url + "' -X '" + method +"'"
        if body:
            base_command += " -d '{}'".format(body)
        if self.level:
            base_command += "  --level=" + str(self.level)  
        header_part = ""
        for header in headers:
            if ": " in header:
                header_part += " -H '{}'".format(header)
        full_command = "{}{} {}".format(base_command, header_part, options)
        return full_command

    def run_tplmap(self):
        try:
            request_info = self._helpers.analyzeRequest(self.original_request.request)
            url = str(request_info.getUrl())
            headers = request_info.getHeaders()
            method = request_info.getMethod()
            body_offset = request_info.getBodyOffset()
            body_bytes = self.original_request.request.getRequest()[body_offset:]
            body = self._helpers.bytesToString(body_bytes)
            param_name = self.param.getName() if isinstance(self.param, IParameter) else self.param
            original_value = self.param.getValue() if isinstance(self.param, IParameter) else self.param
            modified_value = original_value + '*'
            if method == "GET":
                url = url.replace(original_value, modified_value)
            elif method == "POST" and body:
                body = body.replace(original_value, modified_value)
            command = self.construct_tplmap_command(url, method, headers, body, param_name, self.options)
            print(command)
            if method == "GET":
                url = url.replace(modified_value, original_value)
            elif method == "POST" and body:
                body = body.replace(modified_value, original_value)
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            stdout, stderr = process.communicate()
            self.result = stdout
        except Exception as e:
            self.result = str(e)
        if self.panel:
            self.panel.update_result(self.result, self.param)

class TplmapRequestPanel(JPanel):
    def __init__(self, tplmap_request, request_text_area, response_text_area):
        self.tplmap_request = tplmap_request
        self.request_text_area = request_text_area
        self.response_text_area = response_text_area
        self.setupUI()
        self.addMouseListener(PanelMouseListener(self))

    def setupUI(self):
        self.setLayout(BoxLayout(self, BoxLayout.X_AXIS))
        self.setPreferredSize(Dimension(1100, 30))
        self.setMaximumSize(Dimension(sys.maxint, 30))
        self.setBorder(BorderFactory.createLineBorder(Color(0, 0, 0, 0.1), 2))
        url = urlparse(self.tplmap_request.original_request.request_info.getUrl().toString())
        endpoint = url.path
        self.request_label = JLabel(endpoint)
        self.request_label.setFont(Font("Dialog", Font.BOLD, 20))
        self.param_label = JLabel(str(self.tplmap_request.param.getName()) if isinstance(self.tplmap_request.param, IParameter) else str(self.tplmap_request.param))
        self.result_label = JLabel("Pending")
        self.set_label_sizes()
        self.add(self.request_label)
        self.add(Box.createRigidArea(Dimension(25, 0)))
        self.add(self.param_label)
        self.add(Box.createRigidArea(Dimension(25, 0)))
        self.add(self.result_label)

    def set_label_sizes(self):
        size = Dimension(175, 30)
        for label in [self.request_label, self.param_label, self.result_label]:
            label.setPreferredSize(size)

    def update_result(self, result, param):
        def update_components():
            vulnerable_string1 = "confirmed blind injection"
            vulnerable_string2 = "confirmed injection"
            if vulnerable_string1 in result or vulnerable_string2 in result:
                self.result_label.setText("Vulnerable")
            else:
                self.result_label.setText("Safe")
            self.revalidate()
            self.repaint()
        SwingUtilities.invokeLater(update_components)

    def on_panel_clicked(self):
        SwingUtilities.invokeLater(lambda: self.response_text_area.setText(self.tplmap_request.result))

class CommixRequest:
    def __init__(self, request, param, options, level, timeout, callbacks, helpers, burp_extender, config):
        self.original_request = request
        self.param = param
        self.options = options  
        if level == "":
            self.level = 1
        else:
            self.level = level
        self.timeout = timeout
        self._callbacks = callbacks
        self._helpers = helpers
        self.burp_extender = burp_extender
        self.panel = None
        self.config = config
        self.result = "Not yet"
        self.thread = threading.Thread(target=self.run_commix)
        self.thread.start()

    def set_panel(self, panel):
        self.panel = panel
            
    def run_commix(self):
        try:
            file_path = self.burp_extender.save_request_file(self.original_request.request, self.param)
            command = "timeout " + str(self.timeout) + "s " + self.config['commix']['command'] + " -r " + file_path + " --level=" + str(self.level) + " -p " + self.param.getName() + " --batch --ignore-stdin " + self.options  
            print("Command:", command)
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            stdout, stderr = process.communicate()
            self.result = stdout
        except Exception as e:
            self.result = str(e)
        if self.panel:
            self.panel.update_result(self.result, self.param)

class CommixRequestPanel(JPanel):
    def __init__(self, commix_request, request_text_area, response_text_area):
        self.commix_request = commix_request
        self.request_text_area = request_text_area
        self.response_text_area = response_text_area
        self.setupUI()
        self.addMouseListener(PanelMouseListener(self))

    def setupUI(self):
        self.setLayout(BoxLayout(self, BoxLayout.X_AXIS))
        self.setPreferredSize(Dimension(1100, 30))
        self.setMaximumSize(Dimension(sys.maxint, 30))
        self.setBorder(BorderFactory.createLineBorder(Color(0, 0, 0, 0.1), 2))
        url = urlparse(self.commix_request.original_request.request_info.getUrl().toString())
        endpoint = url.path
        self.request_label = JLabel(endpoint)
        self.request_label.setFont(Font("Dialog", Font.BOLD, 20))
        self.param_label = JLabel(str(self.commix_request.param.getName()) if isinstance(self.commix_request.param, IParameter) else str(self.commix_request.param))
        self.result_label = JLabel("Pending")
        self.set_label_sizes()
        self.add(self.request_label)
        self.add(Box.createRigidArea(Dimension(25, 0)))
        self.add(self.param_label)
        self.add(Box.createRigidArea(Dimension(25, 0)))
        self.add(self.result_label)

    def set_label_sizes(self):
        size = Dimension(175, 30)
        for label in [self.request_label, self.param_label, self.result_label]:
            label.setPreferredSize(size)

    def update_result(self, result, param):
        def update_components():
            if "vulnerable" in result.lower():
                self.result_label.setText("Vulnerable")
            else:
                self.result_label.setText("Safe")
            self.revalidate()
            self.repaint()
        SwingUtilities.invokeLater(update_components)

    def on_panel_clicked(self):
        SwingUtilities.invokeLater(lambda: self.response_text_area.setText(self.commix_request.result))

class Utils:
    @staticmethod
    def is_base64_encoded(data):
        try:
            return base64.b64encode(base64.b64decode(data)) == data
        except Exception:
            return False

    @staticmethod
    def compare_response_bodies(body1, body2):
        semilarity = difflib.SequenceMatcher(None, body1, body2)
        difference = 100 - int(semilarity.ratio() * 100)
        return difference

    @staticmethod
    def check_unsual_header(headers_list, new_headers_list):
        try:
            headers = Utils.parse_headers(headers_list)
            new_headers = Utils.parse_headers(new_headers_list)
            ignore_headers = ["Date", "Server", "Content-Length", "Expires", "Cache-Control", "ETag", "Last-Modified", "Vary", "Connection", "Transfer-Encoding"]
            header_weights = {"Set-Cookie": 10, "Content-Type": 8, "X-Frame-Options": 5, "X-XSS-Protection": 5, "X-Content-Type-Options": 5, "Strict-Transport-Security": 7, "Referrer-Policy": 6}
            default_weight = 1
            filtered_headers1 = {k: v for k, v in headers.items() if k not in ignore_headers}
            filtered_headers2 = {k: v for k, v in new_headers.items() if k not in ignore_headers}
            total_weight = 0
            total_difference = 0
            all_headers = set(filtered_headers1.keys()).union(set(filtered_headers2.keys()))

            for header in all_headers:
                weight = header_weights.get(header, default_weight)
                value1 = filtered_headers1.get(header, "")
                value2 = filtered_headers2.get(header, "")
                similarity = difflib.SequenceMatcher(None, value1, value2)
                if similarity.ratio() < 0.100:
                    total_difference += weight
                total_weight += weight

            if total_weight == 0:
                return "0"

            return str(total_difference)
        except Exception as e:
            print(str(e))
            return "error"

    @staticmethod
    def check_unusual_content(body):
        prompt = "Im gonna give you a http response, your job is to give me the problility of it being vulnerable and to what exactly. so your response would be something \
            like '70% sql injection' or '90% file inclusion'. and if it doesnt have any indication of vulnerability say only 'Nothing'. if its less than 40% , say nothing. the response is to a request injected with some malicious payload. So if the response doesnt clearly show a vulnerable response, say 'nothing'. dont hallucinate, be precise and dont give long answers :"
        prompt += "\n Response: \n\n"
        prompt += body
        print(prompt)
        try:
            command = ['python', 'ai.py', prompt]
            
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                return stderr
            
            return stdout
        
        except Exception as e:
            return str(e)

    @staticmethod
    def parse_headers(header_list):
        headers_dict = {}
        for header in header_list:
            if ":" in header:
                key, value = header.split(":", 1)
                headers_dict[key.strip()] = value.strip()
        return headers_dict

    @staticmethod
    def is_same_request(existing_info, new_url, new_method, new_params):
        existing_url = existing_info.getUrl()
        existing_method = existing_info.getMethod()
        existing_params = set(param.getName() for param in existing_info.getParameters())
        
        return (new_url.getPath() == existing_url.getPath() and
                new_method == existing_method and
                new_params == existing_params)
    
class LaunchedRequestTableModel(AbstractTableModel):
    column_names = ["Request", "Parameter", "Status Code", "Difference", "Response Time", "AI Analysis", "Headers Changes", "Find Results"]
    
    def __init__(self, launched_requests):
        self.launched_requests = launched_requests

    def getColumnCount(self):
        return len(self.column_names)

    def getRowCount(self):
        return len(self.launched_requests)

    def getColumnName(self, col):
        return self.column_names[col]

    def getValueAt(self, row, col):
        request = self.launched_requests[row]
        if col == 0:
            return str(request.original_request.request_info.getUrl().getPath())
        elif col == 1:
            return str(request.param.getName() if isinstance(request.param, IParameter) else request.param)
        elif col == 2:
            return str(request.status_code)
        elif col == 3:
            return str(request.diff) + "%"
        elif col == 4:
            try:
                response_time_ms = int(request.response_time * 1000)
                return str(response_time_ms)+" ms"
            except (TypeError, ValueError):
                return "-- ms"
        elif col == 5:
            return str(request.unusual_content)
        elif col == 6:
            return str(request.unusual_headers)
        elif col == 7:
            return str(request.find_result)
        return ""
 
    def isCellEditable(self, row, col):
        return False

    def update_request(self, row, request):
        self.launched_requests[row] = request
        self.fireTableRowsUpdated(row, row)

class DalfoxTableModel(AbstractTableModel):
    column_names = ["Request", "Parameter", "Status"]

    def __init__(self, launched_requests):
        self.launched_requests = launched_requests

    def getColumnCount(self):
        return len(self.column_names)

    def getRowCount(self):
        return len(self.launched_requests)

    def getColumnName(self, col):
        return self.column_names[col]

    def getValueAt(self, row, col):
        request = self.launched_requests[row]
        if col == 0:
            return str(request.original_request.request_info.getUrl().getPath())
        elif col == 1:
            return str(request.param.getName() if isinstance(request.param, IParameter) else request.param)
        elif col == 2:
            return request.panel.result_label.getText() if request.panel else "Pending"
        return ""

    def isCellEditable(self, row, col):
        return False

    def update_request(self, row, request):
        self.launched_requests[row] = request
        self.fireTableRowsUpdated(row, row)

class TplmapTableModel(AbstractTableModel):
    column_names = ["Request", "Parameter", "Status"]

    def __init__(self, launched_requests):
        self.launched_requests = launched_requests

    def getColumnCount(self):
        return len(self.column_names)

    def getRowCount(self):
        return len(self.launched_requests)

    def getColumnName(self, col):
        return self.column_names[col]

    def getValueAt(self, row, col):
        request = self.launched_requests[row]
        if col == 0:
            return str(request.original_request.request_info.getUrl().getPath())
        elif col == 1:
            return str(request.param.getName() if isinstance(request.param, IParameter) else request.param)
        elif col == 2:
            return request.panel.result_label.getText() if request.panel else "Pending"
        return ""

    def isCellEditable(self, row, col):
        return False

    def update_request(self, row, request):
        self.launched_requests[row] = request
        self.fireTableRowsUpdated(row, row)

class TableMouseAdapter(MouseAdapter):
    def __init__(self, table, launched_requests):
        self.table = table
        self.launched_requests = launched_requests

    def mousePressed(self, event):
        self.handle_event(event)

    def mouseReleased(self, event):
        self.handle_event(event)

    def handle_event(self, event):
        if event.isPopupTrigger():  
            row = self.table.rowAtPoint(event.getPoint())
            if row != -1:
                self.table.setRowSelectionInterval(row, row)
                launched_request = self.launched_requests[row]
                self.show_context_menu(event, launched_request)

    def show_context_menu(self, event, launched_request):
        context_menu = JPopupMenu()
        send_to_repeater_item = JMenuItem("Send to Repeater", actionPerformed=lambda e: self.send_to_repeater(launched_request))
        context_menu.add(send_to_repeater_item)
        context_menu.show(event.getComponent(), event.getX(), event.getY())

    def send_to_repeater(self, launched_request):
        request_info = launched_request.original_request.request_info
        http_service = launched_request.original_request.request.getHttpService()
        modified_request_bytes = launched_request.modified_request_bytes
        launched_request._callbacks.sendToRepeater(http_service.getHost(), http_service.getPort(),
                                                   http_service.getProtocol() == 'https', modified_request_bytes, None)
 
class ToolTableMouseAdapter(MouseAdapter):
    def __init__(self, table, launched_requests):
        self.table = table
        self.launched_requests = launched_requests

    def mousePressed(self, event):
        self.handle_event(event)

    def mouseReleased(self, event):
        self.handle_event(event)

    def handle_event(self, event):
        if event.isPopupTrigger():  
            row = self.table.rowAtPoint(event.getPoint())
            if row != -1:
                self.table.setRowSelectionInterval(row, row)  
                launched_request = self.launched_requests[row]
                self.show_context_menu(event, launched_request)

    def show_context_menu(self, event, launched_request):
        context_menu = JPopupMenu()
        send_to_repeater_item = JMenuItem("Send to Repeater", actionPerformed=lambda e: self.send_to_repeater(launched_request))
        context_menu.add(send_to_repeater_item)
        context_menu.show(event.getComponent(), event.getX(), event.getY())

    def send_to_repeater(self, launched_request):
        request_info = launched_request.original_request.request_info
        http_service = launched_request.original_request.request.getHttpService()
        modified_request_bytes = launched_request.original_request.request.getRequest()
        launched_request._callbacks.sendToRepeater(
            http_service.getHost(),
            http_service.getPort(),
            http_service.getProtocol() == 'https',
            modified_request_bytes,
            None
        )
 
class SQLMapTableModel(AbstractTableModel):
    column_names = ["Request", "Parameter", "Status"]

    def __init__(self, launched_requests):
        self.launched_requests = launched_requests

    def getColumnCount(self):
        return len(self.column_names)

    def getRowCount(self):
        return len(self.launched_requests)

    def getColumnName(self, col):
        return self.column_names[col]

    def getValueAt(self, row, col):
        request = self.launched_requests[row]
        if col == 0:
            return str(request.original_request.request_info.getUrl().getPath())
        elif col == 1:
            return str(request.param.getName() if isinstance(request.param, IParameter) else request.param)
        elif col == 2:
            return request.panel.result_label.getText() if request.panel else "Pending"
        return ""

    def isCellEditable(self, row, col):
        return False

    def update_request(self, row, request):
        self.launched_requests[row] = request
        self.fireTableRowsUpdated(row, row)
 
class CommixTableModel(AbstractTableModel):
    column_names = ["Request", "Parameter", "Status"]

    def __init__(self, launched_requests):
        self.launched_requests = launched_requests

    def getColumnCount(self):
        return len(self.column_names)

    def getRowCount(self):
        return len(self.launched_requests)

    def getColumnName(self, col):
        return self.column_names[col]

    def getValueAt(self, row, col):
        request = self.launched_requests[row]
        if col == 0:
            return str(request.original_request.request_info.getUrl().getPath())
        elif col == 1:
            return str(request.param.getName() if isinstance(request.param, IParameter) else request.param)
        elif col == 2:
            return request.panel.result_label.getText() if request.panel else "Pending"
        return ""

    def isCellEditable(self, row, col):
        return False

    def update_request(self, row, request):
        self.launched_requests[row] = request
        self.fireTableRowsUpdated(row, row)

