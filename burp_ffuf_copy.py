from burp import IBurpExtender, IContextMenuFactory, IHttpRequestResponse
from javax.swing import JMenuItem
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection

class BurpExtender(IBurpExtender, IContextMenuFactory, IHttpRequestResponse):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Copy as FFUF Command")
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        items = []
        if invocation.getInvocationContext() == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            item = JMenuItem("Copy as FFUF Command", actionPerformed=lambda _: self.copyAsFFUFCommand(invocation))
            items.append(item)
        return items

    def copyToClipboard(self, data):
        data = self._helpers.bytesToString(data).replace('\r\n', '\n') 
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        selection = StringSelection(data)
        clipboard.setContents(selection, None)
        

    def copyAsFFUFCommand(self, invocation):
        http=invocation.getSelectedMessages()[0]
        requestStr = self._helpers.bytesToString(http.getRequest())
        head=requestStr.split('\r\n')[0]
        headers = {k:v for k,v in list(map(lambda x:[x.split(":")[0],':'.join(x.split(":")[1:])],requestStr.split('\r\n\r\n')[0].split('\r\n')[1:])) if k not in ["Host","Content-Length","Connection","Accept-Encoding","Accept"]}
        data = requestStr.split('\r\n\r\n')[1]
        
        url = http.getUrl().toString()
        method = head.split()[0]
        
        command = "ffuf -u '{}' ".format(url)
        if method != "GET":
            command += "-X {} ".format(method)
        for k,v in headers.items():
            command += "-H '{}:{}' ".format(k,v)
        if data:
            command += "-d '{}' ".format(data)
        
        command+= "-w "
        self.copyToClipboard(command)
        pass
