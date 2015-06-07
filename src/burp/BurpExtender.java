package burp;

import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;

public class BurpExtender implements IBurpExtender, IHttpListener, 
        IProxyListener, IScannerListener, IExtensionStateListener
{
    private IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;
    
    //
    // implement IBurpExtender
    //
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        
        // set our extension name
        callbacks.setExtensionName("Chora Unicode Decode");
        
        // obtain our output stream
        stdout = new PrintWriter(callbacks.getStdout(), true);
        
        // register ourselves as an HTTP listener
        callbacks.registerHttpListener(this);
        
        // register ourselves as a Proxy listener
        callbacks.registerProxyListener(this);
        
        // register ourselves as a Scanner listener
        callbacks.registerScannerListener(this);
        
        // register ourselves as an extension state listener
        callbacks.registerExtensionStateListener(this);
    }

    //
    // implement IHttpListener
    //

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {
    	if(!messageIsRequest) {
    		try {
				String oResponse = new String(messageInfo.getResponse(),"UTF-8");			
	            char[] convtBuf=new char[2];  
	            String nResponse = loadConvert(oResponse.toCharArray(),0,oResponse.length(),convtBuf);
	            messageInfo.setResponse(nResponse.getBytes("UTF-8"));
			} catch (UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
    	}
    }

    //
    // implement IProxyListener
    //

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message)
    {
    }

    //
    // implement IScannerListener
    //

    @Override
    public void newScanIssue(IScanIssue issue)
    {
        stdout.println("New scan issue: " + issue.getIssueName());
    }

    //
    // implement IExtensionStateListener
    //

    @Override
    public void extensionUnloaded()
    {
        stdout.println("Extension was unloaded");
    }
    
    private String loadConvert (char[] in, int off, int len, char[] convtBuf) {  
        if (convtBuf.length < len) {  
            int newLen = len * 2;  
            if (newLen < 0) {  
            newLen = Integer.MAX_VALUE;  
        }   
        convtBuf = new char[newLen];  
        }  
        char aChar;  
        char[] out = convtBuf;   
        int outLen = 0;  
        int end = off + len;  
   
        while (off < end) {  
            aChar = in[off++];  
            if (aChar == '\\') {  
                aChar = in[off++];     
                if(aChar == 'u') {  
                    // Read the xxxx  
                    int value=0;  
            for (int i=0; i<4; i++) {  
                aChar = in[off++];    
                switch (aChar) {  
                  case '0': case '1': case '2': case '3': case '4':  
                  case '5': case '6': case '7': case '8': case '9':  
                     value = (value << 4) + aChar - '0';  
                 break;  
              case 'a': case 'b': case 'c':  
                          case 'd': case 'e': case 'f':  
                 value = (value << 4) + 10 + aChar - 'a';  
                 break;  
              case 'A': case 'B': case 'C':  
                          case 'D': case 'E': case 'F':  
                 value = (value << 4) + 10 + aChar - 'A';  
                 break;  
              default:  
                              throw new IllegalArgumentException(  
                                           "Malformed \\uxxxx encoding.");  
                        }  
                     }  
                    out[outLen++] = (char)value;  
                } else {  
                    if (aChar == 't') aChar = '\t';   
                    else if (aChar == 'r') aChar = '\r';  
                    else if (aChar == 'n') aChar = '\n';  
                    else if (aChar == 'f') aChar = '\f';   
                    out[outLen++] = aChar;  
                }  
            } else {  
            out[outLen++] = (char)aChar;  
            }  
        }  
        return new String (out, 0, outLen);  
    }  
}