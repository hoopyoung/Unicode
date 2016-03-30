package burp;

import java.io.PrintWriter;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, IHttpListener, 
        IProxyListener, IScannerListener, IExtensionStateListener
{
    //private IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;
    private IExtensionHelpers helper;
    
    //
    // implement IBurpExtender
    //
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        //this.callbacks = callbacks;
        helper = callbacks.getHelpers();
        // set our extension name
        callbacks.setExtensionName("Chora[MS509] Unicode Decode");
        
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
    			byte[] oRes = messageInfo.getResponse();
    			IResponseInfo hRes = helper.analyzeResponse(oRes);
    			List<String> headers = hRes.getHeaders();
    			String mime =  hRes.getStatedMimeType();
    			String header = headers.toString();
    			if(!mime.equalsIgnoreCase("GIF") 
    					&& !mime.equalsIgnoreCase("PNG") 
    					&& !mime.equalsIgnoreCase("JPG")
    					&& !mime.equalsIgnoreCase("JPEG")
    					&& !mime.equalsIgnoreCase("BMP")
    					&& !mime.equalsIgnoreCase("IMAGE"))	{
    			Matcher m = Pattern.compile("charset=(.*?),").matcher(header);//根据响应头判断编码
    			String encode = null;
    			if(m.find())
    			{
    				encode = m.group(1);
    			}
    			if (encode == null) {
    				Matcher m2 = Pattern.compile("charset=(.*?)\"").matcher(new String(oRes));//根据网页内容判断编码
        			if(m2.find())
        			{
        				encode = m2.group(1);
        				if(encode.equals("gb2312"))
        				{
        					encode = "8859_1";
        				}
        			} else {
        				encode = "UTF-8";
        			}
    			}
    			String Res = new String(oRes,encode);
    			messageInfo.setResponse(unicodeToString(Res).getBytes(encode));
    			}
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}			
			
    	}
    }
    private String unicodeToString(String str)
    {
    	Pattern pattern = Pattern.compile("(\\\\u([a-fA-F0-9]{4}))"); 
    	Matcher matcher = pattern.matcher(str);
    	char ch;
    	while (matcher.find()) {
    		ch = (char) Integer.parseInt(matcher.group(2), 16);
    		str = str.replace(matcher.group(1), ch + "");
    	}
    	return str;
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
}