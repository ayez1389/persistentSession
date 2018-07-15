/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.example;


import com.example.users.User;
import com.example.users.UserDAO;
import com.example.util.RandomNumberGenerator;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import javax.servlet.http.HttpSession;

/**
 *
 * @author Ayezele Mboto
 */
public class AppUtilityFilter implements Filter
{

    private static final boolean debug = false;

    // The filter configuration object we are associated with.  If
    // this value is null, this filter instance is not currently
    // configured.
    private FilterConfig filterConfig = null;

    public AppUtilityFilter()
    {
    }

    private void doBeforeProcessing(RequestWrapper request, ResponseWrapper response)
            throws IOException, ServletException
    {
        if(debug)
            log("AppUtilityFilter:DoBeforeProcessing");

        // Write code here to process the request and/or response before
        // the rest of the filter chain is invoked.
        // For example, a filter that implements setParameter() on a request
        // wrapper could set parameters on the request before passing it on
        // to the filter chain.
        /*
	String [] valsOne = {"val1a", "val1b"};
	String [] valsTwo = {"val2a", "val2b", "val2c"};
	request.setParameter("name1", valsOne);
	request.setParameter("nameTwo", valsTwo);
         */
        // For example, a logging filter might log items on the request object,
        // such as the parameters.
        /*
	for (Enumeration en = request.getParameterNames(); en.hasMoreElements(); ) {
	    String name = (String)en.nextElement();
	    String values[] = request.getParameterValues(name);
	    int n = values.length;
	    StringBuffer buf = new StringBuffer();
	    buf.append(name);
	    buf.append("=");
	    for(int i=0; i < n; i++) {
	        buf.append(values[i]);
	        if (i < n-1)
	            buf.append(",");
	    }
	    log(buf.toString());
	}
         */
    }

    private void doAfterProcessing(RequestWrapper request, ResponseWrapper response)
            throws IOException, ServletException
    {
        if(debug)
            log("AppUtilityFilter:DoAfterProcessing");

        // Write code here to process the request and/or response after
        // the rest of the filter chain is invoked.
        // For example, a logging filter might log the attributes on the
        // request object after the request has been processed.
        /*
	for (Enumeration en = request.getAttributeNames(); en.hasMoreElements(); ) {
	    String name = (String)en.nextElement();
	    Object value = request.getAttribute(name);
	    log("attribute: " + name + "=" + value.toString());

	}
         */
        // For example, a filter might append something to the response.
        /*
	PrintWriter respOut = new PrintWriter(response.getWriter());
	respOut.println("<p><strong>This has been appended by an intrusive filter.</strong></p>");

	respOut.println("<p>Params (after the filter chain):<br>");
	for (Enumeration en = request.getParameterNames(); en.hasMoreElements(); ) {
		String name = (String)en.nextElement();
		String values[] = request.getParameterValues(name);
		int n = values.length;
		StringBuffer buf = new StringBuffer();
		buf.append(name);
		buf.append("=");
		for(int i=0; i < n; i++) {
		    buf.append(values[i]);
		    if (i < n-1)
			buf.append(",");
		}
		log(buf.toString());
		respOut.println(buf.toString() + "<br>");
	}
        respOut.println("</p>");
         */
    }

    /**
     *
     * @param request The servlet request we are processing
     * @param response The servlet response we are creating
     * @param chain The filter chain we are processing
     *
     * @exception IOException if an input/output error occurs
     * @exception ServletException if a servlet error occurs
     */
    public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain)
            throws IOException, ServletException
    {

        if(debug)
            log("AppUtilityFilter:doFilter()");

        // Create wrappers for the request and response objects.
        // Using these, you can extend the capabilities of the
        // request and response, for example, allow setting parameters
        // on the request before sending the request to the rest of the filter chain,
        // or keep track of the cookies that are set on the response.
        //
        // Caveat: some servers do not handle wrappers very well for forward or
        // include requests.
        RequestWrapper wrappedRequest = new RequestWrapper((HttpServletRequest)request);
        ResponseWrapper wrappedResponse = new ResponseWrapper((HttpServletResponse)response);

        doBeforeProcessing(wrappedRequest, wrappedResponse);

        Throwable problem = null;

        try // Write your do filter method here
        {
            //Create a session instance of none exist
            HttpSession session = wrappedRequest.getSession();
            //If session is not empty and user session attribute is not empty
            if(session != null && session.getAttribute("user") != null)
            {
                //Obtain user object from user session attribute
                User user = (User)session.getAttribute("user");
                if(user.getEmail() != null)//If user session object is valid do filter processing
                {
                    //Do what you want here
                    chain.doFilter(wrappedRequest, wrappedResponse);
                }
                else//If user session attribute is not valid
                {
                    //Declare user token variable
                    String userToken = null;
                    //Get all cookies
                    Cookie[] allCookies = wrappedRequest.getCookies();
                    //Check if cookies exist and get user token value from user cookies
                    if(allCookies != null)
                        for(Cookie allCookie : allCookies)
                            if(allCookie.getName().equals("userToken"))
                                //Allways remember to decode token cookie value
                                userToken = URLDecoder.decode(allCookie.getValue(), "UTF-8");
                    //If user token is not empty validate token value and log user in
                    if(userToken != null)
                    {
                        /*
                        check if stored token identifies a valid user 
                        This is a smaple method called here you will have to write your own                        
                        */
                        user = UserDAO.authenticateUserWithToken(userToken);
                        //If user token identifies a valid user 
                        if(user != null && user.getEmail() != null)
                        {
                            //Set user session attribute
                            session.setAttribute("user", user);
                            chain.doFilter(wrappedRequest, wrappedResponse);
                        }
                        else //If user token exist but does not identify a valid user
                        {
                            //Do what you wish here
                            chain.doFilter(wrappedRequest, wrappedResponse);
                        }
                    }
                    else //If user token is empty
                    {
                        //Generate user identification token
                        userToken = RandomNumberGenerator.generateRandomAlphanumericCharacters(30);
                        //Store encrypted token in a cookie and encode value so as to remove white spaces
                        //Note you only need to encode the cookie if you are storing and ecypted value 
                        Cookie userCookie = new Cookie("userToken", URLEncoder.encode(userToken, "UTF-8"));
                        //Set life span of cookie
                        userCookie.setMaxAge(60 * 60 * 24 * 32 * 12);
                        wrappedResponse.addCookie(userCookie);
                        
                        chain.doFilter(wrappedRequest, wrappedResponse);
                    }
                }
            }
            else//If no session exist
            {
                //Declare user token variable
                String userToken = null;
                //Get all cookies
                Cookie[] allCookies = wrappedRequest.getCookies();
                //Check if cookies exist and get user token value from user cookies
                if(allCookies != null)
                    for(Cookie allCookie : allCookies)
                        if(allCookie.getName().equals("userToken"))
                            //Allways remember to decode token cookie value
                            userToken = URLDecoder.decode(allCookie.getValue(), "UTF-8");
                //if user token is not empty validate token value and log user in
                if(userToken != null)
                {
                    //If user token identifies a valid user 
                    User user = UserDAO.authenticateUserWithToken(userToken);
                    if(user != null && user.getEmail() != null)
                    {
                        session.setAttribute("user", user);
                        chain.doFilter(wrappedRequest, wrappedResponse);
                    }
                    else //If user token identifies no user
                    {
                        //Its your choice do what you want here
                        chain.doFilter(wrappedRequest, wrappedResponse);
                    }
                }
                else //if user token is empty
                {
                    //Generate user identification token
                    userToken = RandomNumberGenerator.generateRandomAlphanumericCharacters(30);
                    //Store token in a cookie and encode value so as to remove white spaces 
                    Cookie userCookie = new Cookie("userToken", URLEncoder.encode(userToken, "UTF-8"));
                    //Set life span of cookie
                    userCookie.setMaxAge(60 * 60 * 24 * 32 * 12);
                    wrappedResponse.addCookie(userCookie);
                   
                    chain.doFilter(wrappedRequest, wrappedResponse);
                }

            }

        }
        catch(Throwable t)
        {
            // If an exception is thrown somewhere down the filter chain,
            // we still want to execute our after processing, and then
            // rethrow the problem after that.
            problem = t;
            t.printStackTrace();
        }

        doAfterProcessing(wrappedRequest, wrappedResponse);

        // If there was a problem, we want to rethrow it if it is
        // a known type, otherwise log it.
        if(problem != null)
        {
            if(problem instanceof ServletException)
                throw (ServletException)problem;
            if(problem instanceof IOException)
                throw (IOException)problem;
            sendProcessingError(problem, response);
        }
    }

    /**
     * Return the filter configuration object for this filter.
     */
    public FilterConfig getFilterConfig()
    {
        return (this.filterConfig);
    }

    /**
     * Set the filter configuration object for this filter.
     *
     * @param filterConfig The filter configuration object
     */
    public void setFilterConfig(FilterConfig filterConfig)
    {
        this.filterConfig = filterConfig;
    }

    /**
     * Destroy method for this filter
     */
    public void destroy()
    {
    }

    /**
     * Init method for this filter
     */
    public void init(FilterConfig filterConfig)
    {
        this.filterConfig = filterConfig;
        if(filterConfig != null)
            if(debug)
                log("AppUtilityFilter: Initializing filter");
    }

    /**
     * Return a String representation of this object.
     */
    @Override
    public String toString()
    {
        if(filterConfig == null)
            return ("AppUtilityFilter()");
        StringBuffer sb = new StringBuffer("AppUtilityFilter(");
        sb.append(filterConfig);
        sb.append(")");
        return (sb.toString());

    }

    private void sendProcessingError(Throwable t, ServletResponse response)
    {
        String stackTrace = getStackTrace(t);

        if(stackTrace != null && !stackTrace.equals(""))
            try
            {
                response.setContentType("text/html");
                PrintStream ps = new PrintStream(response.getOutputStream());
                PrintWriter pw = new PrintWriter(ps);
                pw.print("<html>\n<head>\n<title>Error</title>\n</head>\n<body>\n"); //NOI18N

                // PENDING! Localize this for next official release
                pw.print("<h1>The resource did not process correctly</h1>\n<pre>\n");
                pw.print(stackTrace);
                pw.print("</pre></body>\n</html>"); //NOI18N
                pw.close();
                ps.close();
                response.getOutputStream().close();
            }
            catch(Exception ex)
            {
            }
        else
            try
            {
                PrintStream ps = new PrintStream(response.getOutputStream());
                t.printStackTrace(ps);
                ps.close();
                response.getOutputStream().close();
            }
            catch(Exception ex)
            {
            }
    }

    public static String getStackTrace(Throwable t)
    {
        String stackTrace = null;
        try
        {
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            t.printStackTrace(pw);
            pw.close();
            sw.close();
            stackTrace = sw.getBuffer().toString();
        }
        catch(Exception ex)
        {
        }
        return stackTrace;
    }

    public void log(String msg)
    {
        filterConfig.getServletContext().log(msg);
    }

    /**
     * This request wrapper class extends the support class HttpServletRequestWrapper, which implements all the methods in the HttpServletRequest interface, as delegations to the wrapped request. You
     * only need to override the methods that you need to change. You can get access to the wrapped request using the method getRequest()
     */
    class RequestWrapper extends HttpServletRequestWrapper
    {

        public RequestWrapper(HttpServletRequest request)
        {
            super(request);
        }

        // You might, for example, wish to add a setParameter() method. To do this
        // you must also override the getParameter, getParameterValues, getParameterMap,
        // and getParameterNames methods.
        protected Hashtable localParams = null;

        public void setParameter(String name, String[] values)
        {
            if(debug)
                System.out.println("AppUtilityFilter::setParameter(" + name + "=" + values + ")" + " localParams = " + localParams);

            if(localParams == null)
            {
                localParams = new Hashtable();
                // Copy the parameters from the underlying request.
                Map wrappedParams = getRequest().getParameterMap();
                Set keySet = wrappedParams.keySet();
                for(Iterator it = keySet.iterator(); it.hasNext();)
                {
                    Object key = it.next();
                    Object value = wrappedParams.get(key);
                    localParams.put(key, value);
                }
            }
            localParams.put(name, values);
        }

        @Override
        public String getParameter(String name)
        {
            if(debug)
                System.out.println("AppUtilityFilter::getParameter(" + name + ") localParams = " + localParams);
            if(localParams == null)
                return getRequest().getParameter(name);
            Object val = localParams.get(name);
            if(val instanceof String)
                return (String)val;
            if(val instanceof String[])
            {
                String[] values = (String[])val;
                return values[0];
            }
            return (val == null ? null : val.toString());
        }

        @Override
        public String[] getParameterValues(String name)
        {
            if(debug)
                System.out.println("AppUtilityFilter::getParameterValues(" + name + ") localParams = " + localParams);
            if(localParams == null)
                return getRequest().getParameterValues(name);
            return (String[])localParams.get(name);
        }

        @Override
        public Enumeration getParameterNames()
        {
            if(debug)
                System.out.println("AppUtilityFilter::getParameterNames() localParams = " + localParams);
            if(localParams == null)
                return getRequest().getParameterNames();
            return localParams.keys();
        }

        @Override
        public Map getParameterMap()
        {
            if(debug)
                System.out.println("AppUtilityFilter::getParameterMap() localParams = " + localParams);
            if(localParams == null)
                return getRequest().getParameterMap();
            return localParams;
        }
    }

    /**
     * This response wrapper class extends the support class HttpServletResponseWrapper, which implements all the methods in the HttpServletResponse interface, as delegations to the wrapped response.
     * You only need to override the methods that you need to change. You can get access to the wrapped response using the method getResponse()
     */
    class ResponseWrapper extends HttpServletResponseWrapper
    {

        public ResponseWrapper(HttpServletResponse response)
        {
            super(response);
        }

        // You might, for example, wish to know what cookies were set on the response
        // as it went throught the filter chain. Since HttpServletRequest doesn't
        // have a get cookies method, we will need to store them locally as they
        // are being set.
        /*
	protected Vector cookies = null;

	// Create a new method that doesn't exist in HttpServletResponse
	public Enumeration getCookies() {
		if (cookies == null)
		    cookies = new Vector();
		return cookies.elements();
	}

	// Override this method from HttpServletResponse to keep track
	// of cookies locally as well as in the wrapped response.
	public void addCookie (Cookie cookie) {
		if (cookies == null)
		    cookies = new Vector();
		cookies.add(cookie);
		((HttpServletResponse)getResponse()).addCookie(cookie);
	}
         */
    }

}
