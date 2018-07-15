/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.shop.users;

import com.example.security.Digester;
import com.example.util.RandomNumberGenerator;
import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 *
 * @author Ayezele Mboto
 */
public class LoginServlet extends HttpServlet
{

    /**
     * Processes requests for both HTTP <code>GET</code> and <code>POST</code> methods.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    protected void processRequest(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
    {
        try
        {
            //Request User Email
            String emailAddress = request.getParameter("emailAddress");
            //Request User Password
            String password = request.getParameter("password");
            //Request User Page
            String pageUrl = request.getParameter("userPage");
            //Check if user email and password correspond to a valid user
            User user = UserDAO.authenticateUser(emailAddress, password);
            if(user != null)//If a non empty user object is returned do the following
            {
                //Create a session instance
                HttpSession session = request.getSession(true);
                //Check if the user already has a token identifier in the database
                if(user.getToken() != null)
                {
                    String userToken = user.getToken();
                    //Encrypt user token identifier using your encryption class /you will have to create your own encryption class/
                    Digester digester = new Digester();
                    String encryptedToken = digester.doDigest(userToken);
                    //Store encrypted token along with user info
                    boolean saveUserToken = UserDAO.storeUserSecurityToken(user.getEmail(), userToken, encryptedToken);
                    //Store encrypted token in a cookie and encode value so as to remove white spaces
                    Cookie userCookie = new Cookie("userToken", URLEncoder.encode(userToken, "UTF-8"));
                    //Set life span of cookie
                    userCookie.setMaxAge(60 * 60 * 24 * 32 * 12);
                    //Store cookie object
                    response.addCookie(userCookie);
                    
                    user.setToken(userToken);
                    //set user session
                    session.setAttribute("user", user);
                    //Below is optional
                    if(pageUrl.equals(""))
                        response.sendRedirect("home");
                    else
                        response.sendRedirect(pageUrl);
                }
                else//If an empty user object is returned
                {
                    //Get all cookies
                    Cookie[] allCookies = request.getCookies();
                    if(allCookies != null)//If cookies exist get user token value from user cookies
                    {
                        //Declare user token variable
                        String userToken = null;
                        for(Cookie allCookie : allCookies)
                            if(allCookie.getName().equals("userToken"))
                                //Allways remember to decode token cookie value
                                userToken = URLDecoder.decode(allCookie.getValue(), "UTF-8");
                        if(userToken != null)//If userToken is a non empty string
                        {
                            //Encrypt token
                            Digester digester = new Digester();
                            String encryptedToken = digester.doDigest(userToken);
                            //Store encrypted token along with user info
                            boolean saveUserToken = UserDAO.storeUserSecurityToken(user.getEmail(), userToken, encryptedToken);
                            //Store encrypted token in a cookie and encode value so as to remove white spaces
                            Cookie userCookie = new Cookie("userToken", URLEncoder.encode(userToken, "UTF-8"));
                            //Set life span of cookie
                            userCookie.setMaxAge(60 * 60 * 24 * 32 * 12);
                            response.addCookie(userCookie);
                            //Set life span of cookie
                            userCookie.setMaxAge(60 * 60 * 24 * 32 * 12);
                            //Store cookie object
                            response.addCookie(userCookie);
                    
                            user.setToken(userToken);
                            //set user session
                            session.setAttribute("user", user);
                            //Below is optional
                            if(pageUrl.equals(""))
                                response.sendRedirect("home");
                            else
                                response.sendRedirect(pageUrl);
                        }
                        else//If userToken is an empty string
                        {
                            //Generate user identification token
                            userToken = RandomNumberGenerator.generateRandomAlphanumericCharacters(30);
                            //Encrypt token
                            Digester digester = new Digester();
                            String encryptedToken = digester.doDigest(userToken);
                            //Store encrypted token along with user info
                            boolean saveUserToken = UserDAO.storeUserSecurityToken(user.getEmail(), userToken, encryptedToken);
                            //Store encrypted token in a cookie and encode value so as to remove white spaces
                            Cookie userCookie = new Cookie("userToken", URLEncoder.encode(userToken, "UTF-8"));
                            //Set life span of cookie
                            userCookie.setMaxAge(60 * 60 * 24 * 32 * 12);
                            response.addCookie(userCookie);
                            
                            user.setToken(userToken);
                            //set user session
                            session.setAttribute("user", user);
                            //Below is optional
                            if(pageUrl.equals(""))
                                response.sendRedirect("home");
                            else
                                response.sendRedirect(pageUrl);
                        }
                    }
                    else//If no cookie exist
                    {
                        //Generate user identification token
                        String userToken = RandomNumberGenerator.generateRandomAlphanumericCharacters(30);
                        //Digest token
                        Digester digester = new Digester();
                        String encryptedToken = digester.doDigest(userToken);
                        //Store encrypted token along with user info
                        boolean saveUserToken = UserDAO.storeUserSecurityToken(user.getEmail(), userToken, encryptedToken);
                        //Store encrypted token in a cookie and encode value so as to remove white spaces
                        Cookie userCookie = new Cookie("userToken", URLEncoder.encode(userToken, "UTF-8"));
                        //Set life span of cookie
                        userCookie.setMaxAge(60 * 60 * 24 * 32 * 12);
                        response.addCookie(userCookie);
                        user.setToken(userToken);
                        //set user session
                        session.setAttribute("user", user);
                        //Below is optional
                        if(pageUrl.equals(""))
                            response.sendRedirect("home");
                        else
                            response.sendRedirect(pageUrl);
                    }
                }
            }
            else//If login detail were incorrect
            {
              // Do what you like here
            }
        }
        catch(Exception xcp)
        {
            //Perform exception handling 
        }
    }

    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException
    {
        processRequest(request, response);
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException
    {
        processRequest(request, response);
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo()
    {
        return "Short description";
    }// </editor-fold>

}

