package net.sago.ApacheShiro.controllers;

import net.sago.ApacheShiro.model.UserCredentials;
import org.apache.log4j.Logger;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.servlet.http.HttpServletRequest;

@Controller
public class IndexController {
    private static final Logger logger = Logger.getLogger(IndexController.class);
    @GetMapping("/")
    public String index(){
        return "index";
    }

    @RequestMapping(value = "/login",method = {RequestMethod.GET,RequestMethod.POST})
    public String login(HttpServletRequest request, UserCredentials credentials, RedirectAttributes attributes){
        if (request.getMethod().equals(RequestMethod.GET.toString()))
        {
            return "login";
        }else{
            Subject subject = SecurityUtils.getSubject();
            if(!subject.isAuthenticated()){
                UsernamePasswordToken token = new UsernamePasswordToken(credentials.getUsername(), credentials.getPassword(), credentials.isRememberMe());
                try{
                    subject.login(token);
                }catch (AuthenticationException e){
                    logger.debug("Login Failed",e);
                    attributes.addFlashAttribute("error","Invalid Credentials");
                    return "redirect:/login";
                }
            }
            return "redirect:/secure";
        }
    }

    @GetMapping("/secure")
    public String secure(ModelMap model){

        Subject user = SecurityUtils.getSubject();
        String role = "you are an ", permission="you are allowed to ";

        if(user.hasRole("admin")) {
            role = role +"Admin";
        }else if (user.hasRole("user")){
            role = role + "Regular User";
        }

        //permissions
        if(user.isPermitted("read")){
            permission= permission+"Read";
        }
        if(user.isPermitted("write")){
            permission=permission+"Write";
        }

        model.addAttribute("username",user.getPrincipal());
        model.addAttribute("permission",permission);
        model.addAttribute("role",role);

        return "secure";
    }

    @PostMapping("/logout")
    public String logout() {
        Subject subject = SecurityUtils.getSubject();
        subject.logout();
        return "redirect:/";
    }
}
