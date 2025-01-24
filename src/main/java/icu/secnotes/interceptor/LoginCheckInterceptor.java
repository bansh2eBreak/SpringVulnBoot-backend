package icu.secnotes.interceptor;

import com.alibaba.fastjson.JSONObject;
import icu.secnotes.pojo.Result;
import icu.secnotes.utils.JwtUtils;
import icu.secnotes.utils.Security;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

@Component
@Slf4j
public class LoginCheckInterceptor implements HandlerInterceptor {

    /**
     * 目标资源方法运行前执行，返回true表示放行，返回false表示不放行
     * @param request
     * @param response
     * @param handler
     * @return
     * @throws Exception
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        //1.获取请求url
        String url = request.getRequestURL().toString();
        log.info("访问的url是：{}", url);

        //2.判断请求url中是否login，如果包含说明是登录操作
        //但是，因为在WebConfig类中进行配置：.addPathPatterns("/**").excludePathPatterns("/login");，所以下面的判断方法永远不会执行
        if (url.contains("login") || url.contains("httpBasicLogin")){
            log.info("登录操作，放行");
            return true;
        }

//        if (url.contains("httpBasicLogin1")){
//            String USERNAME = "zhangsan"; // 硬编码用户名
//            String PASSWORD = "123"; // 硬编码密码
//
//            // 处理HTTP Basic Auth登录
//            String token = request.getHeader("token");
//            if (token == null || !token.startsWith("Basic ")) {
//                log.info("HTTP Basic Auth登录，token缺失或者token格式错误");
////                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//                response.setHeader("WWW-Authenticate", "Basic realm=\"Access to the site\"");
//                return false;
//            }
//
//            String[] credentials = Security.decodeBasicAuth(token);
//            if (credentials == null || credentials.length != 2) {
////                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//                return false;
//            }
//
//            String username = credentials[0];
//            String password = credentials[1];
//
//            if (!USERNAME.equals(username) || !PASSWORD.equals(password)) {
//                log.info("HTTP Basic Auth登录，账号密码错误，token：{}" , token);
////                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//                return false;
//            }
//
//            log.info("HTTP Basic Auth登录，放行，token：{}" , token);
//            return true; // 认证通过
//        }

        //3.获取请求头的令牌
        String jwttoken = request.getHeader("Authorization");

        /*        //3.获取请求cookie中的jwt令牌
        String jwttoken = null;

        Cookie[] cookies = request.getCookies();

        //System.out.println(cookies.length); //Cannot read the array length because "cookies" is null

        if (cookies != null){
            for (Cookie cookie : cookies) {
                if ("token".equals(cookie.getName())){
                    jwttoken = cookie.getValue();
                    break;
                }
            }
        }*/

        //4.判断令牌是否存在，如果不存在，返回错误信息（未登录）
        if(!StringUtils.hasLength(jwttoken)){   //如果 jwttoken 为空或只包含空白字符（即没有长度）
            log.info("Authorization为空，返回未登录信息");
            Result error = Result.error("NOT_LOGIN");
            //手动转换， 对象--json
            String notLogin = JSONObject.toJSONString(error);
            response.getWriter().write(notLogin);
            return false;
        }

        //5.解析jwttoken，如果解析失败，返回错误信息（未登录）
        try {
            JwtUtils.parseJwt(jwttoken);
        } catch (Exception e) {
            e.printStackTrace();
            log.info("令牌解析失败，返回未登录信息");
            Result error = Result.error("NOT_LOGIN");
            //手动转换， 对象--json
            String notLogin = JSONObject.toJSONString(error);
            response.getWriter().write(notLogin);
            return false;
        }

        //6.jwt解析没问题，放行
        log.info("登录的令牌合法，放行");
        return true;

    }

    /**
     * 目标资源方法运行后执行，可以对请求域中的属性或视图做出修改
     * @param request
     * @param response
     * @param handler
     * @param modelAndView
     * @throws Exception
     */
    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {
        System.out.println("postHandle...");
    }

    /**
     * 视图渲染完毕后执行，最后运行
     * @param request
     * @param response
     * @param handler
     * @param ex
     * @throws Exception
     */
    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        System.out.println("afterCompletion...");
    }
}
