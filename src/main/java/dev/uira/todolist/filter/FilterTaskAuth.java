package dev.uira.todolist.filter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import dev.uira.todolist.user.IUserRepository;
import dev.uira.todolist.user.UserModel;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Base64;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        var path = request.getServletPath();
        if (path.startsWith("/tasks/")) {
            // pegar a autenticação (usuario e senha)
            var authorizarion = request.getHeader("Authorization");
            var authEncoded = authorizarion.substring("Basic".length()).trim();
            byte[] authDecoded = Base64.getDecoder().decode(authEncoded);
            var authString = new String(authDecoded);

            String[] credentials = authString.split(":");
            String username = credentials[0];
            String password = credentials[1];

            // validar usuario
            var user = userRepository.findByUsername(username);
            if (user == null) {
                response.sendError(401);
            } else {
                // validar a senha
                var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                if (passwordVerify.verified) {
                    // segue viagem
                    request.setAttribute("idUser", user.getId());
                    filterChain.doFilter(request, response);
                } else {
                    response.sendError(401);
                }
            }
        } else {
            // segue viagem
            filterChain.doFilter(request, response);
        }
    }
}
