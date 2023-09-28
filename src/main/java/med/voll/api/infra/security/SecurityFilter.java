package med.voll.api.infra.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import med.voll.api.domain.usuarios.UsuarioRepository;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class SecurityFilter extends OncePerRequestFilter{
	
	@Autowired
	private TokenService tokenService;
	
	@Autowired
	private UsuarioRepository usuarioRepository;
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException{
		var tokenJWT = extracted(request);
		
			
			if(tokenJWT != null) {
				//Token valido

				var subject = tokenService.getSubject(tokenJWT);
				var usuario = usuarioRepository.findByLogin(subject);
				var authentication = new UsernamePasswordAuthenticationToken(usuario, null, usuario.getAuthorities()); // Forzamos un inicio de sesion
				SecurityContextHolder.getContext().setAuthentication(authentication);;
			}
		filterChain.doFilter(request, response);
	}

	private String extracted(HttpServletRequest request) {
		var authHeader = request.getHeader("Authorization");//.replace("Bearer ","");
		if (authHeader != null) {
			return authHeader.replace("Bearer ","");
		}
		return null;
	}
	
}
