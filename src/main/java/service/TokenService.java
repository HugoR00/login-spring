package service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import entity.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class TokenService {

    @Value("${api.security.token.secretkey}")
    private String secret; //Cria uma chave secreta que desbloqueia o hash, nesse caso a chave vem do value
    //determinado lá no application properties com o nome de api.security.token.secretkey

    public String generateToken(User user) {
        try{
            Algorithm algorithm = Algorithm.HMAC256(secret); //Gera o hash a partir do secret
            String token = JWT.create()
                    .withIssuer("login-api") //Quem está emitindo o token
                    .withSubject(user.getEmail()) //Quem recebe o token
                    .sign(algorithm); //Sign o algoritmo
            return token;
        }catch (JWTCreationException exception){
            throw new RuntimeException("Erro ao gerar token");
        }

    }

    public String verifyToken(String token) {
        try{
            Algorithm algorithm = Algorithm.HMAC256(secret); //Monta o algoritmo que gera o hash
            return JWT.require(algorithm) //Inicia a construção do verificador a partir do algoritmo
                    .withIssuer("login-api") // Verifica se quem solicitou a verificação foi o login-api, no caso eu
                    .build() // Constrói o verificador
                    .verify(token) // Verifica se o token recebido é válido
                    .getSubject(); // Se o token for válido retorna o Subject, no caso o email que definimos acima
        }catch(JWTVerificationException exception){
            return null;
        }
    }
}
