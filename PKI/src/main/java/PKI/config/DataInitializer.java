package PKI.config;

import PKI.domain.model.User;
import PKI.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class DataInitializer {

    @Bean
    CommandLineRunner init(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            if (userRepository.findByEmail("admin").isEmpty()) {
                User user = new User();
                user.setEmail("admin");
                user.setPassword(passwordEncoder.encode("admin123"));
                System.out.println("Encoded password: " + passwordEncoder.encode("admin"));
                userRepository.save(user);
            }
        };
    }
}
