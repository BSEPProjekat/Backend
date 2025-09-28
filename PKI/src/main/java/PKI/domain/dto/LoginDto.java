package PKI.domain.dto;

public class LoginDto {
    private String Email;
    private String Password;

    public LoginDto(){}

    public LoginDto(String username, String password) {
        this.Email = username;
        this.Password = password;
    }

    public String getEmail() { return Email; }
    public void setUsername(String username) { this.Email = username; }

    public String getPassword() { return Password; }
    public void setPassword(String password) { this.Password = password; }
}
