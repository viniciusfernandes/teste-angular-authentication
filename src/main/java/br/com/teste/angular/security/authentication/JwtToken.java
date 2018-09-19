package br.com.teste.angular.security.authentication;

public class JwtToken {

	private String token; 
	
	public JwtToken() {
	}
	
	public JwtToken(String token) {
		this.token = token;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

}
