package com.example.AwsSignatureAuth;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

public class App 
{
    private final static String ENDPOINT = "https://<endpoint-url>";

    public static String main( String[] args ) throws Exception {
        Aws4Signer aws4Signer = new Aws4Signer();
        String body = "";
        HttpHeaders headers = aws4Signer.buildHeadersWithAuthentication(body);
        HttpEntity<String> httpEntity = new HttpEntity<>(body, headers);

        RestTemplate restTemplate = new RestTemplate();
        try
        {
            String response = restTemplate.postForObject(ENDPOINT, httpEntity, String.class);
            return response;
        }
        catch(HttpClientErrorException ex)
        {
            System.out.println(ex.getStatusText());
            return null;
        }
    }
}
