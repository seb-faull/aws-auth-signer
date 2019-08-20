package com.example.AwsSignatureAuth;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import com.example.AwsSignatureAuth.Aws4SignatureGenerator;

/**
 * This class wraps AWS4 signing logic. The signing details were implemented
 * based on <a href=
 * "https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html">
 * Examples of the Complete Version 4 Signing Process (Python)</a>
 *
 */
public class Aws4Signer {
    private final static String REQUEST_CONTENT_TYPE = "application/json";

    private final static String AUTH_ALGORITHM = "AWS4-HMAC-SHA256";

    private final static String REQUEST_METHOD = "POST";

    private final static String AWS_REGION = "eu-west-1";

    private final static String CANONICAL_URI = "<canonical_uri>";

    private final static String HOST = "<host>";

    private final static String AWS_SERVICE_NAME = "execute-api";

    private final static String AWS_ACCESS_KEY = "<access_key>";

    private final static String AWS_SECRET_KEY = "<secret_key>";

    class AuthenticationData
    {
        String timestamp, date, payloadHash, authorizationHeader;

        public AuthenticationData(String timestamp, String date, String payloadHash, String authorizationHeader)
        {
            this.timestamp = timestamp;
            this.date = date;
            this.payloadHash = payloadHash;
            this.authorizationHeader = authorizationHeader;
        }

        public String getTimestamp()
        {
            return timestamp;
        }

        public void setTimestamp(String timestamp)
        {
            this.timestamp = timestamp;
        }

        public String getDate()
        {
            return date;
        }

        public void setDate(String date)
        {
            this.date = date;
        }

        public String getPayloadHash()
        {
            return payloadHash;
        }

        public void setPayloadHash(String payloadHash)
        {
            this.payloadHash = payloadHash;
        }

        public String getAuthorizationHeader()
        {
            return authorizationHeader;
        }

        public void setAuthorizationHeader(String authorizationHeader)
        {
            this.authorizationHeader = authorizationHeader;
        }
    }

    /**
     * Gets the timestamp in YYYYMMDD'T'HHMMSS'Z' format, which is the required
     * format for AWS4 signing request headers and credential string
     *
     * @param dateTime an OffsetDateTime object representing the UTC time of current
     *                 signing request
     * @return the formatted timestamp string
     */
    public String getTimeStamp(OffsetDateTime dateTime)
    {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'");
        return dateTime.format(formatter);
    }

    /**
     * Gets the date string in yyyyMMdd format, which is required to build the
     * credential scope string
     *
     * @return the formatted date string
     */
    public String getDate(OffsetDateTime dateTime)
    {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMdd");
        return dateTime.format(formatter);
    }

    /**
     * Get current timestamp with local timezone in yyyyMMddHHmmss format
     *
     * @return the formatted timestamp string
     */
    public String getCurrentLocalTimestamp()
    {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmss");
        LocalDateTime now = LocalDateTime.now();
        return now.format(formatter);
    }

    public byte[] generateAws4SigningKey(String timestamp) throws Exception
    {
        return Aws4SignatureGenerator.generateSignatureKey(AWS_ACCESS_KEY, timestamp, AWS_REGION, AWS_SERVICE_NAME);
    }

    public HttpHeaders buildHeadersWithAuthentication(String requestBody) throws Exception
    {
        HttpHeaders headers;
        AuthenticationData authData = buildAuthorizationData(requestBody);
        headers = createAwsRequestHeaders(authData);

        return headers;
    }

    /**
     * Builds an {@link AuthenticationData} object containing the timestamp, date,
     * payload hash and the AWS4 signature
     *
     * The signing logic was translated from the Python implementation, see this
     * link for more details: <a href=
     * "https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html">Examples
     * of the Complete Version 4 Signing Process (Python)</a>
     *
     * @param requestBody
     * @return
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws IllegalStateException
     */
    public AuthenticationData buildAuthorizationData(String requestBody) throws Exception
    {
        // Starting building the lengthy signing data
        String payloadHash = Hmac.getSha256Hash(requestBody);

        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        String timestamp = getTimeStamp(now);
        String date = getDate(now);

        // Step 1 is to define the verb (GET, POST, etc.) -- already done by defining
        // constant REQUEST_METHOD

        // Step 2: Create canonical URI--the part of the URI from domain to query
        // string (use '/' if no path)
        String canonical_uri = CANONICAL_URI;

        // Step 3: Create the canonical query string. In this example, request
        // parameters are passed in the body of the request and the query string
        // is blank.
        String canonical_querystring = "";

        // Step 4: Create the canonical headers. Header names must be trimmed
        // and lowercase, and sorted in code point order from low to high.
        // Note that there is a trailing \n.
        String canonical_headers =
                "content-type:" + REQUEST_CONTENT_TYPE + "\n" + "host:" + HOST + "\n" + "x-amz-content-sha256:" + payloadHash
                        + "\n" + "x-amz-date:" + timestamp + "\n";
        String signed_headers = "content-type;host;x-amz-content-sha256;x-amz-date";

        String canonical_request =
                REQUEST_METHOD + "\n" + canonical_uri + "\n" + canonical_querystring + "\n" + canonical_headers + "\n"
                        + signed_headers + "\n" + payloadHash;

        String credential_scope = date + "/" + AWS_REGION + "/" + AWS_SERVICE_NAME + "/" + "aws4_request";
        String canonical_request_hash = Hmac.getSha256Hash(canonical_request);

        String string_to_sign = AUTH_ALGORITHM + "\n" + timestamp + "\n" + credential_scope + "\n" + canonical_request_hash;

        byte[] sigKey = generateAws4SigningKey(date);

        String signature = Hmac.calculateHMAC(string_to_sign, sigKey, Hmac.HMAC_SHA256);
        String authorization_header =
                AUTH_ALGORITHM + " " + "Credential=" + AWS_ACCESS_KEY + "/" + credential_scope + ", " + "SignedHeaders="
                        + signed_headers + ", " + "Signature=" + signature;

        return new AuthenticationData(timestamp, date, payloadHash, authorization_header);
    }

    /**
     * Creates the HTTP headers for the prediction request
     *
     * @param authData the {@link AuthenticationData} object containing required
     *                 authentication data for build the headers
     * @return an {@link org.springframework.http.HttpHeaders} object that contains
     * all the required headers
     */
    private HttpHeaders createAwsRequestHeaders(AuthenticationData authData)
    {
        java.util.List<MediaType> accepts = Collections.singletonList(MediaType.APPLICATION_JSON);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.add("Host", HOST);
        headers.add("X-Amz-Date", authData.getTimestamp());
        headers.add("X-Amz-Content-Sha256", authData.getPayloadHash());
        headers.add("Authorization", authData.getAuthorizationHeader());
        headers.setAccept(accepts);
        return headers;
    }
}
