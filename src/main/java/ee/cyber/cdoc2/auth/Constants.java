package ee.cyber.cdoc2.auth;

public final class Constants {
    public static final String KEY_SHARES_EP = "/key-shares";
    public static final String NONCE = "nonce";

    public static final String TYPE_AUTH_TOKEN = "vnd.cdoc2.auth-token.v1+sd-jwt";
    public static final String TYPE_SESSION_TOKEN = "vnd.cdoc2.session-token.v2+sd-jwt";
    public static final String RP_V3_SIGNATURE_ALGORITHM_NAME = "RSASSA-PSS+ACSP_V2";

    private Constants() {}
}
