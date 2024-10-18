package ee.cyber.cdoc2.auth;

import java.util.Map;
import java.util.Objects;

public class ShareAccessData {


    private final String serverBaseUrl;
    private final String shareId;
    private final String nonce;
    /**
     * /key-shares OAS endpoint data
     * @param serverBaseUrl key-shares api endpoint as "https://cdoc-ccs.ria.ee:443/key-shares/"
     * @param shareId shareId
     * @param nonce nonce returned by server /key-shares/${shareId}/nonce
     */

    public ShareAccessData(String serverBaseUrl, String shareId, String nonce) {
        Objects.requireNonNull(serverBaseUrl);
        Objects.requireNonNull(shareId);
        Objects.requireNonNull(nonce);

        this.serverBaseUrl = serverBaseUrl;
        this.shareId = shareId;
        this.nonce = nonce;
    }

    public String getShareId() {
        return this.shareId;
    }

    public String getNonce() {
        return this.nonce;
    }

    public String getServerBaseUrl() {
        return this.serverBaseUrl;
    }

    /**
     * Return map representation that can be easily converted to json
     * <code>
     * {
     *     "serverBaseURL": "https://cdoc-ccs.ria.ee:443/key-shares/",
     *     "shareId": "9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3",
     *     "serverNonce": "649a44d6cd9827cae3f3df04fd5eda98246d2dde"
     * }
     * </code>
     * @return Map representation of ShareAccessData
     */
    public Map<String, Object> toMap() {
        return Map.of(
            Constants.SERVER_BASE_URL, this.serverBaseUrl,
            Constants.NONCE, this.nonce,
            Constants.SHARE_ID, this.shareId
        );
    }

    public static ShareAccessData fromMap(Map<String, Object> m) {
        return new ShareAccessData(
            (String)m.get(Constants.SERVER_BASE_URL),
            (String)m.get(Constants.SHARE_ID),
            (String)m.get(Constants.NONCE));
    }

}
