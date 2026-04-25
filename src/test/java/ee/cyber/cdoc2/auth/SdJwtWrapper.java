package ee.cyber.cdoc2.auth;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

class SdJwtWrapper {
    private final String headerJson;
    private final String payloadJson;
    private final String signature;
    private final String disclosures;

    SdJwtWrapper(String sdJwt) {
        String jwtWithoutSignature = sdJwt.substring(
            0, sdJwt.lastIndexOf(".")
        );

        String header = jwtWithoutSignature.substring(0, jwtWithoutSignature.indexOf("."));
        String payload = jwtWithoutSignature.substring(jwtWithoutSignature.indexOf(".") + 1);

        this.headerJson = new String(Base64.getUrlDecoder().decode(header),
            StandardCharsets.UTF_8);
        this.payloadJson = new String(Base64.getUrlDecoder().decode(payload), StandardCharsets.UTF_8);

        this.signature = sdJwt.substring(
            sdJwt.lastIndexOf(".") + 1,
            sdJwt.indexOf("~")
        );
        this.disclosures = sdJwt.substring(
            sdJwt.indexOf("~")
        );
    }

    String replaceValue(String key, String newValue) {
        String headerReplaced = replaceFirstJsonValue(this.headerJson, key, newValue);
        String payloadReplace = replaceFirstJsonValue(this.payloadJson, key, newValue);

        return reconstructSdJwt(headerReplaced, payloadReplace);
    }

    private String reconstructSdJwt(String header, String payload) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
            header.getBytes(StandardCharsets.UTF_8)
        )
            + "."
            + Base64.getUrlEncoder().withoutPadding().encodeToString(
            payload.getBytes(StandardCharsets.UTF_8)
        )
            + "."
            + signature
            + disclosures;
    }

    private static String replaceFirstJsonValue(String json, String key, String newValue) {
        String search = "\"" + key + "\"";
        int keyPos = json.indexOf(search);

        if (keyPos == -1) {
            return json; // key not found
        }

        // Move to the colon after the key
        int colonPos = json.indexOf(":", keyPos + search.length());
        if (colonPos == -1) {
            return json;
        }

        // Move to the start of the value (skip whitespace)
        int valueStart = colonPos + 1;
        while (valueStart < json.length() && Character.isWhitespace(json.charAt(valueStart))) {
            valueStart++;
        }

        // Only handle string values: "value"
        if (valueStart >= json.length() || json.charAt(valueStart) != '"') {
            return json; // not a string value
        }

        int oldValueStart = valueStart + 1;
        int oldValueEnd = json.indexOf("\"", oldValueStart);
        if (oldValueEnd == -1) {
            return json; // malformed JSON
        }

        // Build the new JSON
        return json.substring(0, oldValueStart)
            + newValue
            + json.substring(oldValueEnd);
    }
}
