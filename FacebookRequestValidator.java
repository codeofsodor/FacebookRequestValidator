import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class FacebookRequestValidator {

	private final static String HMAC_ALG = "HmacSHA256";
	private final static String FB_HM_ALG = "HMAC-SHA256";
	private final static String JSON_ALG_FIELD = "algorithm";
	
	public FacebookRequestValidator(){
		
	}
	
	public boolean requestIsValid(String signedRequest, String secret) throws ParseException, InvalidKeyException, NoSuchAlgorithmException {
		String[] encodedData2 = signedRequest.split(Pattern.quote("."));		
		String signature = encodedData2[0];		
		String decoded = new String(Base64.getDecoder().decode(encodedData2[1]));
		
		JSONParser parser = new JSONParser();
		Object obj = parser.parse(decoded);
		JSONObject json = (JSONObject)obj;
		
		String algorithm = (String)json.get(JSON_ALG_FIELD);
		if(algorithm == null || !algorithm.toUpperCase().equals(FB_HM_ALG)){
			return false;
		}
				
		byte[] hmacVal = HmacSHA256(encodedData2[1].getBytes(), secret.getBytes());
		String computed = Base64.getUrlEncoder().encodeToString(hmacVal).replace(Pattern.quote("+"), "-").replace(Pattern.quote("/"), "_").replace("=", "");
		if(!signature.equals(computed)){
			return false;
		}
		return true;
	}
	
	private byte[] HmacSHA256(byte[] data, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException  {
	     Mac mac = Mac.getInstance(HMAC_ALG);
	     mac.init(new SecretKeySpec(key, HMAC_ALG));
	     return mac.doFinal(data);
	}
	
}

