package encrypt;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * MD5で暗号化するクラス
 *
 * @author CreativeGear
 */
public class MD5 {

	/**
	 * MD5で文字列を暗号化し、暗号化されたバイナリを16進数表記の文字列に変換した値を取得する
	 *
	 * @param str
	 *            暗号化対象の文字列
	 * @return 暗号化した結果を16進数表記に変換した文字列
	 */
	public static String digestMd5(String str) throws NoSuchAlgorithmException {
		if (str == null || str.length() == 0) {
			throw new IllegalArgumentException("文字列がNull、または空です。");
		}

		// MD5で暗号化したByte型配列を取得する
		MessageDigest md5 = MessageDigest.getInstance("MD5");
		md5.update(str.getBytes());
		byte[] enclyptedHash = md5.digest();

		// 暗号化されたByte型配列を、16進数表記文字列に変換する
		return BinaryHexConverter.bytesToHexString(enclyptedHash);
	}
}