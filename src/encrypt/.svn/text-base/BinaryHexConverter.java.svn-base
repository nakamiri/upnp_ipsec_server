package encrypt;

/**
 * Byte型配列⇔16進数表記String型への変換
 * @author CreativeGear
 */
public class BinaryHexConverter {

	/**
	 * Byte型配列から16進数表記文字列へ変換する
	 * @param fromByte 変換対象Byte型配列
	 * @return 16進数表記に変換後の文字列
	 */
	public static String bytesToHexString(byte[] fromByte) {

		StringBuilder hexStrBuilder = new StringBuilder();
		for (int i = 0; i < fromByte.length; i++) {

			// 16進数表記で1桁数値だった場合、2桁目を0で埋める
			if ((fromByte[i] & 0xff) < 0x10) {
				hexStrBuilder.append("0");
			}
			hexStrBuilder.append(Integer.toHexString(0xff & fromByte[i]));
		}

		return hexStrBuilder.toString();
	}

	/**
	 * 16進数表記文字列からByte型配列へ変換する
	 * @param fromHexStr 変換対象の16進数表記文字列
	 * @return 変換後のByte型配列
	 */
	public static byte[] HexStringToBytes(String fromHexStr) {

		//16進数表記では2文字で1バイトを表現するため、
		//Byte型配列に変換する際には、配列の長さは1/2で良い
		byte[] toByte = new byte[fromHexStr.length() / 2];

		//16進数表記文字列を、2文字ずつByte型へ変換していく
		for (int i = 0; i < toByte.length; i++) {
			toByte[i] = (byte) Integer.parseInt(fromHexStr.substring(i * 2, (i + 1) * 2), 16);
		}
		return toByte;
	}
}