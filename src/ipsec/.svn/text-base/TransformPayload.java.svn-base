package ipsec;

import java.nio.ByteBuffer;
import java.util.Vector;

import encrypt.BinaryHexConverter;
import encrypt.ByteArrayBits;

public class TransformPayload {
	public static final int TYPE_ENCRYPT_ALGORITHM = 1;
	public static final int TYPE_HASH_ALGORITHM = 2;
	public static final int TYPE_PARTNER_ALLOW = 3;
	public static final int TYPE_OAKLEY_GROUP = 4;
	public static final int TYPE_GROUP_TYPE = 5;
	public static final int TYPE_GROUP_PRIME_NUMBER = 6;
	public static final int TYPE_GROUP_PRIMITIVE_ELEMENT_1 = 7;
	public static final int TYPE_GROUP_PRIMITIVE_ELEMENT_2 = 8;
	public static final int TYPE_GROUP_CURVE_A = 9;
	public static final int TYPE_GROUP_CURVE_B = 10;
	public static final int TYPE_EXPIRED_TIME_TYPE = 11;
	public static final int TYPE_EXPIRED_TIME = 12;
	public static final int TYPE_PRF = 13;
	public static final int TYPE_KEY_LENGTH = 14;
	public static final int TYPE_GF_SIZE = 15;
	public static final int TYPE_GROUP_ORDER = 16;
	
	private byte[] sec_property_byte;
	
	/** 8bit */
	private short next_payload;				// 8bit
	/** 8bit */
	private byte[] reserved = new byte[1];	// 8bit
	/** 16bit */
	private short payload_length;				// 16bit
	
	/** 8bit */
	private short transform_num;			// 8bit
	/** 8bit */
	private short transform_id;				// 8bit
	/** 16bit */
	private byte[] reserved2 = new byte[2];	// 16bit
	
	private Vector<SaProperty> sa_property;
	
	public int getPayload_length() {
		return payload_length;
	}

	public void setPayload_length(short payload_length) {
		this.payload_length = payload_length;
	}

	public TransformPayload(byte[] payload_byte) {
		ByteBuffer bw = ByteBuffer.wrap(payload_byte);
		
		next_payload = bw.get();
		bw.get(reserved);
		payload_length = bw.getShort();
		
		transform_num = bw.get();
		transform_id = bw.get();
		bw.get(reserved2);
		
		sec_property_byte = new byte[payload_length - 8];
		bw.get(sec_property_byte);
		convertByteToSaProperty();
		
		outputTransformPayload();
	}
	
	public TransformPayload() {
		next_payload = 0;
		
	}
	
	public void initClientIpsecSa1 () {
		payload_length = 16;
		transform_num = 1;
		transform_id = 1;
		sa_property = new Vector<SaProperty>();
		
		SaProperty sp = new SaProperty(transform_id);
		sp.setType(SaProperty.ENCAPSULATION_MODE);
		sp.setFixedValue((short) 2); // Transport
		sa_property.add(sp);
		
		sp = new SaProperty(transform_id);
		sp.setType(SaProperty.AUTHENTICATION_ALGORITHM);
		sp.setFixedValue((short) 2); // SHA
		sa_property.add(sp);
	}
	
	public void initClientIpsecSa2 () {
		payload_length = 16;
		transform_num = 2;
		transform_id = 2;
		sa_property = new Vector<SaProperty>();
		
		SaProperty sp = new SaProperty(transform_id);
		sp.setType(SaProperty.ENCAPSULATION_MODE);
		sp.setFixedValue((short) 2);
		sa_property.add(sp);
		
		sp = new SaProperty(transform_id);
		sp.setType(SaProperty.AUTHENTICATION_ALGORITHM);
		sp.setFixedValue((short) 1); // MD5
		sa_property.add(sp);
	}
	
	public void initSrvIpsecSa1 () {
		payload_length = 16;
		transform_num = 2;
		transform_id = 1;
		sa_property = new Vector<SaProperty>();
		
		SaProperty sp = new SaProperty(transform_id);
		sp.setType(SaProperty.ENCAPSULATION_MODE);
		sp.setFixedValue((short) 2); // Transport
		sa_property.add(sp);
		
		sp = new SaProperty(transform_id);
		sp.setType(SaProperty.AUTHENTICATION_ALGORITHM);
		sp.setFixedValue((short) 2); //SHA
		sa_property.add(sp);
	}
	
	public void initSrvIpsecSa2 () {
		payload_length = 16;
		transform_num = 2;
		transform_id = 2;
		sa_property = new Vector<SaProperty>();
		
		SaProperty sp = new SaProperty(transform_id);
		sp.setType(SaProperty.ENCAPSULATION_MODE);
		sp.setFixedValue((short) 2); // Transport
		sa_property.add(sp);
		
		sp = new SaProperty(transform_id);
		sp.setType(SaProperty.AUTHENTICATION_ALGORITHM);
		sp.setFixedValue((short) 1); // MD5
		sa_property.add(sp);
	}
	
	public void initClientSaPkt () {
		next_payload = 0;
		payload_length = 40;
		transform_num = 1;
		transform_id = 1;
		sa_property = new Vector<SaProperty>();
		
		SaProperty sp = new SaProperty(transform_id);
		sp.af = true;
		sp.type = 1;
		sp.value = BinaryHexConverter.HexStringToBytes("0007");
		sa_property.add(sp);
		
		sp = new SaProperty(transform_id);
		sp.af = true;
		sp.type = 14;
		sp.value = BinaryHexConverter.HexStringToBytes("0100");
		sa_property.add(sp);
		
		sp = new SaProperty(transform_id);
		sp.af = true;
		sp.type = 2;
		sp.value = BinaryHexConverter.HexStringToBytes("0002");
		sa_property.add(sp);
		
		sp = new SaProperty(transform_id);
		sp.af = true;
		sp.type = 4;
		sp.value = BinaryHexConverter.HexStringToBytes("000e");
		sa_property.add(sp);
		
		sp = new SaProperty(transform_id);
		sp.af = true;
		sp.type = 3;
		sp.value = BinaryHexConverter.HexStringToBytes("0001");
		sa_property.add(sp);
		
		sp = new SaProperty(transform_id);
		sp.af = true;
		sp.type = 11;
		sp.value = BinaryHexConverter.HexStringToBytes("0001");
		sa_property.add(sp);
		
		sp = new SaProperty(transform_id);
		sp.af = false;
		sp.type = 12;
		sp.setLength((short) 4);
		sp.value = BinaryHexConverter.HexStringToBytes("00007080");
		sa_property.add(sp);
	}
	
	/**
	 * byte[]からSA属性への変換
	 * SA属性のみが含まれているbyte[]をsec_property_byteに指定した後に実行すること
	 */
	public void convertByteToSaProperty () {
		ByteBuffer bw = ByteBuffer.wrap(sec_property_byte);
		sa_property = new Vector<SaProperty>();
		
		while (bw.hasRemaining()) {
			SaProperty sa = new SaProperty(transform_id);

			byte[] tmp = new byte[2];
			bw.get(tmp);
			ByteArrayBits bab = new ByteArrayBits(tmp);

			int af = bab.subbits(0, 1);
			int type = bab.subbits(1, 16);

			// TODO afのフラグ判定がおかしいから確認して修正
			
			if (af == 1) {
				sa.setAf(true);
				sa.type = type;
				byte[] val = new byte[2];
				bw.get(val);
				sa.setValue(val);
			} else {
				sa.setAf(false);
				sa.type = type;
				sa.setLength(bw.getShort());
				byte[] val = new byte[sa.getLength()];
				bw.get(val);
				sa.setValue(val);
			}

			sa_property.add(sa);
		}
	}
	
	/**
	 * 指定されたSA属性がこのペイロード中に含まれるかどうかを返す
	 * @param values SA属性を表すTypeValue配列
	 * @return true:含まれる false:含まれない
	 */
	public boolean containValues (TypeValue[] values) {
		for (int i = 0; i < values.length; i++) {
			boolean flag = false;
			
			for (int j = 0; j < sa_property.size(); j++) {
				SaProperty sp = sa_property.elementAt(j);
				ByteArrayBits bab = new ByteArrayBits(sp.getValue());
				int val = bab.subbits(0, bab.getBitLength());
				
				if (sp.getType() == values[i].type && val == values[i].value) {
					flag = true;
				}
			}
			
			if (!flag) {
				return false;
			}
		}
		
		return true;
	}
	
	/**
	 * Transformペイロードのbyte[]を取得<br />
	 * 内部に設定されたSA属性も含んだbyte[]を返します
	 * @return Transformペイロードのbyte[]
	 */
	public byte[] getByteArray() {
		byte[] send_byte = new byte[payload_length];
		ByteBuffer bw = ByteBuffer.wrap(send_byte);
		
		bw.put((byte) next_payload);
		bw.put(reserved);
		bw.putShort(payload_length);
		
		bw.put((byte) transform_num);
		bw.put((byte) transform_id);
		bw.put(reserved2);
		
		for (int i = 0; i < sa_property.size(); i++) {
			bw.put(sa_property.elementAt(i).getByteArray());
		}
		
		return send_byte;
	}
	
	public void outputTransformPayload() {
		System.out.println("----- Transform Paylord #" + transform_num + " -----");
		System.out.println("next_payload: "+next_payload);
		System.out.println("payload_length: "+payload_length);
		System.out.println("transform_num: "+transform_num);
		System.out.println("transform_id: "+transform_id);
		for (int i = 0; i < sa_property.size(); i++) {
			System.out.println("----- Sa Property -----");
			SaProperty sa = sa_property.get(i);
			System.out.println("af: "+sa.isAf());
			System.out.println("type: "+sa.getType());
			if (!sa.isAf()) {
				System.out.println("length: "+sa.getLength());
			}
			ByteArrayBits bab = new ByteArrayBits(sa.getValue());
			System.out.println("value: "+bab.subbits(0, bab.getBitLength()));
		}
		System.out.println("----- Transform Paylord End -----");
	}
	
	public static void outputTransformPayload (byte[] transform_byte) {
		ByteBuffer bw = ByteBuffer.wrap(transform_byte);
		
		short next_payload = bw.get();
		bw.get(new byte[1]);
		short payload_length = bw.getShort();
		
		short transform_num = bw.get();
		short transform_id = bw.get();
		bw.get(new byte[2]);
		
		byte[] sec_property_byte = new byte[payload_length - 8];
		bw.get(sec_property_byte);
		
		ByteBuffer prop_bw = ByteBuffer.wrap(sec_property_byte);
		Vector<SaProperty> sa_property = new Vector<SaProperty>();
		
		while (prop_bw.hasRemaining()) {
			SaProperty sa = new SaProperty(transform_id);

			byte[] tmp = new byte[2];
			prop_bw.get(tmp);
			ByteArrayBits bab = new ByteArrayBits(tmp);

			int af = bab.subbits(0, 1);
			int type = bab.subbits(1, 16);

			if (af == 1) {
				sa.setAf(true);
				sa.setType(type);
				byte[] val = new byte[2];
				prop_bw.get(val);
				sa.setValue(val);
			} else {
				sa.setAf(false);
				sa.setType(type);
				sa.setLength(prop_bw.getShort());
				byte[] val = new byte[sa.getLength()];
				prop_bw.get(val);
				sa.setValue(val);
			}

			sa_property.add(sa);
		}
		
		System.out.println("----- Transform Paylord #" + transform_num + " -----");
		System.out.println("next_payload: "+next_payload);
		System.out.println("payload_length: "+payload_length);
		System.out.println("transform_num: "+transform_num);
		System.out.println("transform_id: "+transform_id);
		for (int i = 0; i < sa_property.size(); i++) {
			System.out.println("----- Sa Property -----");
			SaProperty sa = sa_property.get(i);
			System.out.println("af: "+sa.isAf());
			System.out.println("type: "+sa.getType());
			if (!sa.isAf()) {
				System.out.println("length: "+sa.getLength());
			}
			ByteArrayBits bab = new ByteArrayBits(sa.getValue());
			System.out.println("value: "+bab.subbits(0, bab.getBitLength()));
		}
		System.out.println("----- Transform Paylord End -----");
	}

	public short getNext_payload() {
		return next_payload;
	}

	public void setNext_payload(short next_payload) {
		this.next_payload = next_payload;
	}
}

/**
 * SA属性クラス
 * 1個4バイト～可変長
 * @author Nakamiri
 *
 */
class SaProperty {
	public static final int KEY_IKE = 1;
	
	public static final int ENCRYPT_DES_CBC = 1;
	public static final int ENCRYPT_DES3_CBC = 5;
	public static final int ENCRYPT_AES_CBC = 7;
	
	public static final int GROUP_MODP_2048_BIT = 14;
	
	public static final int SA_LIFE_TYPE = 1;
	public static final int SA_LIFE_DURATION = 2;
	public static final int GROUP_DESCRIPTION = 3;
	public static final int ENCAPSULATION_MODE = 4;
	public static final int AUTHENTICATION_ALGORITHM = 5;
	public static final int KEY_LENGTH = 6;
	public static final int KEY_ROUNDS = 7;
	public static final int COMPRESSION_DICTIONARY_SIZE = 8;
	public static final int COMPRESSION_PRIVATE_ALGORITHM = 9;
	
	private int transform_id;
	
	public boolean af;
	public int type;
	public byte[] value;
	
	/** valueのみの長さ */
	private short length;
	
	public SaProperty (int transform_id) {
		this.transform_id = transform_id;
	}
	
	public void convertPropertyVal () {
		if (transform_id == KEY_IKE) {
			
		}
	}
	
	/**
	 * byte[]の取得
	 * lengthは計算してないので後から計算必要
	 * @return
	 */
	public byte[] getByteArray() {
		byte[] send_byte;
		if (af) {
			send_byte = new byte[4];
		} else {
			length = (short) value.length;
			send_byte = new byte[4 + length];
		}
		ByteBuffer bw = ByteBuffer.wrap(send_byte);
		
		int tmp_af = af ? 1 : 0;
		tmp_af <<= 15;
		
		short send_type = (short) (tmp_af + type);
		bw.putShort(send_type);
		
		if (af) {
			bw.put(value);
		} else {
			bw.putShort(length);
			bw.put(value);
		}
		
		return send_byte;
	}

	public boolean isAf() {
		return af;
	}

	public void setAf(boolean af) {
		this.af = af;
	}

	public int getType() {
		return type;
	}

	public void setType(int type) {
		this.type = type;
		switch (type) {
		case SA_LIFE_TYPE:
		case GROUP_DESCRIPTION:
		case ENCAPSULATION_MODE:
		case AUTHENTICATION_ALGORITHM:
		case KEY_LENGTH:
		case KEY_ROUNDS:
		case COMPRESSION_DICTIONARY_SIZE:
			af = true;
			break;
		case SA_LIFE_DURATION:
		case COMPRESSION_PRIVATE_ALGORITHM:
			af = false;
			break;
		}
	}

	public byte[] getValue() {
		return value;
	}

	public void setValue(byte[] value) {
		this.value = value;
	}
	
	public void setFixedValue(short value) {
		ByteBuffer bw = ByteBuffer.allocate(2);
		bw.putShort(value);
		
		this.value = bw.array();
	}

	public int getLength() {
		return length;
	}

	public void setLength(short length) {
		this.length = length;
	}
	
	
}

class TypeValue {
	public int type;
	public int value;
	
	public TypeValue (int type, int value) {
		this.type = type;
		this.value = value;
	}
}