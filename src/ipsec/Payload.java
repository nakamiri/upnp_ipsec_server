package ipsec;

public abstract class Payload {
	/** 次のペイロード無し */
	public static final int NONE = 0;
	public static final int SA_PAYLOAD = 1;
	public static final int PROPOSAL_PAYLOAD = 2;
	public static final int TRANSFORM_PAYLOAD = 3;
	public static final int KEY_EXCHANGE_PAYLOAD = 4;
	public static final int ID_PAYLOAD = 5;
	public static final int CERTIFICATE_PAYLOAD = 6;
	public static final int REQ_CERTIFICATE_PAYLOAD = 7;
	public static final int HASH_PAYLOAD = 8;
	public static final int SIGN_PAYLOAD = 9;
	public static final int NONCE_PAYLOAD = 10;
	public static final int NOTICE_PAYLOAD = 11;
	public static final int REMOVE_PAYLOAD = 12;
	public static final int VENDOR_ID_PAYLOAD = 13;
	public static final int PROPERTY_PAYLOAD = 14;
	public static final int NAT_DISCOVERY_PAYLOAD = 20;
	
	protected int payload_type;
	
	protected byte[] left_data;
	
	abstract void outputValue();
	
	abstract int getNext_payload();
	
	abstract byte[] getLeft_data();
	
	static public Payload makePayload (int type, byte[] payload) {
		
		switch (type) {
		case SA_PAYLOAD:
			return new SaPayload(payload);
		case PROPOSAL_PAYLOAD:
			new PropPayload(payload);
			break;
		case TRANSFORM_PAYLOAD:
			new TransformPayload(payload);
			break;
		case KEY_EXCHANGE_PAYLOAD:
			return new KeyExchangePayload(payload);
		case ID_PAYLOAD:
			return new IdPayload(payload);
		case CERTIFICATE_PAYLOAD:
			break;
		case REQ_CERTIFICATE_PAYLOAD:
			break;
		case HASH_PAYLOAD:
			return new HashPayload(payload);
		case SIGN_PAYLOAD:
			break;
		case NONCE_PAYLOAD:
			return new NoncePayload(payload);
		case NOTICE_PAYLOAD:
			break;
		case REMOVE_PAYLOAD:
			break;
		case VENDOR_ID_PAYLOAD:
			return new VendorIdPayload(payload);
		case PROPERTY_PAYLOAD:
			break;
		case NAT_DISCOVERY_PAYLOAD:
			return new NatDiscoveryPayload(payload);
		}
		
		return null;
	}
}
